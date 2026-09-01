package web

import (
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

func handleProxy(d Deps) http.HandlerFunc {
	// Статусы X-Cache дублируют константы engine/cache: web не тянет
	// внутренности движка ради имён.
	const statusStale = "STALE"
	// byPrefix — индекс экосистем по URL-префиксу (первый сегмент пути).
	// Deps.Ecosystems хранятся по имени (apt, rpm-md); URL-префикс может
	// отличаться (rpm-md → «rpm»). Индекс строится один раз при сборке
	// роутера, lookup за O(1) на запрос.
	byPrefix := make(map[string]port.Ecosystem, len(d.Ecosystems))
	for _, eco := range d.Ecosystems {
		byPrefix[eco.URLPrefix()] = eco
	}
	return func(w http.ResponseWriter, r *http.Request) {
		prefix := chi.URLParam(r, "eco")
		eco, ok := byPrefix[prefix]
		if !ok {
			http.NotFound(w, r)
			return
		}
		path := "/" + prefix + "/" + chi.URLParam(r, "*")
		obj, status, err := d.Cache.FetchStatus(r.Context(), eco, path)
		if err != nil {
			var stale *domain.StaleError
			if errors.As(err, &stale) {
				w.Header().Set("X-Cache", statusStale)
				w.Header().Set("Warning", `111 khrazhevnik "revalidation failed"`)
			} else {
				writeProxyError(w, err)
				return
			}
		} else {
			w.Header().Set("X-Cache", status)
		}
		defer obj.Body.Close()
		if obj.Meta.ETag != "" {
			w.Header().Set("ETag", obj.Meta.ETag)
		}
		if obj.Meta.ContentType != "" {
			w.Header().Set("Content-Type", obj.Meta.ContentType)
		}
		if !obj.Meta.ModTime.IsZero() {
			w.Header().Set("Last-Modified", obj.Meta.ModTime.UTC().Format(http.TimeFormat))
		}
		if obj.Meta.Size >= 0 {
			w.Header().Set("Content-Length", formatInt(obj.Meta.Size))
		}
		// stallWriter: медленный читатель отвалится по write-deadline,
		// а не будет держать FD и tmp-объект вечно (аудит 2026-08-27).
		n, _ := io.CopyBuffer(newStallWriter(w), obj.Body, make([]byte, 32*1024))
		d.Cache.AddBytesToClients(n)
		// object_bytes — точка прокси-отдачи (byte-exact путь, аудит
		// 2026-08-30): размер скопированного тела + имя экосистемы.
		if d.Metrics != nil {
			d.Metrics.ObserveObjectBytes(eco.Name(), float64(n))
		}
	}
}

func formatInt(n int64) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	if i == len(b) {
		return "0"
	}
	return string(b[i:])
}

func writeProxyError(w http.ResponseWriter, err error) {
	var nf *domain.NotFoundError
	var tooLarge *domain.TooLargeError
	var upstream *domain.UpstreamError
	var badKey *domain.InvalidKeyError
	var unavail *domain.UnavailableError
	switch {
	case errors.As(err, &nf):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.As(err, &badKey):
		// мусорный путь клиента — 400, не 5xx-флод в логах
		http.Error(w, "invalid storage path", http.StatusBadRequest)
	case errors.As(err, &tooLarge):
		http.Error(w, "upstream object too large", http.StatusBadGateway)
	case errors.As(err, &unavail):
		// сбой нашего storage/каталога — не вина upstream: 503, как в
		// auth-слое для той же ошибки (аудит 2026-08-30, сессия 45);
		// 502 «proxy error» вводил в заблуждение про upstream.
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
	case errors.As(err, &upstream):
		http.Error(w, "upstream error", http.StatusBadGateway)
	default:
		http.Error(w, "proxy error", http.StatusBadGateway)
	}
}
