package web

import (
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"khrazhevnik/internal/core/domain"
)

func handleProxy(d Deps) http.HandlerFunc {
	// Статусы X-Cache дублируют константы engine/cache: web не тянет
	// внутренности движка ради имён.
	const statusStale = "STALE"
	return func(w http.ResponseWriter, r *http.Request) {
		ecoName := chi.URLParam(r, "eco")
		eco, ok := d.Ecosystems[ecoName]
		if !ok {
			http.NotFound(w, r)
			return
		}
		path := "/" + ecoName + "/" + chi.URLParam(r, "*")
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
		n, _ := io.CopyBuffer(w, obj.Body, make([]byte, 32*1024))
		d.Cache.AddBytesToClients(n)
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
	switch {
	case errors.As(err, &nf):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.As(err, &tooLarge):
		http.Error(w, "upstream object too large", http.StatusBadGateway)
	case errors.As(err, &upstream):
		http.Error(w, "upstream error", http.StatusBadGateway)
	default:
		http.Error(w, "proxy error", http.StatusBadGateway)
	}
}
