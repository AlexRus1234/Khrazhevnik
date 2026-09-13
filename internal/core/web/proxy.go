package web

import (
	"errors"
	"io"
	"net/http"
	"strings"

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
		tail, err := decodedWildcard(r)
		if err != nil {
			// Битые escape (RawPath руками клиента) — тот же класс
			// мусорного пути, что и InvalidKeyError из storage: 400.
			writeProxyError(w, &domain.InvalidKeyError{
				Key:     chi.URLParam(r, "*"),
				Reasons: []error{err},
			})
			return
		}
		path := "/" + prefix + "/" + tail
		if r.Header.Get("Range") == "" {
			// Без Range — сегодняшний путь: FetchStatus открывает тело
			// сразу, Range-семантика хелпера не нужна.
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
			setProxyHeaders(w, path, obj.Meta)
			// stallWriter: медленный читатель отвалится по write-deadline,
			// а не будет держать FD и tmp-объект вечно (аудит 2026-08-27).
			n, err := io.CopyBuffer(newStallWriter(w), obj.Body, make([]byte, 32*1024))
			if err != nil {
				// Обрыв (клиент ушёл или write-deadline stallWriter) — не
				// ошибка отдачи: n байт реально ушли, счётчики честны; но
				// сам факт diagnosable — иначе «почему PM рвёт соединение»
				// неотличим от полной выдачи.
				d.logger().Debug("прокси: клиент оборвал выдачу", "eco", eco.Name(), "path", path, "bytes", n, "err", err)
			}
			d.Cache.AddBytesToClients(eco.Name(), n)
			// object_bytes — точка прокси-отдачи (byte-exact путь, аудит
			// 2026-08-30): размер скопированного тела + имя экосистемы.
			if d.Metrics != nil {
				d.Metrics.ObserveObjectBytes(eco.Name(), float64(n))
			}
			return
		}
		// Range: resolve без открытия тела — телу нужен только Size, а
		// откроется оно в serveRanged (возможно, не раз — multipart).
		meta, status, err := d.Cache.FetchMeta(r.Context(), eco, path)
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
		setProxyHeaders(w, path, meta)
		serveRanged(w, r, meta,
			func() (io.ReadCloser, error) { return d.Cache.OpenBody(r.Context(), meta.Key) },
			func(start, length int64) (io.ReadCloser, error) {
				return d.Cache.OpenRange(r.Context(), meta.Key, start, length)
			},
			func(n int64) {
				d.Cache.AddBytesToClients(eco.Name(), n)
				if d.Metrics != nil {
					d.Metrics.ObserveObjectBytes(eco.Name(), float64(n))
				}
			},
			func() {
				if d.Metrics != nil {
					d.Metrics.ObserveRangeResponse(eco.Name())
				}
			},
		)
	}
}

// setProxyHeaders — общие заголовки прокси-ответа из метаданных
// (ETag/Content-Type/Last-Modified/Content-Length). Range-путь обязан
// дать те же заголовки, что полная выдача: контракт MISS↔HIT
// идентичности заголовков (сессия 69) распространяется и на 206.
//
// Content-Type — allowlist, не passthrough (ревью 2026-09-04, сессия 78):
// злой remote может объявить text/html на любом пути, и браузер отрендерит
// его в origin зеркала (фишинг/дефейс от имени доверенного домена);
// nosniff запрещает лишь переинтерпретацию объявленного типа, сам честно
// объявленный text/html он не чинит. Инвариант byte-exact — про байты
// ТЕЛА, не заголовка: заголовок ответа инстанс и так ставит сам
// (Content-Type, nosniff), а пакетным менеджерам тип безразличен —
// целостность они проверяют чексуммами и подписями в байтах.
func setProxyHeaders(w http.ResponseWriter, path string, meta port.Meta) {
	if meta.ETag != "" {
		w.Header().Set("ETag", meta.ETag)
	}
	w.Header().Set("Content-Type", proxyContentType(path, meta.ContentType))
	if !meta.ModTime.IsZero() {
		w.Header().Set("Last-Modified", meta.ModTime.UTC().Format(http.TimeFormat))
	}
	if meta.Size >= 0 {
		w.Header().Set("Content-Length", formatInt(meta.Size))
	}
}

// proxyContentType — Content-Type ОТВЕТА прокси по allowlist (сессия
// 78). Пакетные расширения получают честный тип независимо от upstream
// (MISS и HIT обязаны дать одинаковый заголовок, а upstream может
// солжёт по-разному); остальное — объявление upstream, ЕСЛИ оно не
// рендерится браузером как активный контент; пустое или опасное —
// application/octet-stream, fail closed к «скачиванию», не к «рендеру».
// Отдельно от repoContentType потому, что у прокси есть честный
// upstream-тип (контракт MISS↔HIT идентичности заголовков, сессия 69),
// а у repo-объектов его нет в принципе.
func proxyContentType(path, upstream string) string {
	// ToLower перед таблицей: A.DEB — реальное имя пакета, а суффиксы
	// пакетов зарегистрированы в нижнем регистре (верификация Р6, LOW).
	path = strings.ToLower(path)
	switch {
	case strings.HasSuffix(path, ".deb"), strings.HasSuffix(path, ".udeb"):
		return "application/vnd.debian.binary-package"
	case strings.HasSuffix(path, ".rpm"): // .rpm, .src.rpm, .drpm
		return "application/x-rpm"
	}
	if upstream != "" && !isRenderableType(upstream) {
		return upstream
	}
	return "application/octet-stream"
}

// isRenderableType — типы, которые браузер исполняет как активный
// контент на origin зеркала. Список сознательно короткий: nosniff
// запрещает переинтерпретацию любого объявленного типа, так что опасен
// только тот, что рендерится сам по себе — script в нём выполняется
// без всякого сниффинга. XML-семейство рядом с HTML не случайно:
// честно объявленный application/xml с PI <?xml-stylesheet href=…xsl?>
// получает браузерный XSLT-рендер (класс XSLT-XSS, верификация Р6) —
// nosniff здесь не помеха, тип-то легальный.
func isRenderableType(contentType string) bool {
	media := contentType
	if i := strings.IndexByte(media, ';'); i >= 0 {
		media = media[:i]
	}
	switch strings.ToLower(strings.TrimSpace(media)) {
	case "text/html", "application/xhtml+xml", "image/svg+xml",
		"application/xml", "text/xml", "text/xsl":
		return true
	}
	return false
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
