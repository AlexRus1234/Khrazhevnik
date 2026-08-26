// Хражевник — кеш-прокси и зеркало linux-репозиториев
// Copyright (C) 2026 AlexRus1234
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
)

// assetsFS — встроенный SPA-бандл (web/, собирается make web-build).
// Единственная package-level переменная пакета помимо экспорта: директива
// //go:embed работает только с package-level сущностями (AGENTS.md).
//
//go:embed assets
var assetsFS embed.FS

// indexHTML — побайтовое содержимое index.html для SPA-fallback: отдаётся
// напрямую (мимо http.ServeFileFS), чтобы выставить Cache-Control: no-cache.
// Отдельная директива (а не чтение из assetsFS в рантайме) даёт compile-time
// гарантию, что точка входа SPA существует — сборка падает, если ассетов нет.
//
//go:embed assets/index.html
var indexHTML []byte

// handleSPA раздаёт встроенный Vue-бандл на /ui/* админского порта (:30202).
// Несуществующие пути → index.html (клиентский роутинг vue-router), КРОМЕ
// /api/v1/*, /metrics, /healthz — те зарегистрированы на роутере выше и в
// /ui/* не попадают. index.html — Cache-Control: no-cache (хеш ассетов
// меняется при релизе, HTML браузер всегда перечитывает); хешированные
// ассеты vite (assets/<name>-<hash>.<ext>) — public, immutable, max-age год.
func handleSPA() http.HandlerFunc {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		// assets встроены compile-time — Sub не падает на практике;
		// защита от непредвиденного: 503, не паника (AGENTS.md).
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "web assets unavailable", http.StatusInternalServerError)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// wildcard из /ui/* (пустой для /ui и /ui/); path.Clean нормализует
		// «..» — embed.FS и так их отвергает, двойная защита от обхода.
		name := strings.TrimPrefix(path.Clean("/"+chi.URLParam(r, "*")), "/")
		if name == "" || name == "index.html" {
			serveIndexHTML(w)
			return
		}
		// deep-link на клиентский роут (/ui/remotes): не файл → index.html.
		if _, statErr := fs.Stat(sub, name); statErr != nil {
			serveIndexHTML(w)
			return
		}
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeFileFS(w, r, sub, name)
	}
}

// serveIndexHTML — точка входа SPA: no-cache, чтобы при релизе браузер
// всегда забирал свежий index.html с актуальными хешами ассетов.
func serveIndexHTML(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(indexHTML)
}
