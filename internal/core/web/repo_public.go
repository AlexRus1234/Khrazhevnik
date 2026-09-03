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

// Публичный роутер личных репо (GET /repo/<name>/<путь> на :29202):
// lookup репо по имени (не id), чтение объекта из Storage, отдача с
// ETag/ModTime/ContentLength из Meta. Иммутабельные пакеты кешируются
// клиентами (apt с trusted=yes не требует подписи на Packages/Release).

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

// handleRepoFile — раздача объекта личного репо по имени. Ключ в
// Storage: repo/<repo-id>/<ecosystem>/<путь>. Путь — chi URLParam "*"
// (raw хвост после /repo/{name}/). Лоуэркейс — не рудимент ValidateKey
// (сессия 19 разрешила верхний регистр в ключах), а v1-конвенция
// личных репо: publish и генераторы пишут ключи в lowercase, а
// apt-клиенты запрашивают индексы с заглавной (Packages/Release) —
// нормализация запроса сводит их. Прокси-кеш upstream (handleProxy)
// регистр НЕ нормализует: там пути case-чувствительны.
func handleRepoFile(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			http.NotFound(w, r)
			return
		}
		repo, err := d.Repos.RepoByName(r.Context(), name)
		if err != nil {
			if isNotFound(err) {
				http.NotFound(w, r)
				return
			}
			writeProxyError(w, publicCatalogError(err))
			return
		}
		rest := chi.URLParam(r, "*")
		if rest == "" {
			http.NotFound(w, r)
			return
		}
		rest = strings.ToLower(rest)
		key := port.RepoPrefix(repo) + "/" + rest
		obj, err := d.Storage.Get(r.Context(), key)
		if err != nil {
			var nf *domain.NotFoundError
			if errors.As(err, &nf) {
				http.NotFound(w, r)
				return
			}
			writeProxyError(w, err)
			return
		}
		defer obj.Body.Close()
		// Аудит 2026-08-30 (stored-XSS): Content-Type строго по
		// расширению, не по содержимому — upload валидирует только
		// путь, а тело, начинающееся с «<html», без этого отдаётся
		// net/http-сниффингом как text/html на домене зеркала.
		// Метаданные Storage для repo-объектов не гарантированы
		// (fs не знает content-type), поэтому единственный источник —
		// расширение; неизвестное — octet-stream (fail closed к
		// «скачиванию», не к «рендеру»). Тело при этом byte-exact.
		w.Header().Set("Content-Type", repoContentType(rest))
		if obj.Meta.ETag != "" {
			w.Header().Set("ETag", obj.Meta.ETag)
		}
		if !obj.Meta.ModTime.IsZero() {
			w.Header().Set("Last-Modified", obj.Meta.ModTime.UTC().Format(http.TimeFormat))
		}
		// Immutable-объекты (пакеты) — публичный кеш-клиент.
		// apt/dnf советуют Cache-Control: immutable для content-addressed.
		// Исключение — nix narinfo: единственный объект, который инстанс
		// сам переписывает (reindex переподписывает Sig под тем же
		// ключом), поэтому предпосылка «никогда не меняется» ложна:
		// клиент, запинивший pre-resign байты на год, после resign не
		// проходит проверку подписи. no-cache — реиспейт каждый раз
		// (narinfo мал, дёшево); nar/* при этом остаётся immutable.
		if isImmutableRepoObject(repo.Ecosystem, rest) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else if repo.Ecosystem == "nix" && strings.HasSuffix(rest, ".narinfo") {
			w.Header().Set("Cache-Control", "no-cache")
		}
		if obj.Meta.Size >= 0 {
			w.Header().Set("Content-Length", formatInt(obj.Meta.Size))
		}
		// stallWriter: write-deadline на соединение (аудит 2026-08-27) —
		// медленный читатель отваливается, а не держит FD и ридер Storage.
		_, _ = io.CopyBuffer(newStallWriter(w), obj.Body, make([]byte, 32*1024))
	}
}

// isImmutableRepoObject решает, выставить ли Cache-Control: immutable.
// Пакеты всех экосистем content-addressed (apt pool/* по имя+версия;
// rpm-md .rpm/.drpm/.src.rpm; pacman .pkg.tar.*; apk .apk; nix nar/*) —
// генераторы всех пяти экосистем с сессии 16, клиентам незачем
// реиспейсить их на каждый проход (аудит 2026-08-30). Индексы
// (dists/*, repodata/, *.db, APKINDEX.tar.gz) — перегенерируются,
// mutable. Список зеркалит ValidateObjectPath адаптеров
// (mod/ecosystem/*/gen.go), кроме nix narinfo: валидатор его принимает,
// но reindex переписывает narinfo под тем же ключом (resign-on-reindex
// меняет байты один раз) — он не immutable, см. ветку no-cache в
// handleRepoFile.
func isImmutableRepoObject(ecosystem, path string) bool {
	switch ecosystem {
	case "apt":
		return strings.HasPrefix(path, "pool/")
	case "rpm-md":
		return strings.HasSuffix(path, ".rpm") || strings.HasSuffix(path, ".drpm")
	case "pacman":
		return strings.Contains(path, ".pkg.tar.")
	case "apk":
		return strings.HasSuffix(path, ".apk")
	case "nix":
		return strings.HasPrefix(path, "nar/")
	default:
		return false
	}
}

// repoContentType — Content-Type repo-объекта по расширению пути
// (аудит 2026-08-30): публикация валидирует расширение, но не тело —
// сниффинг net/http отдавал бы HTML-подобные объекты как text/html
// (stored-XSS на :29202). Модель «не сниффим»: типы, которые клиент
// хочет интерпретировать (json), перечислены явно; всё остальное,
// включая неизвестные расширения, — octet-stream (fail closed).
func repoContentType(path string) string {
	if strings.HasSuffix(path, ".json") {
		return "application/json"
	}
	return "application/octet-stream"
}

// handleRepoKey отдаёт публичный ключ инстанса (armored OpenPGP) для
// apt-клиентов: GET /repo/<name>/key.asc используется в sources.list
// как signed-by=... Ключ один на все репо (v1 KISS, docs/ARCHITECTURE
// §7), но URL привязан к имени репо: lookup RepoByName → 404 для
// несуществующих имён, чтобы не плодить бесконтрольные endpoint'ы.
// Content-Type text/plain (не application/pgp-keys): apt читает и так,
// а браузеру человек прочтёт armored блок.
func handleRepoKey(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			http.NotFound(w, r)
			return
		}
		if _, err := d.Repos.RepoByName(r.Context(), name); err != nil {
			if isNotFound(err) {
				http.NotFound(w, r)
				return
			}
			writeProxyError(w, publicCatalogError(err))
			return
		}
		pub, err := d.Signer.PublicKey()
		if err != nil {
			writeProxyError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		// CORS: ключ публичный, а админка живёт на другом порту (:30202)
		// — SPA фетчит текст ключа для экрана «Ключи» (сессия 18.2).
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(pub)
	}
}

// handleRepoNixKey отдаёт публичный narinfo-ключ инстанса (ed25519,
// формат «name:pubkey-b64», сессия 16) для nix-клиентов: GET /repo/
// <name>/nix-key.asc добавляется в nix.conf trusted-public-keys.
// Ключ один на все репо (v1 KISS), но URL привязан к имени репо:
// lookup RepoByName → 404 для несуществующих имён. Content-Type
// text/plain: браузеру человек прочтёт, nix-клиент читает «name:pubkey».
func handleRepoNixKey(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			http.NotFound(w, r)
			return
		}
		if _, err := d.Repos.RepoByName(r.Context(), name); err != nil {
			if isNotFound(err) {
				http.NotFound(w, r)
				return
			}
			writeProxyError(w, publicCatalogError(err))
			return
		}
		// Формат trusted-public-keys: «name:pubkey-b64» (pubkey — base64
		// raw ed25519). nix.conf: trusted-public-keys = khrazhevnik:<pubkey>.
		body := d.NarSigner.Name() + ":" + d.NarSigner.PubKeyB64() + "\n"
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		// CORS — как в handleRepoKey: публичный ключ с другого порта.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write([]byte(body))
	}
}

// isNotFound — проверка NotFound для публичных lookup'ов.
func isNotFound(err error) bool {
	var nf *domain.NotFoundError
	return errors.As(err, &nf)
}

// publicCatalogError заворачивает сбой каталога БД (всё, что не NotFound)
// в UnavailableError → 503 «мы сломаны»: сырая ошибка драйвера падала в
// default-ветку writeProxyError и отдавалась как 502 «виноват upstream»
// (сессия 50). Обёртка точечно для публичных вызовов: админ-API
// классифицирует ошибки каталога через validate.go.
func publicCatalogError(err error) error {
	return &domain.UnavailableError{What: "каталог", Reason: "чтение репозитория", Err: err}
}
