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
// (raw хвост после /repo/{name}/). Лоуэркейс: ключи проходят
// domain.ValidateKey, который не пускает верхний регистр.
func handleRepoFile(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			http.NotFound(w, r)
			return
		}
		repo, err := d.Repos.RepoByName(r.Context(), name)
		if err != nil {
			var nf *domain.NotFoundError
			if errors.As(err, &nf) {
				http.NotFound(w, r)
				return
			}
			writeProxyError(w, err)
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
		if obj.Meta.ETag != "" {
			w.Header().Set("ETag", obj.Meta.ETag)
		}
		if !obj.Meta.ModTime.IsZero() {
			w.Header().Set("Last-Modified", obj.Meta.ModTime.UTC().Format(http.TimeFormat))
		}
		// Immutable-объекты (пакеты) — публичный кеш-клиент.
		// apt/dnf советуют Cache-Control: immutable для content-addressed.
		if isImmutableRepoObject(repo.Ecosystem, rest) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		if obj.Meta.Size >= 0 {
			w.Header().Set("Content-Length", formatInt(obj.Meta.Size))
		}
		_, _ = io.CopyBuffer(w, obj.Body, make([]byte, 32*1024))
	}
}

// isImmutableRepoObject решает, выставить ли Cache-Control: immutable.
// Для apt: pool/* (пакеты) — content-addressed по имени+версии, можно
// кешировать навсегда; dists/* (индексы) — перегенерируются, mutable.
// Для других экосистем: консервативно false (M3 их генераторов нет).
func isImmutableRepoObject(ecosystem, path string) bool {
	if ecosystem == "apt" {
		return strings.HasPrefix(path, "pool/")
	}
	return false
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
			var nf *domain.NotFoundError
			if errors.As(err, &nf) {
				http.NotFound(w, r)
				return
			}
			writeProxyError(w, err)
			return
		}
		if d.Signer == nil {
			http.Error(w, "signing unavailable", http.StatusServiceUnavailable)
			return
		}
		pub, err := d.Signer.PublicKey()
		if err != nil {
			writeProxyError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
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
			var nf *domain.NotFoundError
			if errors.As(err, &nf) {
				http.NotFound(w, r)
				return
			}
			writeProxyError(w, err)
			return
		}
		if d.NarSigner == nil {
			http.Error(w, "nix signing unavailable", http.StatusServiceUnavailable)
			return
		}
		// Формат trusted-public-keys: «name:pubkey-b64» (pubkey — base64
		// raw ed25519). nix.conf: trusted-public-keys = khrazhevnik:<pubkey>.
		body := d.NarSigner.Name() + ":" + d.NarSigner.PubKeyB64() + "\n"
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write([]byte(body))
	}
}
