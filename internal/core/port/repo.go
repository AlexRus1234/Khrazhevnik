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

// Порт адаптера личного репозитория: экосистемная специфика для upload
// и генерации индексов. Реализации — mod/ecosystem/* (apt — сессия 14;
// rpm-md/pacman/apk/nix — сессия 16). Движок publish (core/engine/
// publish) не знает форматов пакетов, только делегирует адаптеру.

package port

import (
	"context"

	"khrazhevnik/internal/core/domain"
)

// RepoProgress — репортёр прогресса фоновой задачи генерации индексов
// (TaskRegistry под капотом, как у mirror). Идентичен по сигнатуре
// mirror.Progress и web.Progress — отдельный тип, чтобы publish-движок
// не импортировал web/mirror; склейка идёт в wire (cmd/khrazhevnik).
type RepoProgress interface {
	Update(phase, current string, processed, total int64)
	Log(line string)
}

// RepoAdapter — экосистемная специфика личного репозитория. Имя
// совпадает с domain.Repo.Ecosystem; движок ищет адаптер по нему в
// карте, переданной из wire (compile-time реестр + blank-import).
//
// ValidateObjectPath проверяет путь, который клиент хочет загрузить
// (после domain.ValidateKey — общего транспорта-предохранителя): apt
// принимает только pool/* с известными расширениями; dists/* —
// генерируется, клиенту туда соваться нельзя. Возврат *domain.ValidationError
// маппится web-слоем на 400.
//
// GenerateIndexes обходит пул пакетов репо, читает метаданные и пишет
// индексы (apt: Packages + .gz + by-hash + Release). Атомарность v1 —
// перезапись ключей после полной генерации staging; полный atomic-swap
// вместе с s3 — сессия 17, подпись — сессия 15. Путь в Storage:
// repo/<repo-id>/<ecosystem>/<...>; полный префикс — RepoPrefix(repo).
type RepoAdapter interface {
	Name() string
	ValidateObjectPath(path string) error
	GenerateIndexes(ctx context.Context, repo domain.Repo, storage Storage, p RepoProgress) error
}

// RepoPrefix возвращает корневой префикс ключей личного репозитория в
// едином namespace Storage: repo/<repo-id>/<ecosystem>. Слеши — от
// функции, вызывающий дописывает только путь внутри репо (без ведущего
// слеша). Используется движком publish и публичным роутером :29202.
func RepoPrefix(repo domain.Repo) string {
	return "repo/" + itoa(repo.ID) + "/" + repo.Ecosystem
}

// itoa — локальный strconv-заменитель, чтобы не тянуть strconv в порт.
// Производительность не критична: путь строится на запрос. Большие ID
// репо (>20 цифр) не бывают.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	const digits = "0123456789"
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
