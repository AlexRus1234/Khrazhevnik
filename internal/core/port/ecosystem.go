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

// Порт экосистемы пакетного менеджера. Реализации: mod/ecosystem/*
// (apt, rpm-md, pacman, apk, nix). Классификация Class/Kind живёт в
// domain — это предметная логика, а не деталь доставки.

package port

import "khrazhevnik/internal/core/domain"

// Target — куда бьёмся и где кешируем: полный URL upstream-объекта,
// его путь и ключ хранения. StorageKey вида
// cache/<eco>/<remote-id>/<upstream-path> — уникален и стабилен
// (remote берётся из БД по конфигурации маршрута).
type Target struct {
	UpstreamURL  string
	UpstreamPath string
	StorageKey   string
}

// Ecosystem — адаптер экосистемы: суть маппинг «путь публичного
// порта → upstream» + классификация объектов по изменчивости.
type Ecosystem interface {
	// Name — короткое имя экосистемы («apt», «rpm-md»), совпадает
	// с ecosystem в Remote и StorageKey. Каноническая форма — с
	// дефисом (конфиг нормализует rpm_md → rpm-md).
	Name() string

	// URLPrefix — первый сегмент путей публичного порта без слэшей
	// («apt», «rpm»). Чаще совпадает с Name, но не всегда: rpm-md
	// держит один адаптер под dnf+zypper, а URL держит короткий
	// «rpm» (как пишут в .repo baseurl). Роутер_MATCHит /{prefix}/*
	// и ищет экосистему по префиксу, а не по имени.
	URLPrefix() string

	// Resolve переводит путь публичного порта (например,
	// «/apt/debian/pool/main/a/app/app.deb») в Target; false — путь
	// не принадлежит экосистеме или remote неизвестен.
	Resolve(ecosystemPath string) (Target, bool)

	// Classify определяет класс объекта по пути upstream:
	// immutable-пакеты против mutable-индексов с TTL. Ошибка —
	// путь нераспознан (не матчится ни под одну схему экосистемы).
	Classify(upstreamPath string) (domain.Class, error)
}
