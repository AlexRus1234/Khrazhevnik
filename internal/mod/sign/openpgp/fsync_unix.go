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

//go:build !windows

package openpgp

import (
	"errors"
	"os"
	"syscall"
)

// fsyncDir — сброс каталога на носитель после rename: без него
// фиксация ключа переживает не всякое выключение питания. Файловые
// системы без fsync каталогов (некоторые network/vfat) сообщают
// поддерживаемые коды — это не ошибка. Дубликат fs-хранилища:
// mod→mod-импорты запрещены depguard.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) ||
			errors.Is(err, syscall.EBADF) {
			return nil
		}
		return err
	}
	return nil
}
