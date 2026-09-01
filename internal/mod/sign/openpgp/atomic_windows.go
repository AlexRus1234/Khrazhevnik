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

//go:build windows

package openpgp

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// Антивирус/индексатор на доли миллисекунды открывают свежие файлы без
// FILE_SHARE_DELETE — MoveFileEx поверх такого файла отбивается
// ACCESS_DENIED/SHARING_VIOLATION. Короткий retry выжидает ложку,
// не меняя семантики (каждая попытка — по-прежнему атомарный rename).
// Дубликат fs-хранилища: mod→mod-импорты запрещены depguard; в проде
// (linux-контейнер) используется unix-вариант.
const (
	renameAttempts = 10
	renamePause    = 2 * time.Millisecond
)

// renameReplace — замена с retry под Windows-специфичные транзиентные
// отказы.
func renameReplace(from, to string) error {
	err := os.Rename(from, to)
	for i := 0; err != nil && i < renameAttempts && transientRename(err); i++ {
		time.Sleep(renamePause)
		err = os.Rename(from, to)
	}
	return err
}

// transientRename — отказ, который может пройти через миллисекунды
// (ERROR_SHARING_VIOLATION живёт в x/sys; в stdlib syscall приходит
// как ERROR_ACCESS_DENIED — его и ловим).
func transientRename(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED)
}

// fsyncDir — no-op: Windows не даёт открыть каталог на запись для
// FlushFileBuffers, целостность метаданных NTFS обеспечивает
// журналирование. Прод-контейнер — scratch Linux, там работает
// unix-вариант.
func fsyncDir(string) error { return nil }
