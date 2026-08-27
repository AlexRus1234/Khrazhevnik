/*
Хражевник — кеш-прокси и зеркало linux-репозиториев
Copyright (C) 2026 AlexRus1234

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

// Маппинг snake_case-кодов API (docs/SPECIFICATION.md §Коды ошибок) в
// локализованный текст: строка живёт в locales/{ru,en}.json (errors.*),
// коды стабильны. Неизвестный фронту код → «ошибка (HTTP N)»; сетевой
// сбой (status 0) → network. t() читает locale при вызове — строки,
// отрендеренные в шаблоне через errText, реагируют на смену языка.

import { ApiError } from './api'
import { t, tr } from './i18n'

export function errText(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === 'unknown') return t('errors.unknown')
    const s = tr(`errors.${e.code}`)
    if (s !== null) return s
    if (e.status > 0) return t('errors.httpStatus', { status: e.status })
    return t('errors.network')
  }
  return t('errors.fallback')
}
