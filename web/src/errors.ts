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

// Маппинг snake_case-кодов API в ru-текст (docs/SPECIFICATION.md §Коды
// ошибок). Hardcoded ru — сессия 18.3 вынесет в i18n-словари; коды не
// меняются, меняется только источник строки.

import { ApiError } from './api'

const CODES: Record<string, string> = {
  network: 'сервер недоступен',
  auth_required: 'требуется вход',
  invalid_credentials: 'неверный логин или пароль',
  setup_already_done: 'первичный администратор уже создан',
  invalid_setup_token: 'неверный setup-токен',
  not_found: 'не найдено',
  conflict: 'конфликт: объект уже существует',
  forbidden: 'недостаточно прав',
  validation_error: 'неверные данные формы',
  too_large: 'объект больше лимита загрузки',
  quota_exceeded: 'квота репозитория превышена',
  stale: 'данные устарели, обновите',
  task_duplicate: 'задача уже запущена',
  task_limit: 'достигнут лимит параллельных задач',
  invalid_json: 'сервер не понял запрос (invalid_json)',
  tasks_unavailable: 'реестр задач недоступен',
  mirror_unavailable: 'движок зеркала недоступен',
  publish_unavailable: 'движок publish недоступен',
  unsupported: 'операция не поддерживается для этой экосистемы',
  length_required: 'не передан Content-Length',
  internal: 'внутренняя ошибка сервера',
  unknown: 'ошибка',
}

export function errText(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code in CODES) return CODES[e.code]
    if (e.status > 0) return `ошибка (HTTP ${e.status})`
    return CODES.network
  }
  return 'неизвестная ошибка'
}
