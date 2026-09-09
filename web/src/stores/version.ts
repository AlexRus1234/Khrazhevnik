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

// Версия сборки для отображения в углу UI. Один модульный ref (паттерн
// stores/auth.ts); источник — публичный GET /api/v1/ (без auth, доступен
// и на экране входа). Загрузка идёт один раз из App.vue; версия —
// косметика: при ошибке остаётся пустой строкой, интерфейс не роняем.
import { ref } from 'vue'
import { request } from '../api'

export const buildVersion = ref('')

export async function loadVersion(): Promise<void> {
  try {
    const out = await request<{ version: string }>('GET', '/')
    buildVersion.value = out.version
  } catch {
    // сеть/5xx — просто не показываем версию
  }
}
