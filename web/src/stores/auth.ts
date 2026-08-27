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

// Реактивное состояние сессии без Pinia (белый список зависимостей —
// только vue/vue-router). Единственный модульный ref — гарантия, что
// все экраны видят один и тот же логин-статус; сам JWT живёт в
// localStorage (api.ts), store — только производное «вошли/вышли».
import { ref } from 'vue'
import { getToken, setToken } from '../api'

export const loggedIn = ref(getToken() !== null)

export function markLoggedIn(): void {
  loggedIn.value = true
}

// markLoggedOut чистит токен локально всегда — даже если /auth/logout
// не ответил: локальная сессия не должна переживать выход.
export function markLoggedOut(): void {
  setToken(null)
  loggedIn.value = false
}
