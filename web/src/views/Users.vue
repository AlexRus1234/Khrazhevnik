<!--
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
-->

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { request } from '../api'
import { errText } from '../errors'
import { formatTime, parseDuration } from '../format'
import type { ApiToken, User } from '../types'

// Экран admin-only: не-админ увидит forbidden — честно показываем
// текст ошибки (роли в JWT нет, /me-эндпоинта нет).

const users = ref<User[]>([])
const error = ref('')
const loaded = ref(false)

const showForm = ref(false)
const fUsername = ref('')
const fPassword = ref('')
const fRole = ref<'admin' | 'user'>('user')
const formError = ref('')
const busy = ref(false)

// Выпадающая панель токенов на пользователя: expanded === user.id.
const expanded = ref<number | null>(null)
const tokens = ref<Record<number, ApiToken[]>>({})
const tokenError = ref<Record<number, string>>({})

// Создание токена: имя, scope (admin или repo:<id>:write), TTL.
const tName = ref('')
const tScope = ref('admin')
const tRepoID = ref('')
const tTTL = ref('')
const tError = ref<Record<number, string>>({})

// Сырой токен показывается один раз: server хранит только sha256.
const freshToken = ref<Record<number, { token: string; name: string }>>({})
const copied = ref(false)

async function load(): Promise<void> {
  try {
    users.value = await request<User[]>('GET', '/users')
    error.value = ''
    loaded.value = true
  } catch (e) {
    error.value = errText(e)
  }
}

onMounted(load)

async function createUser(): Promise<void> {
  if (busy.value) return
  busy.value = true
  formError.value = ''
  try {
    await request('POST', '/users', {
      body: { username: fUsername.value, password: fPassword.value, role: fRole.value },
    })
    showForm.value = false
    fUsername.value = ''
    fPassword.value = ''
    fRole.value = 'user'
    await load()
  } catch (e) {
    formError.value = errText(e)
  } finally {
    busy.value = false
  }
}

async function removeUser(u: User): Promise<void> {
  if (!window.confirm(`Удалить пользователя «${u.username}»? Токены отзовутся.`)) return
  try {
    await request('DELETE', `/users/${u.id}`)
    await load()
  } catch (e) {
    error.value = errText(e)
  }
}

async function toggleTokens(u: User): Promise<void> {
  if (expanded.value === u.id) {
    expanded.value = null
    return
  }
  expanded.value = u.id
  tName.value = ''
  tScope.value = 'admin'
  tRepoID.value = ''
  tTTL.value = ''
  await loadTokens(u.id)
}

async function loadTokens(userID: number): Promise<void> {
  try {
    tokens.value[userID] = await request<ApiToken[]>('GET', `/users/${userID}/api-tokens`)
  } catch (e) {
    tokenError.value[userID] = errText(e)
  }
}

function scopeValue(): string {
  return tScope.value === 'repo' ? `repo:${tRepoID.value}:write` : 'admin'
}

async function issueToken(u: User): Promise<void> {
  // TTL — опциональная duration («30d», «12h»); пусто — бессрочный.
  const ttlNS = parseDuration(tTTL.value)
  if (ttlNS === null) {
    tError.value[u.id] = 'TTL: примеры «12h», «30d»; пусто — бессрочный'
    return
  }
  if (tScope.value === 'repo' && !/^\d+$/.test(tRepoID.value)) {
    tError.value[u.id] = 'укажите числовой ID репозитория'
    return
  }
  tError.value[u.id] = ''
  try {
    const out = await request<{ token: string; name: string }>(
      'POST',
      `/users/${u.id}/api-tokens`,
      {
        body: {
          name: tName.value,
          scopes: [scopeValue()],
          ttl: ttlNS === 0 ? undefined : ttlNS,
        },
      },
    )
    freshToken.value[u.id] = { token: out.token, name: out.name }
    copied.value = false
    tName.value = ''
    tTTL.value = ''
    await loadTokens(u.id)
  } catch (e) {
    tError.value[u.id] = errText(e)
  }
}

async function revokeToken(u: User, t: ApiToken): Promise<void> {
  try {
    await request('DELETE', `/users/${u.id}/api-tokens/${t.id}`)
    await loadTokens(u.id)
  } catch (e) {
    tokenError.value[u.id] = errText(e)
  }
}

async function copyFresh(): Promise<void> {
  if (expanded.value === null) return
  const f = freshToken.value[expanded.value]
  if (!f) return
  try {
    await navigator.clipboard.writeText(f.token)
    copied.value = true
  } catch {
    // clipboard API может быть недоступна (не https) — пользователь
    // выделяет текст вручную.
  }
}

function zeroTime(iso: string | undefined): boolean {
  return !iso || iso.startsWith('0001-')
}
</script>

<template>
  <section>
    <div class="row spread">
      <h1>Пользователи</h1>
      <button class="btn primary" @click="showForm = !showForm">Добавить</button>
    </div>
    <p v-if="error" class="error">{{ error }}</p>

    <div v-if="showForm" class="panel">
      <h2>Новый пользователь</h2>
      <form class="grid" @submit.prevent="createUser">
        <div class="row">
          <label class="field"
            >Логин
            <input v-model="fUsername" required />
          </label>
          <label class="field"
            >Пароль
            <input v-model="fPassword" type="password" required autocomplete="new-password" />
          </label>
          <label class="field"
            >Роль
            <select v-model="fRole">
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          </label>
        </div>
        <p v-if="formError" class="error">{{ formError }}</p>
        <div class="row">
          <button class="btn primary" type="submit" :disabled="busy">Создать</button>
          <button class="btn" type="button" @click="showForm = false">Отмена</button>
        </div>
      </form>
    </div>

    <div class="panel">
      <table v-if="users.length > 0">
        <thead>
          <tr>
            <th>Логин</th>
            <th>Роль</th>
            <th>Создан</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <template v-for="u in users" :key="u.id">
            <tr>
              <td>{{ u.username }}</td>
              <td>
                <span class="badge" :class="{ succeeded: u.role === 'admin' }">{{ u.role }}</span>
              </td>
              <td class="dim">{{ formatTime(u.created_at) }}</td>
              <td>
                <div class="row actions">
                  <button class="btn" @click="toggleTokens(u)">
                    {{ expanded === u.id ? 'Скрыть токены' : 'API-токены' }}
                  </button>
                  <button class="btn danger" @click="removeUser(u)">Удалить</button>
                </div>
              </td>
            </tr>
            <tr v-if="expanded === u.id" class="tokens">
              <td colspan="4">
                <div v-if="freshToken[u.id]" class="fresh">
                  <p class="warn">
                    Токен «{{ freshToken[u.id].name }}» показывается один раз — скопируйте:
                  </p>
                  <div class="row">
                    <pre class="snippet grow mono">{{ freshToken[u.id].token }}</pre>
                    <button class="btn" @click="copyFresh">
                      {{ copied ? 'Скопировано' : 'Копировать' }}
                    </button>
                  </div>
                </div>
                <form class="row" @submit.prevent="issueToken(u)">
                  <label class="field"
                    >Имя
                    <input v-model="tName" placeholder="deploy" required />
                  </label>
                  <label class="field"
                    >Scope
                    <select v-model="tScope">
                      <option value="admin">admin</option>
                      <option value="repo">repo:&lt;id&gt;:write</option>
                    </select>
                  </label>
                  <label v-if="tScope === 'repo'" class="field"
                    >ID репо
                    <input v-model="tRepoID" placeholder="3" required />
                  </label>
                  <label class="field"
                    >TTL
                    <input v-model="tTTL" placeholder="30d" />
                  </label>
                  <button class="btn" type="submit">Выпустить</button>
                </form>
                <p v-if="tError[u.id]" class="error">{{ tError[u.id] }}</p>
                <p v-if="tokenError[u.id]" class="error">{{ tokenError[u.id] }}</p>
                <table v-if="tokens[u.id]">
                  <thead>
                    <tr>
                      <th>Имя</th>
                      <th>Префикс</th>
                      <th>Scopes</th>
                      <th>Создан</th>
                      <th>Истекает</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="t in tokens[u.id]" :key="t.id">
                      <td>{{ t.name }}</td>
                      <td class="mono">{{ t.prefix }}…</td>
                      <td class="mono">{{ t.scopes.join(', ') }}</td>
                      <td class="dim">{{ formatTime(t.created_at) }}</td>
                      <td class="dim">{{ zeroTime(t.expires_at) ? 'бессрочно' : formatTime(t.expires_at) }}</td>
                      <td>
                        <button class="btn danger small" @click="revokeToken(u, t)">Отозвать</button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
      <p v-else-if="loaded" class="dim">Пользователей нет.</p>
      <p v-else class="dim">Загрузка…</p>
    </div>
  </section>
</template>

<style scoped>
.actions .btn {
  padding: 0.2rem 0.6rem;
}

.small {
  padding: 0.2rem 0.6rem;
}

.tokens > td {
  background: var(--inset);
  border-radius: 6px;
  padding: 0.75rem;
}

.fresh {
  margin-bottom: 0.75rem;
}
</style>
