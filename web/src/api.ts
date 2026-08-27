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

// Обёртка над fetch для REST API админки (docs/SPECIFICATION.md §REST).
// Токен сессии живёт в localStorage; 401 от любого запроса очищает токен
// и оповещает приложение событием UNAUTHORIZED_EVENT. Рукописный (без
// axios): минимум зависимостей, прозрачное поведение. Тело ошибки API —
// {"error":"snake_case_code"}, код живёт в ApiError.code (маппинг в
// текст — errors.ts; i18n — сессия 18.3).

export const UNAUTHORIZED_EVENT = 'khrazhevnik:unauthorized'

const TOKEN_KEY = 'khrazhevnik_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null): void {
  if (token === null) {
    localStorage.removeItem(TOKEN_KEY)
  } else {
    localStorage.setItem(TOKEN_KEY, token)
  }
}

// ApiError — ошибка HTTP с snake_case-кодом из тела {"error":...}.
export class ApiError extends Error {
  status: number
  code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined>
  body?: unknown
  headers?: Record<string, string>
}

function buildQuery(query: RequestOptions['query']): string {
  if (!query) return ''
  const parts: string[] = []
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined) continue
    parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
  }
  return parts.length > 0 ? `?${parts.join('&')}` : ''
}

function authHeaders(): Record<string, string> {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

function errorFromBody(status: number, data: unknown): ApiError {
  const code =
    data && typeof data === 'object' && 'error' in data && typeof data.error === 'string'
      ? data.error
      : 'unknown'
  return new ApiError(status, code, code)
}

async function parseBody(resp: Response): Promise<unknown> {
  const text = await resp.text()
  if (text === '') return null
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

// request выполняет запрос к /api/v1 и возвращает разобранный JSON.
export async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { ...authHeaders(), ...opts.headers }
  let body: string | undefined
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.body)
  }
  let resp: Response
  try {
    resp = await fetch(`/api/v1${path}${buildQuery(opts.query)}`, { method, headers, body })
  } catch {
    throw new ApiError(0, 'network', 'network')
  }
  // 401 от любого запроса = протухшая сессия: чистим токен и
  // оповещаем. Исключение — сам /auth/login: его 401 несёт код
  // invalid_credentials (или rate-limit) и должен дойти до экрана
  // входа как есть, иначе локализация кодов ошибок теряет смысл.
  if (resp.status === 401 && path !== '/auth/login') {
    setToken(null)
    window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT))
    throw new ApiError(401, 'auth_required', 'auth_required')
  }
  const data = await parseBody(resp)
  if (!resp.ok) throw errorFromBody(resp.status, data)
  return data as T
}

// login — POST /auth/login → {"token"} (JWT кладём в localStorage).
export async function login(username: string, password: string): Promise<string> {
  const out = await request<{ token: string }>('POST', '/auth/login', {
    body: { username, password },
  })
  return out.token
}

// setup — POST /setup: первый админ (пустая БД), опциональный
// X-Setup-Token (KHRZ_SETUP_TOKEN на сервере).
export async function setup(username: string, password: string, setupToken: string): Promise<void> {
  const headers: Record<string, string> = {}
  if (setupToken !== '') headers['X-Setup-Token'] = setupToken
  await request('POST', '/setup', { body: { username, password }, headers })
}

// logout — POST /auth/logout: отзыв JWT в процессе. Ошибки (в т.ч.
// уже истёкшая сессия) проглатываем — локальный токен чистим в любом
// случае.
export async function logout(): Promise<void> {
  try {
    await request('POST', '/auth/logout', {})
  } catch {
    // 401 уже очистил токен; сетевая ошибка не должна блокировать выход.
  }
}

export interface UploadProgress {
  loaded: number
  total: number
}

// uploadObject — PUT /repos/{id}/objects/* стримом через XHR: только
// XHR даёт upload.onprogress, а Content-Length браузер ставит сам из
// File. force=true — перезапись существующего ключа (админ).
export function uploadObject(
  repoID: number,
  path: string,
  file: File,
  force: boolean,
  onProgress: (p: UploadProgress) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    const forceQ = force ? '?force=true' : ''
    xhr.open('PUT', `/api/v1/repos/${repoID}/objects/${path
      .split('/')
      .map(encodeURIComponent)
      .join('/')}${forceQ}`)
    xhr.setRequestHeader('Authorization', `Bearer ${getToken() ?? ''}`)
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress({ loaded: e.loaded, total: e.total })
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve()
        return
      }
      if (xhr.status === 401) {
        setToken(null)
        window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT))
      }
      let data: unknown = null
      try {
        data = JSON.parse(xhr.responseText)
      } catch {
        // не-JSON (например, plain-text от auth-middleware) — unknown-код
      }
      reject(errorFromBody(xhr.status, data))
    }
    xhr.onerror = () => reject(new ApiError(0, 'network', 'network'))
    // File целиком: браузер стримит его (не грузит в память) и ставит
    // Content-Length — обязательное требование upload-API v1.
    xhr.send(file)
  })
}
