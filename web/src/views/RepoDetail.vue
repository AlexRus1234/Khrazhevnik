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
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { request, uploadObject } from '../api'
import { errText } from '../errors'
import { formatBytes, formatSpeed, formatTime } from '../format'
import { t } from '../i18n'
import type {
  Perm,
  Repo,
  RepoObject,
  RetentionCandidate,
  RetentionPreview,
  TaskSnapshot,
  User,
} from '../types'

const route = useRoute()
const repoID = Number(route.params.id)

const repo = ref<Repo | null>(null)
const objects = ref<RepoObject[]>([])
const perms = ref<Perm[]>([])
const users = ref<User[]>([])
const error = ref('')
const usersError = ref('')

async function loadRepo(): Promise<void> {
  try {
    repo.value = await request<Repo>('GET', `/repos/${repoID}`)
    // Форма политики — из загруженного репо, затем пины: колонка-замок
    // в таблице объектов (нужен ecosystem — его знает только репо).
    seedRetention(repo.value)
    void loadPins()
  } catch (e) {
    error.value = errText(e)
  }
}

async function loadObjects(): Promise<void> {
  try {
    objects.value = await request<RepoObject[]>('GET', `/repos/${repoID}/objects`)
  } catch (e) {
    error.value = errText(e)
  }
}

async function loadPerms(): Promise<void> {
  try {
    perms.value = await request<Perm[]>('GET', `/repos/${repoID}/perms`)
  } catch (e) {
    error.value = errText(e)
  }
}

async function loadUsers(): Promise<void> {
  try {
    users.value = await request<User[]>('GET', '/users')
  } catch (e) {
    usersError.value = errText(e)
  }
}

onMounted(() => {
  void loadRepo()
  void loadObjects()
  void loadPerms()
  void loadUsers()
})

// Листинг отдаёт полные storage-ключи repo/<id>/<eco>/…; в таблице
// показываем путь внутри репо (без префикса экосистемы).
function relKey(key: string): string {
  const prefix =
    repo.value !== null ? `repo/${repoID}/${repo.value.ecosystem}/` : `repo/${repoID}/`
  return key.startsWith(prefix) ? key.slice(prefix.length) : key
}

async function deleteObject(key: string): Promise<void> {
  const rel = relKey(key)
  if (!window.confirm(t('repo.deleteObjectConfirm', { rel }))) return
  try {
    await request('DELETE', `/repos/${repoID}/objects/${key.split('/').map(encodeURIComponent).join('/')}`)
    await loadObjects()
  } catch (e) {
    error.value = errText(e)
  }
}

// Upload: путь внутри репо (apt — только pool/*); прогресс — XHR
// upload.onprogress (fetch его не даёт). Content-Length браузер ставит
// из File — обязательное требование upload-API v1.
const file = ref<File | null>(null)
const objPath = ref('')
const force = ref(false)
const uploading = ref(false)
const uploaded = ref(0)
const uploadTotal = ref(0)
const uploadSpeed = ref(0)
const uploadError = ref('')
const uploadDone = ref('')
let uploadStartedAt = 0

function onFileChange(e: Event): void {
  const files = (e.target as HTMLInputElement).files
  file.value = files && files.length > 0 ? files[0] : null
  // Умолчание pool/<имя файла>: путь для .deb в apt-репо. Пользователь
  // может переписать поле до отправки.
  if (file.value && objPath.value === '') {
    objPath.value = `pool/${file.value.name}`
  }
}

async function submitUpload(): Promise<void> {
  if (uploading.value || file.value === null || objPath.value === '') {
    uploadError.value = file.value === null ? t('repo.noFile') : t('repo.noPath')
    return
  }
  uploading.value = true
  uploaded.value = 0
  uploadTotal.value = file.value.size
  uploadSpeed.value = 0
  uploadError.value = ''
  uploadDone.value = ''
  uploadStartedAt = performance.now()
  try {
    await uploadObject(repoID, objPath.value, file.value, force.value, (p) => {
      uploaded.value = p.loaded
      uploadTotal.value = p.total
      const sec = (performance.now() - uploadStartedAt) / 1000
      if (sec > 0) uploadSpeed.value = p.loaded / sec
    })
    uploadDone.value = t('repo.uploaded', { path: objPath.value })
    objPath.value = ''
    file.value = null
    const input = document.getElementById('upload-file') as HTMLInputElement | null
    if (input) input.value = ''
    await loadObjects()
  } catch (e) {
    uploadError.value = errText(e)
  } finally {
    uploading.value = false
  }
}

const uploadPercent = computed(() =>
  uploadTotal.value > 0 ? Math.round((uploaded.value / uploadTotal.value) * 100) : 0,
)

// Perms: grant по user_id (select из списка users), revoke по клику.
const grantUserID = ref<number | null>(null)
const permError = ref('')

async function grant(): Promise<void> {
  if (grantUserID.value === null) return
  permError.value = ''
  try {
    await request('POST', `/repos/${repoID}/perms`, { body: { user_id: grantUserID.value } })
    await loadPerms()
  } catch (e) {
    permError.value = errText(e)
  }
}

async function revoke(userID: number): Promise<void> {
  permError.value = ''
  try {
    await request('DELETE', `/repos/${repoID}/perms/${userID}`)
    await loadPerms()
  } catch (e) {
    permError.value = errText(e)
  }
}

// Reindex: 202 → поллинг снимка задачи до терминального состояния.
const reindexTask = ref<TaskSnapshot | null>(null)
const reindexError = ref('')
let reindexTimer: number | undefined

async function pollReindex(taskID: string, after?: () => Promise<void>): Promise<void> {
  try {
    reindexTask.value = await request<TaskSnapshot>('GET', `/tasks/${taskID}`)
  } catch {
    reindexTask.value = null
    reindexError.value = t('repo.reindexLost')
    stopReindexPoll()
    return
  }
  if (reindexTask.value.state !== 'running') {
    stopReindexPoll()
    await loadObjects()
    // Хвост после терминального состояния (сессия 173): применение
    // ретеншна дочитывает пины и показывает итог прохода.
    if (after) await after()
  }
}

function stopReindexPoll(): void {
  if (reindexTimer !== undefined) {
    window.clearInterval(reindexTimer)
    reindexTimer = undefined
  }
}

// startReindexPoll — единственная точка поллинга снимка задачи: им
// пользуются и reindex, и применение ретеншна (202 → task_id).
function startReindexPoll(taskID: string, after?: () => Promise<void>): void {
  if (reindexTimer !== undefined) window.clearInterval(reindexTimer)
  reindexTimer = window.setInterval(() => {
    void pollReindex(taskID, after)
  }, 1000)
  void pollReindex(taskID, after)
}

async function reindex(): Promise<void> {
  reindexError.value = ''
  reindexTask.value = null
  try {
    const out = await request<{ task_id: string }>('POST', `/repos/${repoID}/reindex`)
    startReindexPoll(out.task_id)
  } catch (e) {
    reindexError.value = errText(e)
  }
}

onUnmounted(stopReindexPoll)

// --- Ретеншн (сессия 173) -------------------------------------------------
// Политика репо, прогноз кандидатов (dry-run), применение (confirm →
// фоновая задача → поллинг) и пины версий в таблице объектов.
// nix — content-addressed: семейств нет, движок отдаёт UnsupportedError
// (retention.go:281) — блок и колонку пина не показываем.
const canRetention = computed(() => repo.value !== null && repo.value.ecosystem !== 'nix')

const retentionEnabled = ref(false)
const retentionMin = ref(2)
const retentionMaxAge = ref(90)
const retentionSaving = ref(false)
const retentionSaved = ref(false)
const retentionError = ref('')

// Пустая политика {0,0} — выключена. Поля при выключенной политике
// держат прошлые значения: включение чекбокса отправляет их, а не нули.
function seedRetention(r: Repo): void {
  const min = r.retention.min_versions
  const age = r.retention.max_age_days
  retentionEnabled.value = min > 0 || age > 0
  if (retentionEnabled.value) {
    retentionMin.value = min
    retentionMaxAge.value = age
  }
  retentionSaved.value = false
}

async function saveRetention(): Promise<void> {
  if (repo.value === null || retentionSaving.value) return
  retentionError.value = ''
  retentionSaved.value = false
  const min = retentionEnabled.value ? Number(retentionMin.value) : 0
  const age = retentionEnabled.value ? Number(retentionMaxAge.value) : 0
  if (!Number.isInteger(min) || !Number.isInteger(age) || min < 0 || age < 0) {
    retentionError.value = t('repo.retentionNumError')
    return
  }
  // Зеркало серверной валидации (domain.ValidateRetention): возраст без
  // минимума ≥2 удалил бы последнюю версию семейства (окно 404) — такой
  // запрос не отправляем вовсе; прочие отказы сервера показываем как есть.
  if (age > 0 && min < 2) {
    retentionError.value = t('repo.retentionMinError')
    return
  }
  retentionSaving.value = true
  const r = repo.value
  try {
    // PATCH — full-replace: тело собираем из загруженного репо, меняя
    // только политику (имя/экосистема/владелец/квота не трогаются).
    await request<Repo>('PATCH', `/repos/${repoID}`, {
      body: {
        name: r.name,
        ecosystem: r.ecosystem,
        owner_id: r.owner_id,
        quota: { max_bytes: r.quota.max_bytes, max_objects: r.quota.max_objects },
        retention: { min_versions: min, max_age_days: age },
      },
    })
    await loadRepo()
    retentionSaved.value = true
  } catch (e) {
    retentionError.value = errText(e)
  } finally {
    retentionSaving.value = false
  }
}

// Прогноз — синхронный dry-run отчёт движка; пустой список кандидатов
// не ошибка: dim-строка «кандидатов нет».
const candidates = ref<RetentionCandidate[]>([])
const previewing = ref(false)
const previewDone = ref(false)
const previewError = ref('')

async function previewRetention(): Promise<boolean> {
  if (previewing.value) return false
  previewing.value = true
  previewError.value = ''
  applyError.value = ''
  applyDone.value = ''
  try {
    const out = await request<RetentionPreview>('GET', `/repos/${repoID}/retention/preview`)
    candidates.value = out.candidates ?? []
    previewDone.value = true
    return true
  } catch (e) {
    previewError.value = errText(e)
    return false
  } finally {
    previewing.value = false
  }
}

// Применение необратимо: confirm с числами прогноза (прогноз делаем,
// если его ещё не было — цифры удаляемого нужны до нажатия) и
// существующий механизм поллинга задачи.
const applying = ref(false)
const applyError = ref('')
const applyDone = ref('')

async function applyRetention(): Promise<void> {
  if (applying.value) return
  applyError.value = ''
  applyDone.value = ''
  if (!previewDone.value && !(await previewRetention())) return
  const bytes = candidates.value.reduce((sum, c) => sum + c.size, 0)
  const n = candidates.value.length
  if (!window.confirm(t('repo.retentionConfirm', { n: String(n), size: formatBytes(bytes) }))) return
  applying.value = true
  try {
    const out = await request<{ task_id: string }>('POST', `/repos/${repoID}/retention/apply`)
    startReindexPoll(out.task_id, async () => {
      // Итог прохода — последняя строка лога задачи (счётчики движка);
      // листинг уже перечитан поллером, пины могли осиротеть.
      const logs = reindexTask.value !== null ? reindexTask.value.logs : []
      applyDone.value = logs.length > 0 ? logs[logs.length - 1] : t('repo.retentionApplyDone')
      await loadPins()
    })
  } catch (e) {
    applyError.value = errText(e)
  } finally {
    applying.value = false
  }
}

// Пины: замок в строке таблицы объектов. GET pins отдаёт полные
// storage-ключи (сверяем с o.key), PUT/DELETE — путь ВНУТРИ репо:
// хендлер сам приклеивает префикс repo/<id>/<eco>/ (handlers_retention.go
// retentionPinKey), полный ключ дал бы двойной префикс и 404.
const pins = ref<string[]>([])
const pinError = ref('')

function isPinned(key: string): boolean {
  return pins.value.includes(key)
}

async function loadPins(): Promise<void> {
  if (!canRetention.value) return
  try {
    pins.value = await request<string[]>('GET', `/repos/${repoID}/retention/pins`)
  } catch (e) {
    pinError.value = errText(e)
  }
}

async function togglePin(key: string): Promise<void> {
  pinError.value = ''
  const path = relKey(key)
    .split('/')
    .map(encodeURIComponent)
    .join('/')
  try {
    await request(isPinned(key) ? 'DELETE' : 'PUT', `/repos/${repoID}/retention/pins/${path}`)
    await loadPins()
  } catch (e) {
    pinError.value = errText(e)
  }
}

// Причина защиты из строки прогноза: min/access/pin (движок отдаёт
// access|pin; min оставлен на будущее — ключи есть в обоих словарях).
function protectedLabel(by: string): string {
  if (by === 'access') return t('repo.protectedByAccess')
  if (by === 'pin') return t('repo.protectedByPin')
  if (by === 'min') return t('repo.protectedByMin')
  return by
}

function userName(id: number): string {
  const u = users.value.find((x) => x.id === id)
  return u ? u.username : `#${id}`
}
</script>

<template>
  <section>
    <div class="row spread">
      <h1>
        <RouterLink to="/repos">{{ t('nav.repos') }}</RouterLink> /
        <span class="mono">{{ repo?.name ?? `#${repoID}` }}</span>
      </h1>
      <button class="btn primary" :disabled="reindexTask?.state === 'running'" @click="reindex">
        {{ reindexTask?.state === 'running' ? t('repo.reindexing') : t('repo.reindex') }}
      </button>
    </div>
    <p v-if="error" class="error">{{ error }}</p>

    <div v-if="repo" class="panel">
      <div class="row">
        <span class="dim">{{ t('repo.ecosystem') }}</span> {{ repo.ecosystem }}
        <span class="dim">{{ t('repo.owner') }}</span> #{{ repo.owner_id }}
        <span class="dim">{{ t('repo.quota') }}</span>
        {{ repo.quota.max_bytes > 0 ? formatBytes(repo.quota.max_bytes) : t('repo.infBytes') }} /
        {{ repo.quota.max_objects > 0 ? repo.quota.max_objects : t('repo.infFiles') }}
        <span class="dim">{{ t('repo.created') }}</span> {{ formatTime(repo.created_at) }}
      </div>
      <div v-if="reindexTask" class="row">
        <span class="badge" :class="reindexTask.state">{{ reindexTask.state }}</span>
        <div class="progress grow">
          <div :style="{ width: `${Math.round(reindexTask.percent)}%` }"></div>
        </div>
        <span class="dim">{{ reindexTask.phase }} {{ reindexTask.current }}</span>
      </div>
      <p v-if="reindexTask?.state === 'failed'" class="error">{{ reindexTask.error }}</p>
      <p v-if="reindexError" class="error">{{ reindexError }}</p>
    </div>

    <div class="panel">
      <h2>{{ t('repo.uploadTitle') }}</h2>
      <form class="grid" @submit.prevent="submitUpload">
        <div class="row">
          <label class="field grow2"
            >{{ t('repo.pathLabel') }}
            <input v-model="objPath" required placeholder="pool/main/myapp_1.0_amd64.deb" />
          </label>
          <label class="field"
            >{{ t('repo.fileLabel') }}
            <input id="upload-file" type="file" required @change="onFileChange" />
          </label>
          <label class="field check"
            >{{ t('repo.forceLabel') }}
            <input v-model="force" type="checkbox" />
          </label>
        </div>
        <div v-if="uploading || uploadTotal > 0" class="row">
          <div class="progress grow">
            <div :style="{ width: `${uploadPercent}%` }"></div>
          </div>
          <span class="dim"
            >{{ formatBytes(uploaded) }} / {{ formatBytes(uploadTotal) }} ·
            {{ uploadPercent }} % · {{ formatSpeed(uploadSpeed) }}</span
          >
        </div>
        <p v-if="uploadError" class="error">{{ uploadError }}</p>
        <p v-else-if="uploadDone" class="ok">{{ uploadDone }}</p>
        <div class="row">
          <button class="btn primary" type="submit" :disabled="uploading">
            {{ uploading ? t('repo.uploading') : t('repo.uploadBtn') }}
          </button>
        </div>
      </form>
    </div>

    <div v-if="repo && canRetention" class="panel">
      <h2>{{ t('repo.retention') }}</h2>
      <p class="dim">{{ t('repo.retentionPinned') }}</p>
      <form class="row" @submit.prevent="saveRetention">
        <label class="field check"
          >{{ t('repo.retentionEnable') }}
          <input v-model="retentionEnabled" type="checkbox" />
        </label>
        <label class="field"
          >{{ t('repo.retentionMin') }}
          <input v-model.number="retentionMin" type="number" min="0" :disabled="!retentionEnabled" />
        </label>
        <label class="field"
          >{{ t('repo.retentionMaxAge') }}
          <input v-model.number="retentionMaxAge" type="number" min="0" :disabled="!retentionEnabled" />
        </label>
        <button class="btn" type="submit" :disabled="retentionSaving">{{ t('repo.retentionSave') }}</button>
      </form>
      <p v-if="retentionError" class="error">{{ retentionError }}</p>
      <p v-else-if="retentionSaved" class="ok">{{ t('repo.retentionSaved') }}</p>
      <div class="row">
        <button class="btn" type="button" :disabled="previewing" @click="previewRetention">
          {{ t('repo.retentionPreview') }}
        </button>
        <button class="btn danger" type="button" :disabled="applying" @click="applyRetention">
          {{ t('repo.retentionApply') }}
        </button>
      </div>
      <p v-if="previewError" class="error">{{ previewError }}</p>
      <p v-if="applyError" class="error">{{ applyError }}</p>
      <p v-else-if="applyDone" class="ok">{{ applyDone }}</p>
      <table v-if="candidates.length > 0">
        <thead>
          <tr>
            <th>{{ t('repo.colPath') }}</th>
            <th>{{ t('repo.colFamily') }}</th>
            <th>{{ t('repo.colSize') }}</th>
            <th>{{ t('repo.colModified') }}</th>
            <th>{{ t('repo.colLastAccess') }}</th>
            <th>{{ t('repo.colProtected') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in candidates" :key="c.key">
            <td class="mono" :title="c.key">{{ relKey(c.key).slice(0, 79) }}</td>
            <td class="mono">{{ c.family }}</td>
            <td>{{ formatBytes(c.size) }}</td>
            <td class="dim">{{ formatTime(c.mod_time) }}</td>
            <td class="dim">{{ formatTime(c.last_access) }}</td>
            <td>
              <span v-if="c.protected_by !== ''" class="badge">{{ protectedLabel(c.protected_by) }}</span>
              <span v-else class="dim">—</span>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else-if="previewDone" class="dim">{{ t('repo.candidatesEmpty') }}</p>
    </div>
    <p v-else-if="repo" class="dim">{{ t('repo.retentionNotSupported') }}</p>

    <div class="panel">
      <h2>{{ t('repo.objects', { n: objects.length }) }}</h2>
      <table v-if="objects.length > 0">
        <thead>
          <tr>
            <th>{{ t('repo.colPath') }}</th>
            <th>{{ t('repo.colSize') }}</th>
            <th>{{ t('repo.colModified') }}</th>
            <th v-if="canRetention"></th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="o in objects" :key="o.key">
            <td class="mono">{{ relKey(o.key) }}</td>
            <td>{{ formatBytes(o.size) }}</td>
            <td class="dim">{{ formatTime(o.mod_time) }}</td>
            <td v-if="canRetention">
              <button
                class="btn small"
                :title="isPinned(o.key) ? t('repo.unpin') : t('repo.pin')"
                :aria-label="isPinned(o.key) ? t('repo.unpin') : t('repo.pin')"
                @click="togglePin(o.key)"
              >
                {{ isPinned(o.key) ? '🔒' : '🔓' }}
              </button>
            </td>
            <td>
              <button class="btn danger small" @click="deleteObject(o.key)">{{ t('common.delete') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim">{{ t('repo.objectsEmpty') }}</p>
      <p v-if="pinError" class="error">{{ pinError }}</p>
    </div>

    <div class="panel">
      <h2>{{ t('repo.permsTitle') }}</h2>
      <p class="dim">{{ t('repo.permsHint', { id: repo?.owner_id ?? 0 }) }}</p>
      <table v-if="perms.length > 0">
        <thead>
          <tr>
            <th>{{ t('common.user') }}</th>
            <th>{{ t('repo.colGranted') }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in perms" :key="p.user_id">
            <td>{{ userName(p.user_id) }} (#{{ p.user_id }})</td>
            <td class="dim">{{ formatTime(p.created_at) }}</td>
            <td>
              <button class="btn danger small" @click="revoke(p.user_id)">{{ t('repo.revoke') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim">{{ t('repo.permsEmpty') }}</p>
      <form v-if="usersError === ''" class="row" @submit.prevent="grant">
        <label class="field"
        >{{ t('common.user') }}
          <select v-model="grantUserID" required>
            <option v-for="u in users" :key="u.id" :value="u.id">
              {{ u.username }} (#{{ u.id }})
            </option>
          </select>
        </label>
        <button class="btn" type="submit">{{ t('repo.grantBtn') }}</button>
      </form>
      <p v-if="permError" class="error">{{ permError }}</p>
    </div>
  </section>
</template>

<style scoped>
.grow {
  flex: 1;
  min-width: 8rem;
}

.grow2 {
  flex: 2;
}

.small {
  padding: 0.2rem 0.6rem;
}

.check {
  flex-direction: row;
  align-items: center;
  gap: 0.4rem;
}
</style>
