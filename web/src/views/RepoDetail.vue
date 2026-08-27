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
import type { Perm, Repo, RepoObject, TaskSnapshot, User } from '../types'

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
  if (!window.confirm(`Удалить объект «${rel}»?`)) return
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
    uploadError.value = file.value === null ? 'выберите файл' : 'укажите путь внутри репо'
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
    uploadDone.value = `загружено: ${objPath.value}`
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

async function pollReindex(taskID: string): Promise<void> {
  try {
    reindexTask.value = await request<TaskSnapshot>('GET', `/tasks/${taskID}`)
  } catch {
    reindexTask.value = null
    reindexError.value = 'задача исчезла (рестарт сервера?)'
    stopReindexPoll()
    return
  }
  if (reindexTask.value.state !== 'running') {
    stopReindexPoll()
    await loadObjects()
  }
}

function stopReindexPoll(): void {
  if (reindexTimer !== undefined) {
    window.clearInterval(reindexTimer)
    reindexTimer = undefined
  }
}

async function reindex(): Promise<void> {
  reindexError.value = ''
  reindexTask.value = null
  try {
    const out = await request<{ task_id: string }>('POST', `/repos/${repoID}/reindex`)
    if (reindexTimer !== undefined) window.clearInterval(reindexTimer)
    reindexTimer = window.setInterval(() => {
      void pollReindex(out.task_id)
    }, 1000)
    void pollReindex(out.task_id)
  } catch (e) {
    reindexError.value = errText(e)
  }
}

onUnmounted(stopReindexPoll)

function userName(id: number): string {
  const u = users.value.find((x) => x.id === id)
  return u ? u.username : `#${id}`
}
</script>

<template>
  <section>
    <div class="row spread">
      <h1>
        <RouterLink to="/repos">Репозитории</RouterLink> /
        <span class="mono">{{ repo?.name ?? `#${repoID}` }}</span>
      </h1>
      <button class="btn primary" :disabled="reindexTask?.state === 'running'" @click="reindex">
        {{ reindexTask?.state === 'running' ? 'Переиндексация…' : 'Переиндексировать' }}
      </button>
    </div>
    <p v-if="error" class="error">{{ error }}</p>

    <div v-if="repo" class="panel">
      <div class="row">
        <span class="dim">экосистема:</span> {{ repo.ecosystem }}
        <span class="dim">владелец:</span> #{{ repo.owner_id }}
        <span class="dim">квота:</span>
        {{ repo.quota.max_bytes > 0 ? formatBytes(repo.quota.max_bytes) : '∞ байт' }} /
        {{ repo.quota.max_objects > 0 ? repo.quota.max_objects : '∞ файлов' }}
        <span class="dim">создан:</span> {{ formatTime(repo.created_at) }}
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
      <h2>Загрузка пакета</h2>
      <form class="grid" @submit.prevent="submitUpload">
        <div class="row">
          <label class="field grow2"
            >Путь внутри репо (apt — pool/*)
            <input v-model="objPath" required placeholder="pool/main/myapp_1.0_amd64.deb" />
          </label>
          <label class="field"
            >Файл
            <input id="upload-file" type="file" required @change="onFileChange" />
          </label>
          <label class="field check"
            >перезапись (force, админ)
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
            {{ uploading ? 'Загрузка…' : 'Загрузить' }}
          </button>
        </div>
      </form>
    </div>

    <div class="panel">
      <h2>Объекты ({{ objects.length }})</h2>
      <table v-if="objects.length > 0">
        <thead>
          <tr>
            <th>Путь</th>
            <th>Размер</th>
            <th>Изменён</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="o in objects" :key="o.key">
            <td class="mono">{{ relKey(o.key) }}</td>
            <td>{{ formatBytes(o.size) }}</td>
            <td class="dim">{{ formatTime(o.mod_time) }}</td>
            <td>
              <button class="btn danger small" @click="deleteObject(o.key)">Удалить</button>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim">Пусто. Загрузите пакеты и запустите переиндексацию.</p>
    </div>

    <div class="panel">
      <h2>Права на запись</h2>
      <p class="dim">
        Владелец (#{{ repo?.owner_id }}) пишет всегда; здесь — дополнительные пользователи.
      </p>
      <table v-if="perms.length > 0">
        <thead>
          <tr>
            <th>Пользователь</th>
            <th>Выдано</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in perms" :key="p.user_id">
            <td>{{ userName(p.user_id) }} (#{{ p.user_id }})</td>
            <td class="dim">{{ formatTime(p.created_at) }}</td>
            <td>
              <button class="btn danger small" @click="revoke(p.user_id)">Отозвать</button>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim">Доп. прав нет.</p>
      <form v-if="usersError === ''" class="row" @submit.prevent="grant">
        <label class="field"
        >Пользователь
          <select v-model="grantUserID" required>
            <option v-for="u in users" :key="u.id" :value="u.id">
              {{ u.username }} (#{{ u.id }})
            </option>
          </select>
        </label>
        <button class="btn" type="submit">Выдать право</button>
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
