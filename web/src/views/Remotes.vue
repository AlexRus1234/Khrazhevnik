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
import { onMounted, onUnmounted, ref } from 'vue'
import { exportRemotes, importRemotes, request } from '../api'
import { errText } from '../errors'
import { formatDuration, formatSpeed, formatTime, parseDuration } from '../format'
import { t } from '../i18n'
import type { ImportReport, Remote, TaskSnapshot } from '../types'

const ECOSYSTEMS = ['apt', 'rpm-md', 'pacman', 'apk', 'nix', 'xbps']

const remotes = ref<Remote[]>([])
const error = ref('')
const loaded = ref(false)

// Форма create/edit. editingID === null → создание; иначе PATCH
// (full-replace: шлём все поля, включая неизменённые).
const editingID = ref<number | null>(null)
const showForm = ref(false)
const fName = ref('')
const fEcosystem = ref('apt')
const fBaseURL = ref('')
const fMode = ref<'proxy' | 'mirror'>('proxy')
const fEnabled = ref(true)
const fInterval = ref('')
const fInclude = ref('')
const fProxyMode = ref<'inherit' | 'direct' | 'custom'>('inherit')
const fProxyURL = ref('')
const formError = ref('')
const busy = ref(false)

// Глобальный прокси upstream (GET/PUT /settings/upstream-proxy):
// пусто — env-фолбэк, "direct" или URL.
const gProxy = ref('')
const gBusy = ref(false)
const gError = ref('')
const gSaved = ref(false)

async function load(): Promise<void> {
  try {
    remotes.value = await request<Remote[]>('GET', '/remotes')
    error.value = ''
    loaded.value = true
  } catch (e) {
    error.value = errText(e)
  }
}

async function loadGlobalProxy(): Promise<void> {
  try {
    const out = await request<{ value: string }>('GET', '/settings/upstream-proxy')
    gProxy.value = out.value
  } catch (e) {
    gError.value = errText(e)
  }
}

async function saveGlobalProxy(): Promise<void> {
  if (gBusy.value) return
  gBusy.value = true
  gError.value = ''
  gSaved.value = false
  try {
    const out = await request<{ value: string }>('PUT', '/settings/upstream-proxy', {
      body: { value: gProxy.value.trim() },
    })
    gProxy.value = out.value
    gSaved.value = true
  } catch (e) {
    gError.value = errText(e)
  } finally {
    gBusy.value = false
  }
}

onMounted(() => {
  void load()
  void loadGlobalProxy()
})

function openCreate(): void {
  editingID.value = null
  fName.value = ''
  fEcosystem.value = 'apt'
  fBaseURL.value = ''
  fMode.value = 'proxy'
  fEnabled.value = true
  fInterval.value = ''
  fInclude.value = ''
  fProxyMode.value = 'inherit'
  fProxyURL.value = ''
  formError.value = ''
  showForm.value = true
}

function openEdit(r: Remote): void {
  editingID.value = r.id
  fName.value = r.name
  fEcosystem.value = r.ecosystem
  fBaseURL.value = r.base_url
  fMode.value = r.mode
  fEnabled.value = r.enabled
  // нс → человекочитаемо («1h», «30m»): парсинг обратно на submit.
  fInterval.value = r.sync_interval > 0 ? formatDuration(r.sync_interval) : ''
  fInclude.value = r.include.join('\n')
  if (r.proxy_url === 'direct') {
    fProxyMode.value = 'direct'
    fProxyURL.value = ''
  } else if (r.proxy_url === '') {
    fProxyMode.value = 'inherit'
    fProxyURL.value = ''
  } else {
    fProxyMode.value = 'custom'
    fProxyURL.value = r.proxy_url
  }
  formError.value = ''
  showForm.value = true
}

async function submit(): Promise<void> {
  if (busy.value) return
  const intervalNS = parseDuration(fInterval.value)
  if (intervalNS === null) {
    formError.value = t('remotes.intervalError')
    return
  }
  const proxyURL =
    fProxyMode.value === 'custom'
      ? fProxyURL.value.trim()
      : fProxyMode.value === 'direct'
        ? 'direct'
        : ''
  if (fProxyMode.value === 'custom' && proxyURL === '') {
    formError.value = t('remotes.proxyInvalid')
    return
  }
  const body = {
    name: fName.value,
    ecosystem: fEcosystem.value,
    base_url: fBaseURL.value,
    mode: fMode.value,
    enabled: fEnabled.value,
    sync_interval: intervalNS,
    include: fInclude.value
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s !== ''),
    proxy_url: proxyURL,
  }
  busy.value = true
  formError.value = ''
  try {
    if (editingID.value === null) {
      await request('POST', '/remotes', { body })
    } else {
      await request('PATCH', `/remotes/${editingID.value}`, { body })
    }
    showForm.value = false
    await load()
  } catch (e) {
    formError.value = errText(e)
  } finally {
    busy.value = false
  }
}

async function remove(r: Remote): Promise<void> {
  if (!window.confirm(t('remotes.deleteConfirm', { name: r.name }))) return
  try {
    await request('DELETE', `/remotes/${r.id}`)
    await load()
  } catch (e) {
    error.value = errText(e)
  }
}

const exporting = ref(false)

async function exportNow(): Promise<void> {
  if (exporting.value) return
  exporting.value = true
  error.value = ''
  try {
    await exportRemotes()
  } catch (e) {
    error.value = errText(e)
  } finally {
    exporting.value = false
  }
}

// Импорт источников: панель принимает вставленный текст или .txt-файл;
// после отправки показывает построчный отчёт (created/skipped/errors).
const showImport = ref(false)
const importText = ref('')
const importError = ref('')
const importBusy = ref(false)
const importReport = ref<ImportReport | null>(null)

function openImport(): void {
  importText.value = ''
  importError.value = ''
  importReport.value = null
  showImport.value = true
}

function closeImport(): void {
  showImport.value = false
  importText.value = ''
  importError.value = ''
  importReport.value = null
}

// Файл читаем целиком в textarea; дальнейшее ручное редактирование не
// блокируем — пользователь волен поправить текст перед импортом.
function onImportFile(e: Event): void {
  const file = (e.target as HTMLInputElement).files?.[0]
  if (!file) return
  const reader = new FileReader()
  reader.onload = () => {
    importText.value = typeof reader.result === 'string' ? reader.result : ''
  }
  reader.readAsText(file)
}

async function submitImport(): Promise<void> {
  if (importBusy.value) return
  if (importText.value.trim() === '') {
    importError.value = t('remotes.importEmpty')
    return
  }
  importBusy.value = true
  importError.value = ''
  importReport.value = null
  try {
    importReport.value = await importRemotes(importText.value)
    await load()
  } catch (e) {
    importError.value = errText(e)
  } finally {
    importBusy.value = false
  }
}

// sync + поллинг задачи: 202 → task_id, 409 — уже бежит (подхватываем
// прогресс из списка задач), 429 — лимит воркеров.
const syncing = ref<Record<number, boolean>>({})
const syncProgress = ref<Record<number, TaskSnapshot>>({})
const syncError = ref<Record<number, string>>({})
const trackedTasks = new Map<number, string>()
let pollTimer: number | undefined

async function pollTracked(): Promise<void> {
  for (const [remoteID, taskID] of trackedTasks) {
    try {
      const t = await request<TaskSnapshot>('GET', `/tasks/${taskID}`)
      syncProgress.value[remoteID] = t
      if (t.state !== 'running') {
        trackedTasks.delete(remoteID)
        syncing.value[remoteID] = false
        if (trackedTasks.size === 0 && pollTimer !== undefined) {
          window.clearInterval(pollTimer)
          pollTimer = undefined
        }
        await load()
      }
    } catch {
      // задача исчезла из in-memory реестра (рестарт сервера) — тихо
      // прекращаем поллинг.
      trackedTasks.delete(remoteID)
      syncing.value[remoteID] = false
    }
  }
}

function track(remoteID: number, taskID: string): void {
  trackedTasks.set(remoteID, taskID)
  syncing.value[remoteID] = true
  delete syncError.value[remoteID]
  if (pollTimer === undefined) {
    pollTimer = window.setInterval(() => {
      void pollTracked()
    }, 1000)
  }
  void pollTracked()
}

async function syncNow(r: Remote): Promise<void> {
  try {
    delete syncError.value[r.id]
    const out = await request<{ task_id: string }>('POST', `/remotes/${r.id}/sync`)
    track(r.id, out.task_id)
  } catch (e) {
    syncError.value[r.id] = errText(e)
  }
}

onUnmounted(() => {
  if (pollTimer !== undefined) window.clearInterval(pollTimer)
})
</script>

<template>
  <section>
    <div class="row spread">
      <h1>{{ t('remotes.title') }}</h1>
      <div class="row">
        <button class="btn" @click="openImport">{{ t('remotes.import') }}</button>
        <button class="btn" :disabled="exporting" @click="exportNow">
          {{ t('remotes.export') }}
        </button>
        <button class="btn primary" @click="openCreate">{{ t('common.add') }}</button>
      </div>
    </div>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <h2>{{ t('remotes.globalProxy') }}</h2>
      <div class="row">
        <label class="field"
          >{{ t('remotes.proxyURL') }}
          <input v-model="gProxy" :placeholder="t('remotes.globalProxyHint')" />
        </label>
        <button class="btn primary" type="button" :disabled="gBusy" @click="saveGlobalProxy">
          {{ t('common.save') }}
        </button>
      </div>
      <p class="dim">{{ t('remotes.globalProxyHint') }}</p>
      <p v-if="gError" class="error">{{ gError }}</p>
      <p v-if="gSaved" class="ok">{{ t('remotes.globalSaved') }}</p>
    </div>

    <div v-if="showImport" class="panel">
      <h2>{{ t('remotes.import') }}</h2>
      <label class="field"
        >{{ t('remotes.import') }}
        <textarea v-model="importText" rows="8" :placeholder="t('remotes.importHint')"></textarea>
      </label>
      <div class="row">
        <input type="file" accept=".txt,text/plain" @change="onImportFile" />
      </div>
      <p v-if="importError" class="error">{{ importError }}</p>
      <div class="row">
        <button class="btn primary" type="button" :disabled="importBusy" @click="submitImport">
          {{ t('remotes.importRun') }}
        </button>
        <button class="btn" type="button" @click="closeImport">{{ t('common.close') }}</button>
      </div>
      <div v-if="importReport">
        <p>
          <strong>{{ t('remotes.reportCreated') }}:</strong>
          {{ importReport.created.join(', ') || '—' }}
        </p>
        <p>
          <strong>{{ t('remotes.reportSkipped') }}:</strong>
          {{
            importReport.skipped
              .map((s) => `${s.name} (${t('remotes.reportLine')} ${s.line})`)
              .join(', ') || '—'
          }}
        </p>
        <p>
          <strong>{{ t('remotes.reportErrors') }}:</strong>
          {{
            importReport.errors
              .map((e) => `${t('remotes.reportLine')} ${e.line}: ${e.code}`)
              .join(', ') || '—'
          }}
        </p>
      </div>
    </div>

    <div v-if="showForm" class="panel">
      <h2>{{ editingID === null ? t('remotes.newRemote') : t('remotes.editRemote', { name: fName }) }}</h2>
      <form class="grid" @submit.prevent="submit">
        <div class="row">
          <label class="field"
            >{{ t('remotes.nameSlug') }}
            <input v-model="fName" required placeholder="debian" />
          </label>
          <label class="field"
            >{{ t('common.ecosystem') }}
            <select v-model="fEcosystem">
              <option v-for="e in ECOSYSTEMS" :key="e" :value="e">{{ e }}</option>
            </select>
          </label>
          <label class="field"
            >{{ t('remotes.mode') }}
            <select v-model="fMode">
              <option value="proxy">{{ t('remotes.modeProxy') }}</option>
              <option value="mirror">{{ t('remotes.modeMirror') }}</option>
            </select>
          </label>
        </div>
        <label class="field"
          >Base URL
          <input v-model="fBaseURL" required placeholder="https://deb.debian.org/debian" />
        </label>
        <div class="row">
          <label class="field"
            >{{ t('remotes.proxyMode') }}
            <select v-model="fProxyMode">
              <option value="inherit">{{ t('remotes.proxyInherit') }}</option>
              <option value="direct">{{ t('remotes.proxyDirect') }}</option>
              <option value="custom">{{ t('remotes.proxyCustom') }}</option>
            </select>
          </label>
          <label v-if="fProxyMode === 'custom'" class="field"
            >{{ t('remotes.proxyURL') }}
            <input v-model="fProxyURL" placeholder="socks5://127.0.0.1:1080" />
          </label>
        </div>
        <div class="row">
          <label class="field"
            >{{ t('remotes.syncInterval') }}
            <input v-model="fInterval" :placeholder="t('remotes.syncIntervalPlaceholder')" />
          </label>
          <label class="field check"
            >{{ t('remotes.enabled') }}
            <input v-model="fEnabled" type="checkbox" />
          </label>
        </div>
        <label class="field"
          >{{ t('remotes.include') }}
          <textarea v-model="fInclude" rows="3" placeholder="stable&#10;stable/main"></textarea>
        </label>
        <p v-if="formError" class="error">{{ formError }}</p>
        <div class="row">
          <button class="btn primary" type="submit" :disabled="busy">
            {{ editingID === null ? t('common.create') : t('common.save') }}
          </button>
          <button class="btn" type="button" @click="showForm = false">{{ t('common.cancel') }}</button>
        </div>
      </form>
    </div>

    <div class="panel">
      <table v-if="remotes.length > 0">
        <thead>
          <tr>
            <th>{{ t('common.name') }}</th>
            <th>{{ t('common.ecosystem') }}</th>
            <th>Base URL</th>
            <th>{{ t('remotes.mode') }}</th>
            <th>{{ t('remotes.colProxy') }}</th>
            <th>{{ t('remotes.colOn') }}</th>
            <th>{{ t('remotes.colSync') }}</th>
            <th>Include</th>
            <th>{{ t('common.created') }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in remotes" :key="r.id">
            <td>{{ r.name }}</td>
            <td>{{ r.ecosystem }}</td>
            <td class="mono url">{{ r.base_url }}</td>
            <td>{{ r.mode }}</td>
            <td>
              <template v-if="r.proxy_url === ''">{{ t('remotes.proxyInherit') }}</template>
              <template v-else-if="r.proxy_url === 'direct'">{{ t('remotes.proxyDirect') }}</template>
              <span v-else class="mono url">{{ r.proxy_url }}</span>
            </td>
            <td>{{ r.enabled ? t('common.yes') : t('common.no') }}</td>
            <td>
              <template v-if="syncing[r.id] && syncProgress[r.id]">
                <span class="badge running">{{ syncProgress[r.id].phase }}</span>
                {{ Math.round(syncProgress[r.id].percent) }} %
                {{ formatSpeed(syncProgress[r.id].speed_bps) }}
              </template>
              <template v-else>{{ formatDuration(r.sync_interval) }}</template>
            </td>
            <td class="dim">{{ r.include.join(', ') || '—' }}</td>
            <td class="dim">{{ formatTime(r.created_at) }}</td>
            <td>
              <div class="row actions">
                <button
                  v-if="r.mode === 'mirror'"
                  class="btn"
                  :disabled="syncing[r.id]"
                  @click="syncNow(r)"
                >
                  {{ syncing[r.id] ? t('remotes.syncing') : 'Sync' }}
                </button>
                <button class="btn" @click="openEdit(r)">{{ t('common.edit') }}</button>
                <button class="btn danger" @click="remove(r)">{{ t('common.delete') }}</button>
              </div>
              <p v-if="syncError[r.id]" class="error">{{ syncError[r.id] }}</p>
              <p
                v-if="syncProgress[r.id] && !syncing[r.id] && syncProgress[r.id].state === 'failed'"
                class="error"
              >
                {{ syncProgress[r.id].error }}
              </p>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else-if="loaded" class="dim">{{ t('remotes.empty') }}</p>
      <p v-else class="dim">{{ t('common.loading') }}</p>
    </div>
  </section>
</template>

<style scoped>
.url {
  max-width: 18rem;
  overflow-wrap: anywhere;
}

.actions .btn {
  padding: 0.2rem 0.6rem;
}

.check {
  flex-direction: row;
  align-items: center;
  gap: 0.4rem;
}
</style>
