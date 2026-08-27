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
import { request } from '../api'
import { errText } from '../errors'
import { formatDuration, formatSpeed, formatTime, parseDuration } from '../format'
import { t } from '../i18n'
import type { Remote, TaskSnapshot } from '../types'

const ECOSYSTEMS = ['apt', 'rpm-md', 'pacman', 'apk', 'nix']

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
const formError = ref('')
const busy = ref(false)

async function load(): Promise<void> {
  try {
    remotes.value = await request<Remote[]>('GET', '/remotes')
    error.value = ''
    loaded.value = true
  } catch (e) {
    error.value = errText(e)
  }
}

onMounted(load)

function openCreate(): void {
  editingID.value = null
  fName.value = ''
  fEcosystem.value = 'apt'
  fBaseURL.value = ''
  fMode.value = 'proxy'
  fEnabled.value = true
  fInterval.value = ''
  fInclude.value = ''
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
      <button class="btn primary" @click="openCreate">{{ t('common.add') }}</button>
    </div>
    <p v-if="error" class="error">{{ error }}</p>

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
