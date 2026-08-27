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
import { RouterLink } from 'vue-router'
import { request } from '../api'
import { errText } from '../errors'
import { formatBytes, formatTime } from '../format'
import type { Repo, User } from '../types'

// Генераторы метаданных есть у apt и nix (сессии 14/15/16); остальные
// экосистемы можно создать, но reindex ответит unsupported.
const ECOSYSTEMS = ['apt', 'nix']

const repos = ref<Repo[]>([])
const users = ref<User[]>([])
const error = ref('')
const usersError = ref('')
const loaded = ref(false)

const showForm = ref(false)
const editingID = ref<number | null>(null)
const fName = ref('')
const fEcosystem = ref('apt')
const fOwner = ref<number | null>(null)
const fQuotaBytes = ref('')
const fQuotaFiles = ref('')
const formError = ref('')
const busy = ref(false)

async function load(): Promise<void> {
  try {
    repos.value = await request<Repo[]>('GET', '/repos')
    error.value = ''
    loaded.value = true
  } catch (e) {
    error.value = errText(e)
  }
}

// Владельцы нужны для create/edit (owner_id — существующий user);
// не-админ получит 403 — форма создания скрывается.
async function loadUsers(): Promise<void> {
  try {
    users.value = await request<User[]>('GET', '/users')
  } catch (e) {
    usersError.value = errText(e)
  }
}

onMounted(() => {
  void load()
  void loadUsers()
})

function openCreate(): void {
  editingID.value = null
  fName.value = ''
  fEcosystem.value = 'apt'
  fOwner.value = users.value.length > 0 ? users.value[0].id : null
  fQuotaBytes.value = ''
  fQuotaFiles.value = ''
  formError.value = ''
  showForm.value = true
}

function openEdit(r: Repo): void {
  editingID.value = r.id
  fName.value = r.name
  fEcosystem.value = r.ecosystem
  fOwner.value = r.owner_id
  fQuotaBytes.value = r.quota.max_bytes > 0 ? String(r.quota.max_bytes) : ''
  fQuotaFiles.value = r.quota.max_objects > 0 ? String(r.quota.max_objects) : ''
  formError.value = ''
  showForm.value = true
}

async function submit(): Promise<void> {
  if (busy.value || fOwner.value === null) return
  // Квоты — байты/файлы числом (0 = без лимита); ГиБ-суффиксы не
  // парсим: это редкая операция, а явные байты не дают двусмысленностей.
  const body = {
    name: fName.value,
    ecosystem: fEcosystem.value,
    owner_id: fOwner.value,
    quota: {
      max_bytes: Number(fQuotaBytes.value || '0'),
      max_objects: Number(fQuotaFiles.value || '0'),
    },
  }
  if (body.quota.max_bytes < 0 || body.quota.max_objects < 0 || Number.isNaN(body.quota.max_bytes) || Number.isNaN(body.quota.max_objects)) {
    formError.value = 'квоты — неотрицательные числа (байты и файлы; 0 = без лимита)'
    return
  }
  busy.value = true
  formError.value = ''
  try {
    if (editingID.value === null) {
      await request('POST', '/repos', { body })
    } else {
      await request('PATCH', `/repos/${editingID.value}`, { body })
    }
    showForm.value = false
    await load()
  } catch (e) {
    formError.value = errText(e)
  } finally {
    busy.value = false
  }
}

async function remove(r: Repo): Promise<void> {
  if (!window.confirm(`Удалить репозиторий «${r.name}»? Права удалятся каскадом.`)) return
  try {
    await request('DELETE', `/repos/${r.id}`)
    await load()
  } catch (e) {
    error.value = errText(e)
  }
}

function ownerName(id: number): string {
  const u = users.value.find((x) => x.id === id)
  return u ? `${u.username} (#${id})` : `#${id}`
}
</script>

<template>
  <section>
    <div class="row spread">
      <h1>Личные репозитории</h1>
      <button
        v-if="usersError === ''"
        class="btn primary"
        @click="openCreate"
      >
        Добавить
      </button>
    </div>
    <p v-if="error" class="error">{{ error }}</p>

    <div v-if="showForm" class="panel">
      <h2>{{ editingID === null ? 'Новый репозиторий' : `Репозиторий: ${fName}` }}</h2>
      <form class="grid" @submit.prevent="submit">
        <div class="row">
          <label class="field"
            >Имя (slug)
            <input v-model="fName" required placeholder="myrepo" />
          </label>
          <label class="field"
            >Экосистема
            <select v-model="fEcosystem">
              <option v-for="e in ECOSYSTEMS" :key="e" :value="e">{{ e }}</option>
            </select>
          </label>
          <label class="field"
            >Владелец
            <select v-model="fOwner" required>
              <option v-for="u in users" :key="u.id" :value="u.id">
                {{ u.username }} (#{{ u.id }})
              </option>
            </select>
          </label>
        </div>
        <div class="row">
          <label class="field"
            >Квота, байт (0 — без лимита)
            <input v-model="fQuotaBytes" placeholder="5368709120" />
          </label>
          <label class="field"
            >Квота, файлов (0 — без лимита)
            <input v-model="fQuotaFiles" placeholder="10000" />
          </label>
        </div>
        <p v-if="formError" class="error">{{ formError }}</p>
        <div class="row">
          <button class="btn primary" type="submit" :disabled="busy">
            {{ editingID === null ? 'Создать' : 'Сохранить' }}
          </button>
          <button class="btn" type="button" @click="showForm = false">Отмена</button>
        </div>
      </form>
    </div>

    <div class="panel">
      <table v-if="repos.length > 0">
        <thead>
          <tr>
            <th>Имя</th>
            <th>Экосистема</th>
            <th>Владелец</th>
            <th>Квота</th>
            <th>Создан</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in repos" :key="r.id">
            <td>
              <RouterLink :to="`/repos/${r.id}`" class="mono">{{ r.name }}</RouterLink>
            </td>
            <td>{{ r.ecosystem }}</td>
            <td>{{ ownerName(r.owner_id) }}</td>
            <td>
              {{ r.quota.max_bytes > 0 ? formatBytes(r.quota.max_bytes) : '∞' }} /
              {{ r.quota.max_objects > 0 ? r.quota.max_objects : '∞' }}
            </td>
            <td class="dim">{{ formatTime(r.created_at) }}</td>
            <td>
              <div class="row actions">
                <RouterLink class="btn" :to="`/repos/${r.id}`">Открыть</RouterLink>
                <button class="btn" @click="openEdit(r)">Править</button>
                <button class="btn danger" @click="remove(r)">Удалить</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else-if="loaded" class="dim">Репозиториев нет.</p>
      <p v-else class="dim">Загрузка…</p>
    </div>
  </section>
</template>

<style scoped>
.actions .btn {
  padding: 0.2rem 0.6rem;
}
</style>
