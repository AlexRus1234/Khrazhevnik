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
import { formatTime } from '../format'
import type { AuditEntry } from '../types'

// Keyset-пагинация: after_id — последний увиденный ID (SPECIFICATION
// §REST). offset-страниц нет — записи только добавляются в конец,
// классическая пагинация съезжала бы.
const LIMIT = 100

const entries = ref<AuditEntry[]>([])
const error = ref('')
const loading = ref(false)
const done = ref(false)

async function load(): Promise<void> {
  if (loading.value || done.value) return
  loading.value = true
  const last = entries.value.length > 0 ? entries.value[entries.value.length - 1].id : 0
  try {
    const page = await request<AuditEntry[]>('GET', '/audit', {
      query: { after_id: last, limit: LIMIT },
    })
    entries.value = entries.value.concat(page)
    if (page.length < LIMIT) done.value = true
    error.value = ''
  } catch (e) {
    error.value = errText(e)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <section>
    <div class="row spread">
      <h1>Аудит</h1>
      <button class="btn" :disabled="loading || done" @click="load">
        {{ done ? 'Всё загружено' : loading ? 'Загрузка…' : 'Ещё' }}
      </button>
    </div>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <table v-if="entries.length > 0">
        <thead>
          <tr>
            <th>ID</th>
            <th>Время</th>
            <th>Актор</th>
            <th>Действие</th>
            <th>Объект</th>
            <th>Результат</th>
            <th>Детали</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in entries" :key="e.id">
            <td class="dim">{{ e.id }}</td>
            <td class="dim">{{ formatTime(e.at) }}</td>
            <td>{{ e.actor }}</td>
            <td class="mono">{{ e.action }}</td>
            <td class="mono">{{ e.object }}</td>
            <td>
              <span class="badge" :class="e.result === 'ok' ? 'succeeded' : 'failed'">{{
                e.result
              }}</span>
            </td>
            <td class="dim detail">{{ e.detail }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else-if="!loading" class="dim">Записей нет.</p>
      <p v-else class="dim">Загрузка…</p>
    </div>
  </section>
</template>

<style scoped>
.detail {
  max-width: 22rem;
  overflow-wrap: anywhere;
}
</style>
