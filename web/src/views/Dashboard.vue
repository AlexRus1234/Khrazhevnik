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
import { formatBytes, formatSpeed, formatTime } from '../format'
import type { CacheStats, TaskSnapshot } from '../types'

const stats = ref<CacheStats | null>(null)
const tasks = ref<TaskSnapshot[]>([])
const error = ref('')

const POLL_MS = 2000
let timer: number | undefined

// /metrics — тот же админ-порт, что и SPA; относительная ссылка от
// корня origin.
const metricsURL = '/metrics'

async function loadStats(): Promise<void> {
  try {
    stats.value = await request<CacheStats>('GET', '/cache/stats')
  } catch (e) {
    error.value = errText(e)
  }
}

async function loadTasks(): Promise<void> {
  try {
    tasks.value = await request<TaskSnapshot[]>('GET', '/tasks')
    error.value = ''
  } catch (e) {
    error.value = errText(e)
  }
}

// Поллинг 2с: реестр задач живой (in-memory), завершённые пропадают из
// списка при рестарте — дашборд честно показывает «что бегает сейчас».
onMounted(() => {
  void loadStats()
  void loadTasks()
  timer = window.setInterval(() => {
    void loadTasks()
  }, POLL_MS)
})

onUnmounted(() => {
  if (timer !== undefined) window.clearInterval(timer)
})

function pct(ratio: number): string {
  return `${Math.round(ratio * 100)} %`
}
</script>

<template>
  <section>
    <h1>Дашборд</h1>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <h2>Кеш</h2>
      <div v-if="stats" class="grid cards">
        <div class="card">
          <span class="dim">Hit ratio</span>
          <div class="value">{{ pct(stats.hit_ratio) }}</div>
        </div>
        <div class="card">
          <span class="dim">Попадания</span>
          <div class="value">{{ stats.hits }}</div>
        </div>
        <div class="card">
          <span class="dim">Промахи</span>
          <div class="value">{{ stats.misses }}</div>
        </div>
        <div class="card">
          <span class="dim">Stale отдач</span>
          <div class="value">{{ stats.stale_served }}</div>
        </div>
        <div class="card">
          <span class="dim">Отриц. попаданий</span>
          <div class="value">{{ stats.negative_hits }}</div>
        </div>
        <div class="card">
          <span class="dim">Ошибок upstream</span>
          <div class="value">{{ stats.upstream_errors }}</div>
        </div>
        <div class="card">
          <span class="dim">Скачано с upstream</span>
          <div class="value">{{ formatBytes(stats.bytes_from_upstream) }}</div>
        </div>
        <div class="card">
          <span class="dim">Отдано клиентам</span>
          <div class="value">{{ formatBytes(stats.bytes_to_clients) }}</div>
        </div>
      </div>
      <p v-else class="dim">Загрузка…</p>
    </div>

    <div class="panel">
      <div class="row spread">
        <h2>Фоновые задачи</h2>
        <a class="btn" :href="metricsURL" target="_blank" rel="noopener">/metrics</a>
      </div>
      <p class="dim">
        Prometheus: <span class="mono">{{ metricsURL }}</span> — доступ по токену сессии/админ.
      </p>
      <table v-if="tasks.length > 0">
        <thead>
          <tr>
            <th>Задача</th>
            <th>Цель</th>
            <th>Состояние</th>
            <th>Прогресс</th>
            <th>Скорость</th>
            <th>Начало</th>
            <th>Ошибка</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="t in tasks" :key="t.id">
            <td>{{ t.kind }}</td>
            <td>{{ t.label }}</td>
            <td>
              <span class="badge" :class="t.state">{{ t.state }}</span>
            </td>
            <td>
              <template v-if="t.total > 0"
                >{{ t.processed }}/{{ t.total }} ({{ Math.round(t.percent) }} %)</template
              >
              <template v-else>{{ t.phase }} {{ t.current }}</template>
            </td>
            <td>{{ formatSpeed(t.speed_bps) }}</td>
            <td>{{ formatTime(t.started_at) }}</td>
            <td class="error">{{ t.error ?? '' }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim">Активных задач нет.</p>
    </div>
  </section>
</template>
