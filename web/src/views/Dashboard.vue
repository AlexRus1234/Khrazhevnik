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
import { t } from '../i18n'
import type { CacheStats, TaskSnapshot } from '../types'

const stats = ref<CacheStats | null>(null)
const tasks = ref<TaskSnapshot[]>([])
const error = ref('')
const refreshing = ref(false)
const resetting = ref(false)

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

// Кнопка «Обновить»: stats в 2-секундный поллинг не включены (поллинг
// молотил бы админ-API без надобности — статистика меняется редко,
// реестр задач — живой), перечитываются по требованию.
async function refreshAll(): Promise<void> {
  refreshing.value = true
  try {
    await loadStats()
    await loadTasks()
  } finally {
    refreshing.value = false
  }
}

// Кнопка «Сбросить статистику»: confirm нативным window.confirm
// (модальных компонентов в проекте нет), затем POST reset (204 без
// тела — request() разбирает пустой ответ в null) и немедленное
// перечитывание — обнулённые значения на экране без перезагрузки.
async function resetStats(): Promise<void> {
  if (!window.confirm(t('dashboard.statsResetConfirm'))) return
  resetting.value = true
  try {
    await request('POST', '/cache/stats/reset')
    await refreshAll()
  } catch (e) {
    error.value = errText(e)
  } finally {
    resetting.value = false
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
    <h1>{{ t('dashboard.title') }}</h1>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <div class="row spread">
        <h2>{{ t('dashboard.cache') }}</h2>
        <div class="row">
          <button class="btn" :disabled="refreshing || resetting" @click="void refreshAll()">
            {{ t('dashboard.refresh') }}
          </button>
          <button class="btn" :disabled="refreshing || resetting" @click="void resetStats()">
            {{ t('dashboard.statsReset') }}
          </button>
        </div>
      </div>
      <div v-if="stats" class="grid cards">
        <div class="card">
          <span class="dim">{{ t('dashboard.cachedPackages') }}</span>
          <div class="value">{{ stats.packages }}</div>
        </div>
        <div class="card">
          <span class="dim">{{ t('dashboard.hitRatio') }}</span>
          <div class="value">{{ pct(stats.hit_ratio) }}</div>
        </div>
        <div class="card">
          <span class="dim">{{ t('dashboard.hits') }}</span>
          <div class="value">{{ stats.hits }}</div>
        </div>
        <div class="card">
          <span class="dim">{{ t('dashboard.misses') }}</span>
          <div class="value">{{ stats.misses }}</div>
        </div>
        <div class="card">
          <span class="dim">{{ t('dashboard.staleServed') }}</span>
          <div class="value">{{ stats.stale_served }}</div>
        </div>
        <div class="card">
          <span class="dim">{{ t('dashboard.negativeHits') }}</span>
          <div class="value">{{ stats.negative_hits }}</div>
        </div>
        <div class="card">
          <span class="dim">{{ t('dashboard.upstreamErrors') }}</span>
          <div class="value">{{ stats.upstream_errors }}</div>
        </div>
        <div class="card">
          <span class="dim">{{ t('dashboard.bytesFromUpstream') }}</span>
          <div class="value">{{ formatBytes(stats.bytes_from_upstream) }}</div>
        </div>
        <div class="card">
          <span class="dim">{{ t('dashboard.bytesToClients') }}</span>
          <div class="value">{{ formatBytes(stats.bytes_to_clients) }}</div>
        </div>
      </div>
      <p v-else class="dim">{{ t('common.loading') }}</p>
    </div>

    <div v-if="stats" class="panel">
      <h2>{{ t('dashboard.perEco') }}</h2>
      <table v-if="stats.per_ecosystem.length > 0">
        <thead>
          <tr>
            <th>{{ t('dashboard.colEco') }}</th>
            <th>{{ t('dashboard.colPackages') }}</th>
            <th>{{ t('dashboard.hitRatio') }}</th>
            <th>{{ t('dashboard.hits') }}</th>
            <th>{{ t('dashboard.misses') }}</th>
            <th>{{ t('dashboard.colBytesUp') }}</th>
            <th>{{ t('dashboard.colBytesDown') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="eco in stats.per_ecosystem" :key="eco.ecosystem">
            <td>{{ eco.ecosystem }}</td>
            <td>{{ eco.packages }}</td>
            <td>{{ pct(eco.hit_ratio) }}</td>
            <td>{{ eco.hits }}</td>
            <td>{{ eco.misses }}</td>
            <td>{{ formatBytes(eco.bytes_from_upstream) }}</td>
            <td>{{ formatBytes(eco.bytes_to_clients) }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim">{{ t('dashboard.perEcoEmpty') }}</p>
    </div>

    <div class="panel">
      <div class="row spread">
        <h2>{{ t('dashboard.tasks') }}</h2>
        <a class="btn" :href="metricsURL" target="_blank" rel="noopener">/metrics</a>
      </div>
      <p class="dim">{{ t('dashboard.prometheusHint', { url: metricsURL }) }}</p>
      <table v-if="tasks.length > 0">
        <thead>
          <tr>
            <th>{{ t('dashboard.colTask') }}</th>
            <th>{{ t('dashboard.colTarget') }}</th>
            <th>{{ t('dashboard.colState') }}</th>
            <th>{{ t('dashboard.colProgress') }}</th>
            <th>{{ t('dashboard.colSpeed') }}</th>
            <th>{{ t('dashboard.colStarted') }}</th>
            <th>{{ t('dashboard.colError') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="task in tasks" :key="task.id">
            <td>{{ task.kind }}</td>
            <td>{{ task.label }}</td>
            <td>
              <span class="badge" :class="task.state">{{ task.state }}</span>
            </td>
            <td>
              <template v-if="task.total > 0"
                >{{ task.processed }}/{{ task.total }} ({{ Math.round(task.percent) }} %)</template
              >
              <template v-else>{{ task.phase }} {{ task.current }}</template>
            </td>
            <td>{{ formatSpeed(task.speed_bps) }}</td>
            <td>{{ formatTime(task.started_at) }}</td>
            <td class="error">{{ task.error ?? '' }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim">{{ t('dashboard.noTasks') }}</p>
    </div>
  </section>
</template>
