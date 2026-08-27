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
import { computed, onMounted, ref, watch } from 'vue'
import { request } from '../api'
import { errText } from '../errors'
import { t } from '../i18n'
import type { Repo } from '../types'

// Ключи раздаются с публичного порта (:29202), а SPA живёт на админском
// (:30202) — origin вводится пользователем (дефолт — тот же хост с
// 29202) и запоминается в localStorage.
const ORIGIN_KEY = 'khrazhevnik_public_origin'

const repos = ref<Repo[]>([])
const selected = ref<number | null>(null)
const origin = ref(localStorage.getItem(ORIGIN_KEY) ?? defaultOrigin())
const keyText = ref('')
const nixKeyText = ref('')
const error = ref('')
const keyError = ref('')
const loading = ref(false)

function defaultOrigin(): string {
  // vite dev (5173) ходит через proxy /repo → относительный origin.
  if (window.location.port === '5173') return window.location.origin
  return `${window.location.protocol}//${window.location.hostname}:29202`
}

const repo = computed(() => repos.value.find((r) => r.id === selected.value) ?? null)

const keyURL = computed(() =>
  repo.value ? `${origin.value}/repo/${repo.value.name}/key.asc` : '',
)

const nixKeyURL = computed(() =>
  repo.value ? `${origin.value}/repo/${repo.value.name}/nix-key.asc` : '',
)

const repoBaseURL = computed(() =>
  repo.value ? `${origin.value}/repo/${repo.value.name}` : '',
)

// Готовая строка sources.list (apt) — то, ради чего экран существует.
const aptSnippet = computed(() =>
  repo.value && repo.value.ecosystem === 'apt'
    ? `deb [signed-by=/usr/share/keyrings/${repo.value.name}.asc] ${repoBaseURL.value} stable main`
    : '',
)

async function loadRepos(): Promise<void> {
  try {
    repos.value = await request<Repo[]>('GET', '/repos')
    if (repos.value.length > 0 && selected.value === null) {
      selected.value = repos.value[0].id
    }
  } catch (e) {
    error.value = errText(e)
  }
}

async function loadKey(): Promise<void> {
  if (repo.value === null) return
  loading.value = true
  keyError.value = ''
  keyText.value = ''
  nixKeyText.value = ''
  // CORS на key-эндпоинтах разрешён (repo_public.go); недоступный
  // ключ (подпись не инициализирована) — 503 текстом.
  try {
    const resp = await fetch(keyURL.value)
    if (resp.ok) {
      keyText.value = await resp.text()
    } else {
      keyError.value = `HTTP ${resp.status}: ${await resp.text()}`
    }
  } catch {
    keyError.value = t('keys.portUnavailable')
  }
  if (repo.value.ecosystem === 'nix') {
    try {
      const resp = await fetch(nixKeyURL.value)
      if (resp.ok) nixKeyText.value = await resp.text()
    } catch {
      // narinfo-ключ опционален — ошибка не перекрывает основной
    }
  }
  loading.value = false
}

function saveOrigin(): void {
  origin.value = origin.value.replace(/\/+$/, '')
  localStorage.setItem(ORIGIN_KEY, origin.value)
}

onMounted(loadRepos)
watch([selected, origin], () => {
  void loadKey()
})
</script>

<template>
  <section>
    <h1>{{ t('keys.title') }}</h1>
    <p v-if="error" class="error">{{ error }}</p>

    <div class="panel">
      <div class="row">
        <label class="field"
          >{{ t('keys.repo') }}
          <select v-model.number="selected">
            <option v-for="r in repos" :key="r.id" :value="r.id">
              {{ r.name }} ({{ r.ecosystem }})
            </option>
          </select>
        </label>
        <label class="field grow"
          >{{ t('keys.publicOrigin') }}
          <input v-model="origin" @change="saveOrigin" />
        </label>
      </div>
      <p class="dim">{{ t('keys.hint') }}</p>
    </div>

    <template v-if="repo">
      <div class="panel">
        <div class="row spread">
          <h2>{{ t('keys.publicKey') }}</h2>
          <a class="btn" :href="keyURL" :download="`${repo.name}.asc`" target="_blank" rel="noopener">
            {{ t('keys.downloadFile', { name: `${repo.name}.asc` }) }}
          </a>
        </div>
        <p class="dim mono">{{ keyURL }}</p>
        <p v-if="loading" class="dim">{{ t('common.loading') }}</p>
        <p v-else-if="keyError" class="error">{{ keyError }}</p>
        <pre v-else-if="keyText" class="snippet mono">{{ keyText }}</pre>

        <template v-if="repo.ecosystem === 'apt'">
          <h2>sources.list</h2>
          <pre class="snippet mono">{{ aptSnippet }}</pre>
          <p class="dim">{{ t('keys.sourcesHint') }}</p>
        </template>
      </div>

      <div v-if="repo.ecosystem === 'nix'" class="panel">
        <div class="row spread">
          <h2>{{ t('keys.nixKey') }}</h2>
          <a class="btn" :href="nixKeyURL" :download="`${repo.name}-nix.asc`" target="_blank" rel="noopener">
            {{ t('keys.download') }}
          </a>
        </div>
        <p class="dim mono">{{ nixKeyURL }}</p>
        <pre v-if="nixKeyText" class="snippet mono">{{ nixKeyText }}</pre>
        <p v-else class="dim">{{ t('keys.nixUnavailable') }}</p>
      </div>
    </template>
  </section>
</template>
