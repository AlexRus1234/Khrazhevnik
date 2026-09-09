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
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { login, setToken, setup } from '../api'
import { errText } from '../errors'
import LangSwitch from '../components/LangSwitch.vue'
import { t } from '../i18n'
import { markLoggedIn } from '../stores/auth'
import { buildVersion } from '../stores/version'

const router = useRouter()
const route = useRoute()

// Статуса /setup нет в API (GET не заводили): экран предлагает вход и
// первичную настройку переключателем. 403 setup_already_done честно
// показывается текстом — пользователь переключается на вход.
const mode = ref<'login' | 'setup'>('login')
const username = ref('')
const password = ref('')
const password2 = ref('')
const setupToken = ref('')
const busy = ref(false)
const error = ref('')

async function submit(): Promise<void> {
  if (busy.value) return
  if (mode.value === 'setup' && password.value !== password2.value) {
    error.value = t('login.passwordMismatch')
    return
  }
  busy.value = true
  error.value = ''
  try {
    if (mode.value === 'login') {
      setToken(await login(username.value, password.value))
    } else {
      await setup(username.value, password.value, setupToken.value)
      setToken(await login(username.value, password.value))
    }
    markLoggedIn()
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/dashboard'
    void router.push(redirect)
  } catch (e) {
    error.value = errText(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="panel login-panel">
    <div class="row spread">
      <h1>Хражевник</h1>
      <LangSwitch />
    </div>
    <p class="dim">{{ t('login.tagline') }}</p>

    <div class="row tabswitch">
      <button
        class="btn ghost"
        :class="{ on: mode === 'login' }"
        type="button"
        @click="mode = 'login'"
      >
        {{ t('login.tabLogin') }}
      </button>
      <button
        class="btn ghost"
        :class="{ on: mode === 'setup' }"
        type="button"
        @click="mode = 'setup'"
      >
        {{ t('login.tabSetup') }}
      </button>
    </div>

    <form class="grid" @submit.prevent="submit">
      <label class="field"
        >{{ t('login.username') }}
        <input v-model="username" autocomplete="username" required />
      </label>
      <label class="field"
        >{{ t('login.password') }}
        <input
          v-model="password"
          type="password"
          :autocomplete="mode === 'login' ? 'current-password' : 'new-password'"
          required
        />
      </label>
      <label v-if="mode === 'setup'" class="field"
        >{{ t('login.password2') }}
        <input v-model="password2" type="password" autocomplete="new-password" required />
      </label>
      <label v-if="mode === 'setup'" class="field"
        >{{ t('login.setupToken') }}
        <input v-model="setupToken" autocomplete="off" placeholder="KHRZ_SETUP_TOKEN" />
      </label>
      <p v-if="error" class="error">{{ error }}</p>
      <button class="btn primary" type="submit" :disabled="busy">
        {{ t(mode === 'login' ? 'login.submitLogin' : 'login.submitSetup') }}
      </button>
      <p v-if="mode === 'setup'" class="dim">
        {{ t('login.setupHint') }}
      </p>
    </form>
    <p v-if="buildVersion" class="dim mono build">{{ buildVersion }}</p>
  </section>
</template>

<style scoped>
.login-panel {
  max-width: 24rem;
  margin: 2rem auto;
}

.tabswitch {
  margin-bottom: 0.75rem;
  border-bottom: 1px solid var(--border);
}

.tabswitch .on {
  color: var(--text);
  box-shadow: inset 0 -2px 0 var(--accent);
}

.build {
  margin: 0.75rem 0 0;
  font-size: 0.78rem;
  text-align: right;
}
</style>
