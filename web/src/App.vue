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
import { RouterLink, RouterView, useRouter } from 'vue-router'
import { logout } from './api'
import LangSwitch from './components/LangSwitch.vue'
import { t } from './i18n'
import { loggedIn, markLoggedOut } from './stores/auth'

const router = useRouter()

async function onLogout(): Promise<void> {
  await logout()
  markLoggedOut()
  void router.push({ name: 'login' })
}
</script>

<template>
  <div class="app">
    <header v-if="loggedIn" class="topbar">
      <span class="brand">Хражевник</span>
      <nav class="tabs">
        <RouterLink to="/dashboard">{{ t('nav.dashboard') }}</RouterLink>
        <RouterLink to="/remotes">{{ t('nav.remotes') }}</RouterLink>
        <RouterLink to="/repos">{{ t('nav.repos') }}</RouterLink>
        <RouterLink to="/users">{{ t('nav.users') }}</RouterLink>
        <RouterLink to="/audit">{{ t('nav.audit') }}</RouterLink>
        <RouterLink to="/keys">{{ t('nav.keys') }}</RouterLink>
      </nav>
      <LangSwitch />
      <button class="btn ghost logout" @click="onLogout">{{ t('nav.logout') }}</button>
    </header>

    <main class="content">
      <RouterView />
    </main>
  </div>
</template>

<style>
:root {
  --bg: #16181d;
  --panel: #1e2128;
  --inset: #12141a;
  --border: #333845;
  --text: #d7dae0;
  --dim: #8b93a3;
  --accent: #6ca0ff;
  --ok: #7ec98f;
  --warn: #e0b464;
  --err: #e07a7a;
  color-scheme: dark;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.5 system-ui, 'Segoe UI', Roboto, sans-serif;
}

.app {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.content {
  flex: 1;
  padding: 1rem;
  max-width: 75rem;
  width: 100%;
  margin: 0 auto;
}

h1 {
  margin: 0 0 0.75rem;
  font-size: 1.2rem;
}

h2 {
  margin: 0 0 0.6rem;
  font-size: 1rem;
}

.dim {
  color: var(--dim);
}

.mono {
  font-family: ui-monospace, 'Cascadia Mono', Consolas, monospace;
}

/* Панели/сетка — общие для всех экранов. */
.panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 1rem;
}

.grid {
  display: grid;
  gap: 0.75rem;
}

.cards {
  grid-template-columns: repeat(auto-fill, minmax(10rem, 1fr));
}

.card {
  background: var(--inset);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.6rem 0.75rem;
}

.card .value {
  font-size: 1.35rem;
  font-weight: 600;
  margin-top: 0.15rem;
}

.row {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  flex-wrap: wrap;
}

.spread {
  justify-content: space-between;
}

/* Формы. */
label.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.85rem;
  color: var(--dim);
  min-width: 0;
}

input,
select,
textarea {
  background: var(--inset);
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text);
  padding: 0.35rem 0.5rem;
  font: inherit;
}

input:focus,
select:focus,
textarea:focus {
  outline: 1px solid var(--accent);
}

input[type='checkbox'] {
  width: 1rem;
  height: 1rem;
  accent-color: var(--accent);
}

/* Кнопки. */
.btn {
  background: var(--inset);
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text);
  padding: 0.35rem 0.9rem;
  font: inherit;
  cursor: pointer;
  text-decoration: none;
  display: inline-block;
}

.btn:hover {
  border-color: var(--accent);
}

.btn.primary {
  background: var(--accent);
  border-color: var(--accent);
  color: #10131a;
  font-weight: 600;
}

.btn.danger:hover {
  border-color: var(--err);
  color: var(--err);
}

.btn.ghost {
  background: none;
  border-color: transparent;
}

.btn:disabled {
  opacity: 0.5;
  cursor: default;
}

/* Таблицы. */
table {
  border-collapse: collapse;
  width: 100%;
}

th,
td {
  text-align: left;
  padding: 0.35rem 0.5rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}

th {
  color: var(--dim);
  font-weight: 500;
  font-size: 0.85rem;
  white-space: nowrap;
}

/* Статусные строки. */
.error {
  color: var(--err);
}

.ok {
  color: var(--ok);
}

.warn {
  color: var(--warn);
}

.progress {
  height: 0.7rem;
  background: var(--inset);
  border: 1px solid var(--border);
  border-radius: 4px;
  overflow: hidden;
}

.progress > div {
  height: 100%;
  background: var(--accent);
  transition: width 0.2s;
}

.badge {
  display: inline-block;
  border-radius: 999px;
  padding: 0 0.5rem;
  font-size: 0.8rem;
  border: 1px solid var(--border);
}

.badge.running {
  color: var(--accent);
  border-color: var(--accent);
}

.badge.succeeded {
  color: var(--ok);
  border-color: var(--ok);
}

.badge.failed {
  color: var(--err);
  border-color: var(--err);
}

pre.snippet {
  background: var(--inset);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.6rem 0.75rem;
  overflow-x: auto;
  margin: 0.25rem 0;
}
</style>

<style scoped>
.topbar {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 1rem;
  background: var(--panel);
  border-bottom: 1px solid var(--border);
}

.brand {
  font-weight: 700;
  letter-spacing: 0.05em;
}

.tabs {
  display: flex;
  gap: 0.25rem;
  flex-wrap: wrap;
  flex: 1;
}

.tabs a {
  border: none;
  background: none;
  border-radius: 4px;
  padding: 0.3rem 0.9rem;
  color: var(--dim);
  text-decoration: none;
}

.tabs a:hover {
  color: var(--text);
}

.tabs a.router-link-active {
  background: var(--inset);
  color: var(--text);
  box-shadow: inset 0 -2px 0 var(--accent);
}

.logout {
  color: var(--dim);
}
</style>
