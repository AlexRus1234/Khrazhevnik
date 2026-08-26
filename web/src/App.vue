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
import { RouterLink, RouterView } from 'vue-router'
</script>

<template>
  <div class="app">
    <header class="topbar">
      <span class="brand">Хражевник</span>
      <nav class="tabs">
        <RouterLink to="/dashboard">Дашборд</RouterLink>
        <RouterLink to="/remotes">Источники</RouterLink>
        <RouterLink to="/repos">Репозитории</RouterLink>
      </nav>
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

.dim {
  color: var(--dim);
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
</style>
