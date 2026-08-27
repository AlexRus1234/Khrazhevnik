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
import { locale, setLocale, type Locale } from '../i18n'

// Переключатель RU/EN: одна кнопка на язык, активная подчёркнута.
// data-lang — стабильный селектор для e2e (текст кнопки = язык).
const LOCALES: Locale[] = ['ru', 'en']
</script>

<template>
  <div class="langswitch" role="group" aria-label="language">
    <button
      v-for="l in LOCALES"
      :key="l"
      class="btn ghost lang-btn"
      :class="{ on: locale === l }"
      type="button"
      :data-lang="l"
      @click="setLocale(l)"
    >
      {{ l.toUpperCase() }}
    </button>
  </div>
</template>

<style scoped>
.langswitch {
  display: flex;
}

.lang-btn {
  padding: 0.3rem 0.5rem;
  text-transform: uppercase;
}

.lang-btn.on {
  color: var(--text);
  box-shadow: inset 0 -2px 0 var(--accent);
}
</style>
