/*
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
*/

// Рукописный i18n без библиотеки (белый список зависимостей — только
// vue/vue-router): locale — реактивный ref, t() читает его при вызове,
// поэтому шаблоны и вычисляемые строки перерисовываются при смене языка
// без пересборки. Каталоги — плоские dotted-ключи в locales/{ru,en}.json
// (ru — источник истины: en-ключ без ru-пары не существует по камере).
// Выбор языка сохраняется в localStorage, дефолт — ru.

import { ref } from 'vue'
import ru from './locales/ru.json'
import en from './locales/en.json'

export type Locale = 'ru' | 'en'

const LOCALE_KEY = 'khrazhevnik_locale'
const DICTS: Record<Locale, Record<string, string>> = { ru, en }

function detect(): Locale {
  const saved = localStorage.getItem(LOCALE_KEY)
  if (saved === 'ru' || saved === 'en') return saved
  return 'ru'
}

export const locale = ref<Locale>(detect())

export function setLocale(l: Locale): void {
  locale.value = l
  localStorage.setItem(LOCALE_KEY, l)
  document.documentElement.lang = l
}

// t — ключ активного словаря с {param}-подстановками; отсутствующий ключ
// фолбэчится на ru, затем на сам ключ (опечатка в ключе видна сразу).
export function t(key: string, params?: Record<string, string | number>): string {
  let s = DICTS[locale.value][key] ?? DICTS.ru[key] ?? key
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      s = s.replaceAll(`{${k}}`, String(v))
    }
  }
  return s
}

// tr — как t, но null для отсутствующего ключа: errText различает
// «известный код ошибки» и фолбэк по HTTP-статусу.
export function tr(key: string): string | null {
  return DICTS[locale.value][key] ?? DICTS.ru[key] ?? null
}
