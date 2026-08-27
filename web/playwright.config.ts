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

// Playwright config для e2e-смоука Web UI поверх СОБРАННОГО бинарника
// (khrazhevnik-ci). Оркестрация — e2e/global-setup.ts (паттерн
// test/integration/binary_smoke_test.go): exec'ит процесс с temp-TOML
// до тестов и убивает после (вложенный podman на раннере невозможен,
// см. AGENTS.md §Тестирование в CI). workers:1 — тесты делят один
// инстанс сервера (первый создаёт администратора, остальные зависят
// от него); порядок = порядок объявления.

import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 120_000,
  reporter: [['list']],
  globalSetup: './e2e/global-setup.ts',
  use: {
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
