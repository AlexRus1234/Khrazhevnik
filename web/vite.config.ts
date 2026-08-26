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

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Прод: бандл ложится в ../internal/core/web/assets и встраивается в бинарь
// через //go:embed (internal/core/web/spa.go). base '/ui/' совпадает с
// mount-поинтом админского роутера (:30202). Дев: vite dev-сервер с прокси
// /api на админку и /repo на публичный порт (make web-dev).
export default defineConfig({
  plugins: [vue()],
  base: '/ui/',
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:30202',
      '/repo': 'http://127.0.0.1:29202',
    },
  },
  build: {
    outDir: '../internal/core/web/assets',
    emptyOutDir: true,
  },
})
