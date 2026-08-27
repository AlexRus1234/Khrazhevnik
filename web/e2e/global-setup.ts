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

// Оркестрация бинарника для Playwright e2e (JS-аналог
// test/integration/binary_smoke_test.go): до тестов — temp-TOML
// (server + fs-storage + sqlite + jwt), свободные порты, exec
// khrazhevnik-ci, ожидание /healthz на обоих слушателях; после
// тестов — SIGTERM (graceful) с подстраховкой SIGKILL. URL'ы
// передаются в спеки через env: сервер один на весь прогон, тесты
// идут последовательно (workers:1).
//
// Путь к артефакту: env KHRZ_TEST_BINARY (CI выставляет абсолютный)
// либо <repo-root>/khrazhevnik-ci; cwd Playwright = web/, корень
// репо — на уровень выше.

import { spawn, type ChildProcess } from 'node:child_process'
import { createServer } from 'node:net'
import { mkdtemp, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const ROOT = path.resolve(process.cwd(), '..')

async function binaryPath(): Promise<string> {
  const env = process.env.KHRZ_TEST_BINARY
  if (env !== undefined && env !== '') {
    await stat(env)
    return env
  }
  const p = path.join(ROOT, 'khrazhevnik-ci')
  try {
    await stat(p)
  } catch {
    throw new Error(
      `бинарник не найден: ${p}. Собери \`go build -o khrazhevnik-ci ./cmd/khrazhevnik\` ` +
        'или выстави KHRZ_TEST_BINARY',
    )
  }
  return p
}

// freePort: занять 127.0.0.1:0 и отдать номер порта. Между close и
// стартом сервера есть окно гонки — для e2e (один прогон на машине)
// это не хуже паттерна Go-тестов (wire_test.go freePort).
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address()
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0
      srv.close(() => resolve(port))
    })
  })
}

async function waitHealthy(
  url: string,
  serverOutput: () => string,
  spawnError: () => Error | null,
): Promise<void> {
  const deadline = Date.now() + 30_000
  for (;;) {
    const se = spawnError()
    if (se !== null) {
      throw new Error(`не удалось запустить бинарник: ${se.message}`)
    }
    try {
      const resp = await fetch(url)
      if (resp.ok) return
    } catch {
      // ещё не слушает — poll до дедлайна
    }
    if (Date.now() > deadline) {
      throw new Error(`сервер не поднялся за 30с: ${url}\n--- вывод сервера ---\n${serverOutput()}`)
    }
    await new Promise((r) => setTimeout(r, 250))
  }
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  const bin = await binaryPath()
  const dir = await mkdtemp(path.join(tmpdir(), 'khrazhevnik-e2e-'))
  const publicPort = await freePort()
  const adminPort = await freePort()

  // Минимальный TOML (как в binary_smoke_test.go): экосистемы включены
  // дефолтным конфигом, админ создаётся через /api/v1/setup из UI.
  // Windows-пути → слэши (pelletier/go-toml принимает обе формы, но
  // обратные слэши в basic-строках TOML являются escape-последовательностями).
  const toSlash = (p: string): string => p.split(path.sep).join('/')
  const toml =
    '[server]\n' +
    `public_listen = "127.0.0.1:${publicPort}"\n` +
    `admin_listen = "127.0.0.1:${adminPort}"\n\n` +
    '[storage.fs]\n' +
    `path = "${toSlash(path.join(dir, 'store'))}"\n\n` +
    '[database]\n' +
    `dsn = "${toSlash(path.join(dir, 'khrazhevnik.db'))}"\n\n` +
    '[auth]\n' +
    'jwt_secret = "e2e-secret"\n'
  const confPath = path.join(dir, 'khrazhevnik.toml')
  await writeFile(confPath, toml, 'utf-8')

  const proc: ChildProcess = spawn(bin, ['-config', confPath], { stdio: ['ignore', 'pipe', 'pipe'] })
  let out = ''
  proc.stdout?.on('data', (d: Buffer) => {
    out += d.toString()
  })
  proc.stderr?.on('data', (d: Buffer) => {
    out += d.toString()
  })
  const exited = new Promise<number | null>((resolve) => {
    proc.on('exit', (code) => resolve(code))
  })
  // Ошибка spawn (ENOENT и т.п.): флаг, а не throw из листенера —
  // waitHealthy проверяет его на каждой итерации и фейлится быстро.
  let spawnErr: Error | null = null
  proc.on('error', (err: Error) => {
    spawnErr = err
  })

  process.env.KHRZ_E2E_ADMIN_URL = `http://127.0.0.1:${adminPort}`
  process.env.KHRZ_E2E_PUBLIC_URL = `http://127.0.0.1:${publicPort}`

  try {
    await waitHealthy(`${process.env.KHRZ_E2E_ADMIN_URL}/healthz`, () => out, () => spawnErr)
    await waitHealthy(`${process.env.KHRZ_E2E_PUBLIC_URL}/healthz`, () => out, () => spawnErr)
  } catch (err) {
    proc.kill('SIGKILL')
    throw err
  }

  return async () => {
    // SIGTERM → graceful shutdown (exit 0 <10с — проверено Go-смоуком);
    // локально на Windows kill terminates немедленно — код выхода не
    // ассертим, важно только не оставить процесс живым.
    proc.kill('SIGTERM')
    const grace = new Promise((r) => setTimeout(r, 10_000))
    await Promise.race([exited, grace])
    if (proc.exitCode === null) proc.kill('SIGKILL')
  }
}
