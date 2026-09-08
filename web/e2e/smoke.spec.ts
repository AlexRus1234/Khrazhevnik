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

// E2E-смоук полного цикла publish через реальный UI поверх собранного
// бинарника (оркестрация — global-setup.ts): первичная настройка →
// вход → создание apt-репо → загрузка .deb-фикстуры → переиндексация
// → публичный GET /repo/<name>/dists/stable/Release с byte-exact
// сверкой sha256 из двух независимых клиентов (браузер same-origin
// fetch + Node) и проверкой цепочки хешей (sha загруженного файла ===
// SHA256 в опубликованном Packages). Плюс: переключатель ru↔en и
// локализация кода ошибки API (invalid_credentials).

import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { expect, test } from '@playwright/test'

const ADMIN = process.env.KHRZ_E2E_ADMIN_URL ?? 'http://127.0.0.1:30202'
const PUBLIC = process.env.KHRZ_E2E_PUBLIC_URL ?? 'http://127.0.0.1:29202'

const PASSWORD = 'e2e-password'
const REPO = 'e2e'
const DEB_PATH = 'pool/main/a/app/app_1.0_amd64.deb'
// cwd Playwright = web/; фикстура — из test/smoke/fixtures (та же, что
// в binary_smoke_test.go и test/smoke/smoke.sh).
const FIXTURE_DEB = path.resolve(process.cwd(), '..', 'test', 'smoke', 'fixtures', ...DEB_PATH.split('/'))

// Язык пинаем на ru: ассерты в спеке завязаны на русские строки
// (селекторы типа placeholder/href стабильны независимо от языка).
// Только если ключа ещё нет: init-script выполняется на каждую
// навигацию, без проверки он затирал бы выбор пользователя (тест
// персистентности языка).
async function pinRu(page: import('@playwright/test').Page): Promise<void> {
  await page.addInitScript(() => {
    if (localStorage.getItem('khrazhevnik_locale') === null) {
      localStorage.setItem('khrazhevnik_locale', 'ru')
    }
  })
}

test.describe.configure({ mode: 'serial' })

test('publish: setup → репо apt → upload .deb → reindex → публичный Release byte-exact', async ({
  page,
  request,
}) => {
  await pinRu(page)
  await page.goto(`${ADMIN}/ui/login`)

  // Первичная настройка (база пустая): создаём администратора, экран
  // сам логинится и ведёт на дашборд.
  await page.getByRole('button', { name: 'Первичная настройка' }).click()
  await page.getByLabel('Логин').fill('admin')
  await page.getByLabel('Пароль', { exact: true }).fill(PASSWORD)
  await page.getByLabel('Пароль ещё раз').fill(PASSWORD)
  await page.locator('form button[type="submit"]').click()
  await expect(page.getByRole('heading', { name: 'Дашборд' })).toBeVisible()

  // Создание apt-репозитория. Владелец — первый (и единственный) user;
  // селект появляется после загрузки /users, ждём option с admin.
  await page.click('a[href="/ui/repos"]')
  await expect(page.getByRole('heading', { name: 'Личные репозитории' })).toBeVisible()
  await page.getByRole('button', { name: 'Добавить' }).click()
  await page.getByPlaceholder('myrepo').fill(REPO)
  const ownerSelect = page.locator('form select').nth(1)
  await expect(ownerSelect.locator('option', { hasText: 'admin' })).toBeAttached()
  await ownerSelect.selectOption({ label: 'admin (#1)' })
  await page.locator('form button[type="submit"]').click()
  await expect(page.getByRole('link', { name: REPO, exact: true })).toBeVisible()
  await page.getByRole('link', { name: REPO, exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Загрузка пакета' })).toBeVisible()

  // Upload фикстуры: путь вводим ДО выбора файла (onFileChange не
  // перезапишет непустое поле) — канонический pool/main/a/app/….
  await page.getByPlaceholder('pool/main/myapp_1.0_amd64.deb').fill(DEB_PATH)
  await page.setInputFiles('#upload-file', FIXTURE_DEB)
  await page.getByRole('button', { name: 'Загрузить', exact: true }).click()
  await expect(page.locator('p.ok')).toContainText(DEB_PATH)

  // Reindex: ждём появления сгенерированного Release в листинге
  // объектов (pollReindex обновляет таблицу по завершении задачи).
  await page.getByRole('button', { name: 'Переиндексировать', exact: true }).click()
  await expect(page.getByRole('cell', { name: 'dists/stable/release', exact: true })).toBeVisible({
    timeout: 60_000,
  })

  // Публичный Release: 200 + ожидаемые поля suite/component/arch.
  const releaseURL = `${PUBLIC}/repo/${REPO}/dists/stable/Release`
  const resp = await request.get(releaseURL)
  expect(resp.status()).toBe(200)
  const releaseBody = await resp.body()
  const nodeSha = createHash('sha256').update(releaseBody).digest('hex')
  const releaseText = releaseBody.toString('utf-8')
  expect(releaseText).toContain('Suite: stable')
  expect(releaseText).toContain('Components: main')
  expect(releaseText).toContain('Architectures: amd64')

  // Byte-exact: sha256, посчитанный В БРАУЗЕРЕ (fetch с публичного
  // origin — same-origin, CORS не участвует), === sha256 из Node по
  // независимому запросу: два клиента получили идентичные байты.
  await page.goto(`${PUBLIC}/healthz`)
  const browserSha = await page.evaluate(async (url) => {
    const buf = await (await fetch(url)).arrayBuffer()
    const digest = await crypto.subtle.digest('SHA-256', buf)
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
  }, releaseURL)
  expect(browserSha).toBe(nodeSha)

  // Цепочка хешей: sha256 локального файла фикстуры === SHA256 в
  // опубликованном Packages (загруженные байты дошли до индекса как есть).
  const deb = await readFile(FIXTURE_DEB)
  const debSha = createHash('sha256').update(deb).digest('hex')
  const pkgs = await request.get(`${PUBLIC}/repo/${REPO}/dists/stable/main/binary-amd64/Packages`)
  expect(pkgs.status()).toBe(200)
  const pkgsText = await pkgs.text()
  expect(pkgsText).toContain(`Filename: ${DEB_PATH}`)
  expect(pkgsText).toContain(`SHA256: ${debSha}`)
})

test('i18n: переключатель ru↔en, выбор сохраняется в localStorage', async ({ page }) => {
  await pinRu(page)
  await page.goto(`${ADMIN}/ui/login`)

  await expect(page.getByText('Кеш-прокси и зеркало linux-репозиториев')).toBeVisible()
  await page.click('[data-lang="en"]')
  await expect(page.getByText('Cache proxy and mirror of Linux repositories')).toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem('khrazhevnik_locale'))).toBe('en')

  // Перезагрузка не сбрасывает язык.
  await page.reload()
  await expect(page.getByText('Cache proxy and mirror of Linux repositories')).toBeVisible()

  await page.click('[data-lang="ru"]')
  await expect(page.getByText('Кеш-прокси и зеркало linux-репозиториев')).toBeVisible()
})

test('i18n: код ошибки API invalid_credentials локализован', async ({ page }) => {
  await pinRu(page)
  await page.goto(`${ADMIN}/ui/login`)

  // admin создан первым тестом (serial): неверный пароль → 401
  // invalid_credentials → ru-строка из словаря.
  await page.getByLabel('Логин').fill('admin')
  await page.getByLabel('Пароль', { exact: true }).fill('definitely-wrong')
  await page.locator('form button[type="submit"]').click()
  await expect(page.locator('p.error')).toHaveText('неверный логин или пароль')

  // Тот же код — en-строка после переключения языка и повторного сабмита.
  await page.click('[data-lang="en"]')
  await page.locator('form button[type="submit"]').click()
  await expect(page.locator('p.error')).toHaveText('invalid username or password')
})

test('дашборд: кнопка «Обновить» перечитывает статистику', async ({ page }) => {
  await pinRu(page)
  await page.goto(`${ADMIN}/ui/login`)

  // admin создан первым тестом (serial): обычный вход на дашборд.
  await page.getByLabel('Логин').fill('admin')
  await page.getByLabel('Пароль', { exact: true }).fill(PASSWORD)
  await page.locator('form button[type="submit"]').click()
  await expect(page.getByRole('heading', { name: 'Дашборд' })).toBeVisible()

  // Механика UI (числовая семантика перечитанных значений — уровень
  // TestAdminCacheStatsLive): клик по «Обновить» в панели кеша — без
  // ошибки, карточки на месте, кнопка выходит из disabled.
  const refresh = page.getByRole('button', { name: 'Обновить', exact: true })
  await expect(refresh).toBeVisible()
  await refresh.click()
  await expect(page.locator('p.error')).toHaveCount(0)
  await expect(page.getByText('Hit ratio')).toBeVisible()
  await expect(page.getByText('Попадания')).toBeVisible()
  await expect(page.getByText('Промахи')).toBeVisible()
  await expect(refresh).toBeEnabled()
})

test('дашборд: панель «По экосистемам»', async ({ page }) => {
  await pinRu(page)
  await page.goto(`${ADMIN}/ui/login`)

  // admin создан первым тестом (serial): обычный вход на дашборд.
  await page.getByLabel('Логин').fill('admin')
  await page.getByLabel('Пароль', { exact: true }).fill(PASSWORD)
  await page.locator('form button[type="submit"]').click()
  await expect(page.getByRole('heading', { name: 'Дашборд' })).toBeVisible()

  // Прокси-трафика в e2e-окружении нет (remotes не настроены):
  // per_ecosystem пуст → dim-строка; карточка пакетов в гриде кеша
  // со значением 0. Числа per-eco — уровень TestAdminCacheStatsPerEcosystem.
  await expect(page.getByRole('heading', { name: 'По экосистемам' })).toBeVisible()
  await expect(page.getByText('Данных по экосистемам пока нет.')).toBeVisible()
  const packagesCard = page.locator('.card', { hasText: 'Кешировано пакетов' })
  await expect(packagesCard).toBeVisible()
  await expect(packagesCard.locator('.value')).toHaveText('0')
})
