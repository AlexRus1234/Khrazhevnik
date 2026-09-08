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

# Веб-админка

SPA встроена в бинарник (`//go:embed`) и раздаётся на админском порту:
**`http://127.0.0.1:30202/ui/`**. Язык — русский/английский
(переключатель в шапке), все операции идут через
[REST API](api.md).

## Вход

- **Логин**: username + password → JWT-сессия (TTL `auth.session_ttl`,
  8h по умолчанию). Разлогинивание отзывает JWT.
- **Bootstrap**: при пустой таблице users вместо логина предлагается
  создание первого админа (вторая вкладка). Если задан
  `auth.setup_token` — вводится и он.
- Без токена доступен только `/ui/login`; истечение сессии (401 от
  любого запроса) автоматически возвращает на логин.

## Дашборд

Статистика кеша (`/api/v1/cache/stats`): hits/misses, hit-ratio,
stale-отдачи, negative-hits, ошибки upstream, байты от upstream и
клиентам, число закешированных пакетов. Кнопки в заголовке панели:
**Обновить** — перечитывает статистику и задачи без перезагрузки
страницы; **Сбросить статистику** — после подтверждения обнуляет
счётчики (в памяти и в БД, [REST](api.md) `POST /cache/stats/reset`,
запись в аудит) — операция необратима.

Ниже — панель **По экосистемам**: для каждой экосистемы с трафиком —
число закешированных пакетов, hit-ratio, hits/misses, байты от
upstream и клиентам (`per_ecosystem` из `/cache/stats`).

Ниже — панель **Последние транзакции**: лента последних клиентских
запросов к кешу — время, экосистема, путь, статус
(HIT/MISS/STALE/ERROR), размер, текст ошибки. Лента обновляется в
общем 2-секундном поллинге задач и кнопкой «Обновить»; буфер
in-memory (последние 50) — после рестарта сервера история начинается
с нуля.

Ниже — живой список фоновых задач (state, прогресс,
скорость). Подсказка со ссылкой на Prometheus `/metrics`.

## Remotes

Управление upstream'ами: создание/правка/удаление, переключение
`proxy`/`mirror`, `sync_interval`, `include` (фильтр зеркала — формат
зависит от экосистемы, см. [ecosystems/](ecosystems/)), вкл/выкл,
кнопка запуска sync для зеркал (состояние задачи видно тут же и на
дашборде).

## Repos и репозиторий

- **Список репо**: создание (имя-slug, экосистема, владелец, квота
  max_bytes/max_objects), правка, удаление.
- **Страница репо**:
  - **Upload**: путь внутри репо (`pool/main/f/foo/foo_1.0_amd64.deb`)
    + файл; `force` — перезапись существующего ключа (только админ:
    остальные субъекты получают 403 `admin_required`). После
    upload — `reindex` (кнопка): фоновая генерация индексов и подписей.
  - **Объекты**: листинг (путь/размер/изменён), удаление объектов.
  - **Права**: выдача/отзыв права записи пользователям.
- Формат путей и генерируемые индексы — [personal-repos.md](personal-repos.md).

## Users

Создание/удаление пользователей, выпуск scoped API-токенов
(`repo:<id>:write` с выбором репо; секрет показывается один раз —
копируется сразу), отзыв токенов, список действующих.

## Audit

Журнал мутаций (actor/action/object/result/detail) с подгрузкой старых
записей (keyset-пагинация по `after_id`).

## Keys

Публичный ключ выбранного репо: копирование/скачивание `key.asc`,
готовые строки для клиентов (`signed-by=…`, `rpm --import`, файл в
`/etc/apk/keys/`, `pacman-key --add`); для nix-репо — отдельно
`nix-key.asc` (формат `name:pubkey-b64`). Если ключ ещё не
сгенерирован — подсказка (репо без подписи до первого reindex /
деградированный режим).

## Tasks

Список задач с дашборда также доступен через API (`/api/v1/tasks`);
UI показывает активные и завершившиеся с ошибкой задачи реестра
(in-memory, переживает перезагрузку списка, но не сервер).
