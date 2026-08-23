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

# Smoke-тесты

Дымовые тесты живого контейнера: `smoke.sh` поднимает fixture-upstream
(python3 `http.server` на каталоге `fixtures/`), запускает образ
khrazhevnik под podman и curl'ом проверяет раздачу метаданных через
прокси (byte-exact инвариант кеша), bootstrap-флоу (`/setup` → login →
create remote), 404 на мусорном пути и graceful shutdown по SIGTERM
за <10с.

## Запуск

```sh
make image          # собрать образ (нативная платформа)
make smoke          # = test/smoke/smoke.sh
# или с переопределением образа:
IMAGE=ghcr.io/alexrus1234/khrazhevnik TAG=v0.1.0 test/smoke/smoke.sh
```

Требует: `podman`, `python3`, `curl`, `jq`, `sha256sum`, `timeout`.
Контейнер дотягивается до fixture-upstream через `--add-host=...:host-gateway`,
поэтому скрипт надо запускать в окружении, где podman и python3 видят
одного хоста (CI Linux, WSL/podman-machine SSH).

## Известные баги

`known-bugs.txt` — паттерны (подстроки в сообщениях `FAIL: ...`). Если
все падения матчат известный баг, скрипт выходит 0 (фича в разработке,
регрессий нет); любое неизвестное падение красит сборку. Формат
унаследован из Intermasq.

## Fixtures

`fixtures/dists/stable/Release` и `fixtures/pool/.../*.deb` — мини-репо
apt: smoke создаёт remote apt с `base_url` на fixture-upstream и
проверяет, что прокси отдаёт Release побайтово (sha256 совпадает с
файлом). Сессия 10, этап M1.
