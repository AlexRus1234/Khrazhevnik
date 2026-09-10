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

# Быстрый старт

За пять минут: контейнер → первый админ → первый remote → клиент apt
через кеш-прокси. Подразумевается rootless podman + systemd --user на
Linux-машине.

## 1. Установка контейнера

Образ — в пяти реестрах-зеркалах (любой на выбор; подробности и
нюансы — [deploy.md](deploy.md#реестры-образа)):

```sh
docker pull git.alexrus1234.ru/alexrus1234/khrazhevnik:latest   # основной
docker pull ghcr.io/alexrus1234/khrazhevnik:latest
docker pull docker.io/alexrus1234/khrazhevnik:latest
docker pull codeberg.org/alexrus1234/khrazhevnik:latest   # нужен login
podman pull quay.io/alexrus1234/khrazhevnik:latest
```

```sh
# quadlet в пользовательский путь генератора systemd.
mkdir -p ~/.config/containers/systemd
cp deploy/quadlet/khrazhevnik.container ~/.config/containers/systemd/

# JWT-секрет — Podman Secret (не светится в env и systemctl show).
podman secret create jwt-secret "$(openssl rand -hex 32)"

# Каталог данных: контейнер работает под UID 65534 (nobody).
sudo mkdir -p /var/lib/khrazhevnik
sudo chown 65534:65534 /var/lib/khrazhevnik

# Старт.
systemctl --user daemon-reload
systemctl --user start khrazhevnik.service
curl -s http://localhost:29202/healthz   # → ok
```

Подробности, переменные окружения, свой TOML — в
[deploy.md](deploy.md) и [config.md](config.md).

## 2. Bootstrap: первый админ

Пока таблица `users` пуста, веб-админка при первом заходе предлагает
создать админа. То же через API:

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/setup \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<пароль>"}'
```

Откройте `http://127.0.0.1:30202/ui/` и войдите — дальше всё можно
делать из UI ([ui.md](ui.md)). Шаги ниже — те же действия через API.

## 3. Первый remote (кеш-прокси Debian)

```sh
TOKEN=$(curl -s -X POST http://127.0.0.1:30202/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<пароль>"}' | jq -r .token)

curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy","enabled":true}'
```

Headless-альтернатива (без поднятия UI/API — для init-скриптов):

```sh
podman exec khrazhevnik /khrazhevnik -add-remote apt/debian=https://deb.debian.org/debian
```

## 4. Настройка клиента

На любой Debian/Ubuntu-машине укажите Хражевник вместо upstream:

```sh
echo 'deb http://<хражевник>:29202/apt/debian stable main' \
  > /etc/apt/sources.list.d/khrazhevnik.list
apt-get update
apt-get install hello
```

Подписи и чексуммы валидны: метаданные upstream отдаются побайтово.

## 5. Проверка кеша

```sh
curl -sI http://<хражевник>:29202/apt/debian/dists/stable/main/binary-amd64/Packages.gz | grep -i x-cache
```

Повторный запрос отдаётся из кеша (`X-Cache: HIT`); пакеты (`pool/…`)
кешируются навсегда, индексы (`dists/…`) ревалидируются по
ETag/Last-Modified.

## Что дальше

- Все экосистемы (apt, dnf/zypper, pacman, apk, nix) — [ecosystems/](ecosystems/).
- Зеркала (`mode = mirror`) — [README](../../README.md#зеркало).
- Личные репозитории с подписью — [personal-repos.md](personal-repos.md).
- Веб-админка — [ui.md](ui.md).
- Справочник REST API — [api.md](api.md).
