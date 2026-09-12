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

# Нагрузочное тестирование (bench/)

Методика и инструменты для замера производительности живого инстанса:
RPS/пропускная способность/латентность + потребление CPU/RAM контейнером
Хражевника и его бэкендами (S3-хранилище, каталог БД). Результаты
прогонов и описание окружения — в
[`docs/func/ru/benchmarks.md`](../docs/func/ru/benchmarks.md).

## Схема

```
рабочая станция (k6) ──► публичный порт Хражевника (пакеты, /healthz)
                              │
        ┌─────────────────────┴─────────────────────┐
        ▼                                           ▼
  S3-хранилище (объекты)                     каталог (postgres/sqlite)
  сэмплер: nas-stats.sh / podman-stats.sh     сэмплер: там же
                              │
                    metrics-scrape.sh ──► /metrics (админ-порт)
```

Нагрузчик всегда запускается **не на целевом хосте** — иначе он
конкурирует с тестируемым сервисом за CPU и портит измерение.

## Состав

| Путь | Назначение |
|---|---|
| `k6/urls.txt` | список объектов: `путь\|класс` (meta/small/mid/large) |
| `k6/hit-mixed.js` | сценарий A: тёплый кеш, ступени фиксированного RPS |
| `k6/stream-large.js` | сценарий B: стриминг одного крупного объекта, ступени VU |
| `k6/apt-storm.js` | сценарий C: итерация «apt update + установка», VU = клиент |
| `k6/cold-miss.js` | сценарий D (опц.): холодные объекты, MISS-путь |
| `sampling/podman-stats.sh` | на хосте контейнера: `podman stats` + cgroup-пики → CSV |
| `sampling/nas-stats.sh` | на NAS (bare-metal systemd-юниты): cgroup v2 → CSV |
| `sampling/metrics-scrape.sh` | циклический снапшот `/metrics` (JWT) |
| `sampling/metrics-diff.sh` | дифф двух снапшотов: дельты счётчиков + p50/p90/p99 |

## Зависимости

- **k6** (нагрузчик; [grafana.com/docs/k6](https://grafana.com/docs/k6/latest/set-up/install-k6/))
- **curl, jq, awk** — прогрев и сэмплеры
- SSH-доступ к хостам контейнера/БД для сэмплеров

## Подготовка (один раз перед прогоном)

1. **Список объектов.** Проверить `k6/urls.txt`: имена remotes — как в
   `GET /api/v1/remotes`, пути — существуют, классы соответствуют
   фактическим размерам. Дефолт рассчитан на remote `debian` (apt);
   строки прочих экосистем закомментированы.
2. **Прогрев кеша** (каждый URL дважды; второй — `X-Cache: HIT`):

   ```bash
   while IFS='|' read -r path _; do
     case "$path" in ''|'#'*) continue;; esac
     code=$(curl -s -o /dev/null -w '%{http_code}' "KHRZ_BASE$path")
     hit=$(curl -s -o /dev/null -D - "KHRZ_BASE$path" | awk -F': ' '/^X-Cache/{print $2}')
     echo "$code $hit $path"
   done < k6/urls.txt
   ```

   (вместо `KHRZ_BASE` — адрес, дефолт скриптов `http://172.20.6.9:10002`).
3. **Сброс статистики** (счётчики кеша с нуля; аудируется):

   ```bash
   curl -X POST -H "Authorization: Bearer $TOKEN" \
     KHRA_ADMIN/api/v1/cache/stats/reset
   ```

## Снятие метрик (три контура, запустить до нагрузки)

```bash
# 1. Целевой хост (panelka, app-runner): контейнер Хражевника (+ соседи).
#    Имена контейнеров = `podman ps` (quadlet даёт systemd-<name>).
ssh app-runner@172.20.6.9 'INTERVAL=10 CONTAINERS="systemd-02-khrazhevnik systemd-01-nora" \
  OUT=bench/podman-stats.csv PEAKS=bench/cgroup-peaks.csv \
  bash -s' < sampling/podman-stats.sh &

# 2. NAS: postgres и S3-хранилище как systemd-юниты (cgroup v2 читается
#    без root; имена контейнеров/юнитов подставь свои).
ssh alexrus1234@172.20.50.1 'UNITS="postgresql.service rustfs.service" \
  INTERVAL=10 OUT=/tmp/nas-stats.csv bash -s' < sampling/nas-stats.sh &

# 3. /metrics каждые 15с (JWT или KHRZ_TOKEN; админ-порт).
ADMIN=http://172.20.6.9:10003 KHRZ_USER=admin KHRZ_PASS='…' \
  OUT_DIR=bench/metrics INTERVAL=15 sampling/metrics-scrape.sh &
```

`bench/results/` (CSV, снапшоты) в git не попадает; эталонные цифры
переносятся в `docs/func/ru/benchmarks.md` таблицами.

## Сценарии

Все сценарии читают `KHRZ_BASE` (дефолт `http://172.20.6.9:10002`),
ступени — `KHRZ_STAGES`, пауза между ступенями — `KHRZ_GAP` (дефолт
`30s`). Имя ступени = имя k6-сценария (`r200` — 200 rps, `v8` — 8 VU):
по нему фильтруются summary и trend-вывод (`--summary-export`).

### A. hit-mixed — тёплый кеш, RPS-ступени

Главный сценарий: горячий путь «каталог → S3 → стрим» на смеси
метаданных и пакетов.

```bash
k6 run -e KHRZ_STAGES='50:2m,200:2m,500:2m,1000:2m,2000:2m' \
  --summary-export=bench/results/hit-mixed.json k6/hit-mixed.js
```

Смотрим: RPS-потолок (где `http_req_duration` p95 растёт нелинейно),
`khz_cache_miss` (должен быть ≈0; иначе кеш не прогрет), CPU/RAM
контейнера по CSV на времени ступени.

### B. stream-large — пропускная способность

```bash
k6 run -e KHRZ_LARGE_URL='/apt/debian/…/big.deb' \
  -e KHRZ_STAGES='1:2m,2:2m,4:2m,8:2m' \
  --summary-export=bench/results/stream-large.json k6/stream-large.js
```

Смотрим: `khz_stream_bytes`/ступень ÷ длительность = MB/s; плечо LAN
(1 Gb/s ≈ 118 MB/s) может оказаться потолком — это честный потолок
прод-сети, фиксируется в результатах отдельно от сервера.

### C. apt-storm — шторм apt-клиентов

```bash
k6 run -e KHRZ_STAGES='10:2m,50:2m,200:2m' \
  --summary-export=bench/results/apt-storm.json k6/apt-storm.js
```

Итерация VU: все `/apt/*` meta из urls.txt + `KHRZ_PKGS` (дефолт 4)
случайных пакета. Условные GET не моделируются: прокси не отвечает
клиентам 304 (byte-exact инвариант), метаданные отдаются целиком.

### D. cold-miss (опционально)

Список `urls-cold.txt` — реальный существующий upstream-контент, не
пересекающийся с urls.txt; параллелизм низкий (бьём в настоящий
upstream через socks5).

```bash
k6 run -e KHRZ_URLS='./urls-cold.txt' -e KHRZ_VUS=4 -e KHRZ_PACE=1 \
  k6/cold-miss.js
```

Смотрим: `khz_cold_status{xcache="MISS"}` должна доминировать,
singleflight не должен дублировать загрузки (логи/счётчик misses).

## Порядок прогона

1. Pre-flight: место в S3-бакете, отсутствие плановых задач (зеркала,
   бэкапы), версия образа — записать в benchmarks.md.
2. Запустить три сэмплера; 5 минут idle = baseline.
3. Прогрев urls.txt, сброс статистики кеша.
4. A → пауза 5 мин → B → пауза 5 мин → C (→ D по необходимости).
5. Остановить сэмплеры; собрать CSV и снапшоты в `bench/results/`.

## Разбор

- **k6:** `--summary-export` JSON + консольный summary; ступень
  фильтруется по тегу `scenario`.
- **Сервер:** `metrics-diff.sh <снапшот-до> <снапшот-после>` — дельты
  hits/misses/байт и p50/p90/p99 по серверу (сравнить с клиентскими
  p95 из k6: расхождение = очередь на сети/клиенте).
- **CPU/RAM:** корреляция CSV сэмплеров с интервалами ступеней по
  времени (`ts`); `memory.peak` за прогон — пиковый RSS.

Результаты и выводы оформляются в
[`docs/func/ru/benchmarks.md`](../docs/func/ru/benchmarks.md).
