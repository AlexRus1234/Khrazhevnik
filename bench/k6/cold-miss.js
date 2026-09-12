// Хражевник — кеш-прокси и зеркало linux-репозиториев
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Сценарий D «cold-miss» (опциональный): объекты, которых нет в кеше —
// проверка MISS-пути: singleflight, spool, скорость upstream через
// socks5. Список — реальный существующий upstream-контент, НЕ из
// urls.txt (иначе снова измерим HIT). Ожидаем X-Cache: MISS на первом
// получении; параллелизм держим низким — бьём в настоящий upstream.
//   k6 run -e KHRZ_URLS='./urls-cold.txt' -e KHRZ_VUS=4 cold-miss.js
// Каждая VU идёт по своему непересекающемуся срезу списка (stride =
// число VU), между запросами пауза KHRZ_PACE секунд (дефолт 1).

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';
import { BASE, parseUrls } from './common.js';

const urls = parseUrls(open(__ENV.KHRZ_URLS || './urls-cold.txt'), '*');
if (urls.length === 0) {
  throw new Error('KHRZ_URLS: пустой список холодных объектов');
}
const vus = parseInt(__ENV.KHRZ_VUS || '4', 10);
const pace = parseFloat(__ENV.KHRZ_PACE || '1');

const seen = new Counter('khz_cold_status');

export const options = {
  scenarios: {
    cold: {
      executor: 'constant-vus',
      vus,
      duration: __ENV.KHRZ_DURATION || '10m',
    },
  },
  thresholds: { 'http_req_failed': ['rate<0.02'] },
};

export default function () {
  // Страйд по числу VU: непересекающиеся срезы — каждый объект кеша
  // гарантированно холодный ровно один раз на прогон.
  const idx = (__VU - 1) + __ITER * vus;
  if (idx >= urls.length) {
    return; // свой срез исчерпан — доигрываем паузу и выходим
  }
  const res = http.get(BASE + urls[idx].path);
  check(res, { 'status 200': (r) => r.status === 200 });
  seen.add(1, { xcache: res.headers['X-Cache'] || '-' });
  sleep(pace);
}
