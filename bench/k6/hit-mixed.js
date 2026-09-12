// Хражевник — кеш-прокси и зеркало linux-репозиториев
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Сценарий A «hit-mixed»: тёплый кеш, смесь метаданных и пакетов
// (классы meta+small+mid из urls.txt). Ступени фиксированного RPS:
//   k6 run -e KHRZ_STAGES='50:2m,200:2m,500:2m,1000:2m,2000:2m' hit-mixed.js
// Перед прогоном — прогрев (см. bench/README.md), иначе ступень уйдёт в
// MISS-загрузку upstream и измерит socks5, а не Хражевника.

import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { BASE, parseUrls, buildArrivalScenarios } from './common.js';

const urls = parseUrls(
  open(__ENV.KHRZ_URLS || './urls.txt'),
  __ENV.KHRZ_CLASSES || 'meta,small,mid',
);
if (urls.length === 0) {
  throw new Error('urls.txt не дал ни одного объекта выбранных классов (KHRZ_CLASSES)');
}

const cacheMiss = new Counter('khz_cache_miss');

export const options = buildArrivalScenarios(
  __ENV.KHRZ_STAGES || '50:2m,200:2m,500:2m,1000:2m,2000:2m',
);

export default function () {
  // По кругу от seed VU+ITER: детерминированное покрытие списка без
  // корреляции выбора между VU (все гонятся по одному смещению).
  const u = urls[(__VU * 31 + __ITER * 7) % urls.length];
  const res = http.get(BASE + u.path, { tags: { cls: u.cls } });
  const xc = res.headers['X-Cache'] || '';
  check(res, {
    'status 200': (r) => r.status === 200,
    'cache HIT': () => xc === 'HIT' || xc === 'STALE',
  });
  if (xc === 'MISS' || xc === '') cacheMiss.add(1, { cls: u.cls });
}
