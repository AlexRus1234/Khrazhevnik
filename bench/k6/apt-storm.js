// Хражевник — кеш-прокси и зеркало linux-репозиториев
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Сценарий C «apt-storm»: имитация apt-клиента — итерация VU это
// «apt update + установка пары пакетов»: все метаданные /apt/* класса
// meta, затем KHRZ_PKGS случайных пакетов из small/mid. Условные
// клиентские GET не моделируем: прокси не отвечает 304 (byte-exact
// инвариант), метаданные всегда отдаются целиком.
//   k6 run -e KHRZ_STAGES='10:2m,50:2m,200:2m' apt-storm.js
// VU = «клиент» (машина с apt).

import http from 'k6/http';
import { check } from 'k6';
import { BASE, parseUrls, buildVUScenarios } from './common.js';

const all = parseUrls(open(__ENV.KHRZ_URLS || './urls.txt'), '*');
const meta = all.filter((u) => u.cls === 'meta' && u.path.startsWith('/apt/'));
const pool = all.filter(
  (u) => (u.cls === 'small' || u.cls === 'mid') && u.path.startsWith('/apt/'),
);
if (meta.length === 0 || pool.length === 0) {
  throw new Error('нужны /apt/-объекты классов meta и small/mid в urls.txt');
}
const pkgs = parseInt(__ENV.KHRZ_PKGS || '4', 10);

export const options = buildVUScenarios(
  __ENV.KHRZ_STAGES || '10:2m,50:2m,200:2m',
);

function shuffle(n) {
  // Фишер–Йетс на индексах пула: сэмпл без возвращения.
  const idx = pool.map((_, i) => i);
  for (let i = idx.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [idx[i], idx[j]] = [idx[j], idx[i]];
  }
  return idx.slice(0, n);
}

export default function () {
  for (const m of meta) {
    const res = http.get(BASE + m.path, { tags: { kind: 'meta' } });
    check(res, { 'meta 200': (r) => r.status === 200 });
  }
  for (const i of shuffle(pkgs)) {
    const res = http.get(BASE + pool[i].path, { tags: { kind: 'pkg' } });
    check(res, { 'pkg 200': (r) => r.status === 200 });
  }
}
