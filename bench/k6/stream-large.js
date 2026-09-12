// Хражевник — кеш-прокси и зеркало linux-репозиториев
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Сценарий B «stream-large»: пропускная способность отдачи одного
// крупного объекта (по умолчанию — первый класса large из urls.txt).
//   k6 run -e KHRZ_LARGE_URL='/apt/debian/.../big.deb' \
//          -e KHRZ_STAGES='1:2m,2:2m,4:2m,8:2m' stream-large.js
// VU = параллельный стример. Байты берём из Content-Length (прокси
// ставит его честно из каталога), а не из res.body: строковое тело
// после utf8-декодания не равно байтам, а латентность http_req_duration
// и так покрывает полное чтение тела.

import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { BASE, parseUrls, buildVUScenarios } from './common.js';

let url = __ENV.KHRZ_LARGE_URL;
if (!url) {
  const large = parseUrls(open(__ENV.KHRZ_URLS || './urls.txt'), 'large');
  if (large.length === 0) {
    throw new Error('нет объекта класса large (urls.txt) и не задан KHRZ_LARGE_URL');
  }
  url = large[0].path;
}

const streamBytes = new Counter('khz_stream_bytes');

export const options = buildVUScenarios(
  __ENV.KHRZ_STAGES || '1:2m,2:2m,4:2m,8:2m',
);

export default function () {
  const res = http.get(BASE + url);
  check(res, { 'status 200': (r) => r.status === 200 });
  const len = parseInt(res.headers['Content-Length'] || '0', 10);
  if (len > 0) streamBytes.add(len);
}
