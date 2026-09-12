// Хражевник — кеш-прокси и зеркало linux-репозиториев
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Общие помощники сценариев k6 (bench/k6/*.js): разбор списка URL и
// конструирование ступеней нагрузки. Почему ступени — отдельные
// сценарии constant-arrival-rate / constant-vus, а не один ramping:
// плато дают установившиеся значения, а тег scenario = имя ступени
// прямо в summary и CSV — коррелируется с сэмплами podman stats по
// времени без ручной разметки.

export const BASE = (__ENV.KHRZ_BASE || 'http://172.20.6.9:10002').replace(/\/+$/, '');

// parseUrls — строки «<путь>|<класс>», класс ∈ {meta, small, mid, large};
// «#» — комментарий. Класс фильтруется вторым аргументом (список через
// запятую, «*» — все).
export function parseUrls(text, classes) {
  const want = classes === '*' ? null
    : new Set(classes.split(',').map((s) => s.trim()).filter(Boolean));
  const out = [];
  for (let raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const sep = line.indexOf('|');
    const path = (sep === -1 ? line : line.slice(0, sep)).trim();
    const cls = sep === -1 ? '' : line.slice(sep + 1).trim();
    if (!path.startsWith('/')) continue;
    if (want && !want.has(cls)) continue;
    out.push({ path, cls });
  }
  return out;
}

// toSec — «90s»/«2m»/«1h30m» → секунды.
function toSec(s) {
  let total = 0;
  const re = /(\d+(?:\.\d+)?)(ms|s|m|h)/g;
  let m;
  while ((m = re.exec(s)) !== null) {
    const v = parseFloat(m[1]);
    total += m[2] === 'ms' ? v / 1000 : m[2] === 's' ? v : m[2] === 'm' ? v * 60 : v * 3600;
  }
  return Math.ceil(total);
}

// parseStages — «50:2m,200:2m» → [{value, hold}] для arrival- (value=rps)
// и VU-ступеней (value=VU).
function parseStages(spec) {
  return spec.split(',').map((chunk) => {
    const [value, hold] = chunk.split(':').map((s) => s.trim());
    const v = parseInt(value, 10);
    if (!Number.isFinite(v) || v <= 0 || !hold) {
      throw new Error(`ступень «${chunk}»: ожидался формат <N>:<длительность>`);
    }
    return { value: v, hold };
  });
}

// buildArrivalScenarios — ступени фиксированного RPS: каждая ступень —
// свой сценарий constant-arrival-rate, стартующий после предыдущей +
// KHRZ_GAP (по умолчанию 30s — окно остывания между ступенями).
// Возвращает готовый объект k6 options (scenarios + thresholds).
export function buildArrivalScenarios(spec) {
  const gap = toSec(__ENV.KHRZ_GAP || '30s');
  const pre = parseInt(__ENV.KHRZ_VUS || '300', 10);
  const max = parseInt(__ENV.KHRZ_MAX_VUS || '800', 10);
  const scenarios = {};
  const thresholds = {};
  let start = 0;
  for (const st of parseStages(spec)) {
    const name = `r${st.value}`;
    scenarios[name] = {
      executor: 'constant-arrival-rate',
      rate: st.value,
      timeUnit: '1s',
      duration: st.hold,
      preAllocatedVUs: Math.min(pre, st.value * 2),
      maxVUs: max,
      startTime: `${start}s`,
      gracefulStop: '10s',
    };
    thresholds[`http_req_failed{scenario:${name}}`] = ['rate<0.01'];
    start += toSec(st.hold) + gap;
  }
  return { scenarios, thresholds };
}

// buildVUScenarios — ступени фиксированных VU («клиентов»): каждая —
// сценарий constant-vus. Для сценария стриминга и apt-шторма, где
// единица нагрузки — клиент, а не запрос.
export function buildVUScenarios(spec) {
  const gap = toSec(__ENV.KHRZ_GAP || '30s');
  const scenarios = {};
  const thresholds = {};
  let start = 0;
  for (const st of parseStages(spec)) {
    const name = `v${st.value}`;
    scenarios[name] = {
      executor: 'constant-vus',
      vus: st.value,
      duration: st.hold,
      startTime: `${start}s`,
      gracefulStop: '10s',
    };
    thresholds[`http_req_failed{scenario:${name}}`] = ['rate<0.01'];
    start += toSec(st.hold) + gap;
  }
  return { scenarios, thresholds };
}
