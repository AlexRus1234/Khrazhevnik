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

// Форматтеры UI: байты, Go-durations (нс), скорости, времена.
// Дублировать библиотеку нечего — три чистые функции.

export function formatBytes(n: number): string {
  if (!Number.isFinite(n)) return '—'
  if (n < 1024) return `${n} Б`
  const units = ['КиБ', 'МиБ', 'ГиБ', 'ТиБ', 'ПиБ']
  let v = n
  let i = -1
  do {
    v /= 1024
    i++
  } while (v >= 1024 && i < units.length - 1)
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`
}

export function formatSpeed(bps: number): string {
  if (!Number.isFinite(bps) || bps <= 0) return '—'
  return `${formatBytes(bps)}/с`
}

// formatDuration — наносекунды → «1ч 5м 3с» (как в конфиге, но без
// дробных).
export function formatDuration(ns: number): string {
  if (!Number.isFinite(ns)) return '—'
  if (ns === 0) return 'только вручную'
  const totalSec = Math.round(ns / 1e9)
  const h = Math.floor(totalSec / 3600)
  const m = Math.floor((totalSec % 3600) / 60)
  const s = totalSec % 60
  const parts: string[] = []
  if (h > 0) parts.push(`${h}ч`)
  if (m > 0) parts.push(`${h > 0 ? String(m).padStart(2, '0') : m}м`)
  if (s > 0 || parts.length === 0) parts.push(`${parts.length > 0 ? String(s).padStart(2, '0') : s}с`)
  return parts.join(' ')
}

// parseDuration — «90m»/«1h30m»/«2h»/«45s»/«10» → наносекунды для
// time.Duration полей API. Суффиксы s/m/h/d; без суффикса — секунды.
// Возвращает null при мусоре (валидацию показывает поле формы).
export function parseDuration(s: string): number | null {
  const input = s.trim().toLowerCase()
  if (input === '') return 0
  const re = /(\d+(?:\.\d+)?)([smhd]?)/g
  let total = 0
  let matched = false
  let m: RegExpExecArray | null
  while ((m = re.exec(input)) !== null) {
    if (m[0] === '') break
    matched = true
    const v = parseFloat(m[1])
    if (!Number.isFinite(v)) return null
    const mult: Record<string, number> = {
      '': 1e9,
      s: 1e9,
      m: 60e9,
      h: 3600e9,
      d: 86400e9,
    }
    total += v * mult[m[2]]
  }
  if (!matched || !Number.isFinite(total) || total < 0) return null
  // time.Duration — int64 наносекунды; дробные округляем.
  return Math.round(total)
}

// formatTime — RFC3339 → локальное «27.08.2026 14:03:05». Нулевое
// время Go (0001-…) — пустая строка (бессрочные токены и т.п.).
export function formatTime(iso: string | undefined): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime()) || d.getFullYear() <= 1) return ''
  const p = (n: number): string => String(n).padStart(2, '0')
  return (
    `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()} ` +
    `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  )
}
