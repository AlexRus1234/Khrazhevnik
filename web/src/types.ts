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

// Типы ответов /api/v1 (docs/SPECIFICATION.md §REST API). Durations —
// наносекунды (Go time.Duration в JSON), времена — RFC3339.

export interface Remote {
  id: number
  name: string
  ecosystem: string
  base_url: string
  mode: 'proxy' | 'mirror'
  enabled: boolean
  sync_interval: number
  include: string[]
  created_at: string
}

export interface Quota {
  max_bytes: number
  max_objects: number
}

export interface Repo {
  id: number
  name: string
  owner_id: number
  ecosystem: string
  quota: Quota
  created_at: string
}

export interface Perm {
  repo_id: number
  user_id: number
  created_at: string
}

export interface RepoObject {
  key: string
  size: number
  mod_time: string
}

export interface TaskSnapshot {
  id: string
  kind: string
  label: string
  state: 'running' | 'succeeded' | 'failed'
  phase: string
  current: string
  processed: number
  total: number
  percent: number
  speed_bps: number
  logs: string[]
  error?: string
  started_at: string
  finished_at?: string
}

export interface EcoStats {
  ecosystem: string
  packages: number
  hits: number
  misses: number
  hit_ratio: number
  stale_served: number
  negative_hits: number
  upstream_errors: number
  bytes_from_upstream: number
  bytes_to_clients: number
}

export interface CacheStats {
  hits: number
  misses: number
  hit_ratio: number
  stale_served: number
  negative_hits: number
  upstream_errors: number
  bytes_from_upstream: number
  bytes_to_clients: number
  packages: number
  per_ecosystem: EcoStats[]
}

export interface User {
  id: number
  username: string
  role: 'admin' | 'user'
  token_version: number
  created_at: string
}

export interface ApiToken {
  id: number
  name: string
  prefix: string
  scopes: string[]
  created_at: string
  expires_at: string
  revoked_at?: string
}

export interface AuditEntry {
  id: number
  at: string
  actor: string
  action: string
  object: string
  result: string
  detail: string
}
