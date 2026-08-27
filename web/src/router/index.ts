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

import { createRouter, createWebHistory } from 'vue-router'
import { getToken, UNAUTHORIZED_EVENT } from '../api'
import { markLoggedOut } from '../stores/auth'
import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'
import Remotes from '../views/Remotes.vue'
import Repos from '../views/Repos.vue'
import RepoDetail from '../views/RepoDetail.vue'
import Users from '../views/Users.vue'
import Audit from '../views/Audit.vue'
import Keys from '../views/Keys.vue'

// History mode с базой '/ui/' (совпадает с vite base и mount-поинтом /ui
// админского роутера). Гард: без токена — только /login; 401 от любого
// запроса (UNAUTHORIZED_EVENT из api.ts) выкидывает на /login.
const router = createRouter({
  history: createWebHistory('/ui/'),
  routes: [
    { path: '/', redirect: { name: 'dashboard' } },
    { path: '/login', name: 'login', component: Login },
    { path: '/dashboard', name: 'dashboard', component: Dashboard },
    { path: '/remotes', name: 'remotes', component: Remotes },
    { path: '/repos', name: 'repos', component: Repos },
    { path: '/repos/:id', name: 'repo-detail', component: RepoDetail },
    { path: '/users', name: 'users', component: Users },
    { path: '/audit', name: 'audit', component: Audit },
    { path: '/keys', name: 'keys', component: Keys },
  ],
})

router.beforeEach((to) => {
  if (to.name !== 'login' && getToken() === null) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
})

window.addEventListener(UNAUTHORIZED_EVENT, () => {
  markLoggedOut()
  if (router.currentRoute.value.name !== 'login') {
    void router.push({ name: 'login' })
  }
})

export default router
