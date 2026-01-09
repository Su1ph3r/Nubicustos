import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'dashboard',
    component: () => import('../views/DashboardView.vue')
  },
  {
    path: '/findings',
    name: 'findings',
    component: () => import('../views/FindingsView.vue')
  },
  {
    path: '/findings/:id',
    name: 'finding-detail',
    component: () => import('../views/FindingDetailView.vue'),
    props: true
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
