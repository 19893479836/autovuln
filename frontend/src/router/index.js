import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/login', component: () => import('../views/Login.vue') },
  {
    path: '/',
    component: () => import('../views/Layout.vue'),
    redirect: '/dashboard',
    children: [
      { path: 'dashboard', component: () => import('../views/Dashboard.vue'), meta: { title: '态势总览' } },
      { path: 'assets', component: () => import('../views/Assets.vue'), meta: { title: '资产管理' } },
      { path: 'assets/:id', component: () => import('../views/AssetDetail.vue'), meta: { title: '资产详情' } },
      { path: 'scans', component: () => import('../views/Scans.vue'), meta: { title: '扫描任务' } },
      { path: 'vulns', component: () => import('../views/Vulns.vue'), meta: { title: '漏洞管理' } },
      { path: 'vulns/:id', component: () => import('../views/VulnDetail.vue'), meta: { title: '漏洞详情' } },
      { path: 'reports', component: () => import('../views/Reports.vue'), meta: { title: '报告中心' } },
      { path: 'rules', component: () => import('../views/Rules.vue'), meta: { title: '规则库' } },
      { path: 'admin', component: () => import('../views/Admin.vue'), meta: { title: '系统管理' } }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to) => {
  const token = localStorage.getItem('token')
  if (to.path !== '/login' && !token) return '/login'
  if (to.path === '/login' && token) return '/dashboard'
  document.title = (to.meta.title ? to.meta.title + ' - ' : '') + 'AutoVuln'
})

export default router
