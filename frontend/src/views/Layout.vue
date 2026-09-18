<template>
  <el-container class="layout">
    <el-aside width="220px" class="aside">
      <div class="brand">
        <el-icon :size="26" color="#fff"><Aim /></el-icon>
        <span>AutoVuln</span>
      </div>
      <el-menu :default-active="route.path" router background-color="#0d1b3e" text-color="#a8b7d8"
               active-text-color="#ffffff">
        <el-menu-item index="/dashboard"><el-icon><Odometer /></el-icon>态势总览</el-menu-item>
        <el-menu-item index="/assets"><el-icon><Files /></el-icon>资产管理</el-menu-item>
        <el-menu-item index="/scans"><el-icon><VideoPlay /></el-icon>扫描任务</el-menu-item>
        <el-menu-item index="/vulns"><el-icon><Warning /></el-icon>漏洞管理</el-menu-item>
        <el-menu-item index="/reports"><el-icon><Document /></el-icon>报告中心</el-menu-item>
        <el-menu-item index="/rules"><el-icon><Collection /></el-icon>规则库</el-menu-item>
        <el-menu-item v-if="auth.isAdmin" index="/admin"><el-icon><Setting /></el-icon>系统管理</el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <div class="title">{{ route.meta.title || '' }}</div>
        <el-dropdown @command="onCommand">
          <span class="user">
            <el-icon><UserFilled /></el-icon>
            {{ auth.user?.username }}（{{ auth.user?.role === 'admin' ? '管理员' : '用户' }}）
            <el-icon><ArrowDown /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="logout">退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </el-header>
      <el-main class="main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

function onCommand(cmd) {
  if (cmd === 'logout') {
    auth.logout()
    router.push('/login')
  }
}
</script>

<style scoped>
.layout { height: 100vh; }
.aside { background: #0d1b3e; }
.brand { display: flex; align-items: center; gap: 10px; color: #fff; font-size: 20px; font-weight: 700;
  padding: 20px 24px; letter-spacing: 1px; }
.aside :deep(.el-menu) { border-right: none; }
.aside :deep(.el-menu-item.is-active) { background: #1565c0; }
.header { background: #fff; display: flex; align-items: center; justify-content: space-between;
  box-shadow: 0 1px 4px rgba(0,0,0,.08); }
.title { font-size: 16px; font-weight: 600; color: #333; }
.user { display: flex; align-items: center; gap: 6px; cursor: pointer; color: #555; }
.main { background: #f0f2f5; overflow-y: auto; }
</style>
