<template>
  <div>
    <el-card shadow="never" style="margin-bottom:16px">
      <el-tabs v-model="tab">
        <el-tab-pane label="审计日志" name="audit" />
        <el-tab-pane v-if="auth.isAdmin" label="用户管理" name="users" />
      </el-tabs>
    </el-card>

    <el-card shadow="never" v-if="tab === 'audit'">
      <el-table :data="logs" v-loading="loading" size="small">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="username" label="操作人" width="110" />
        <el-table-column prop="action" label="动作" width="160" />
        <el-table-column prop="target_type" label="对象" width="100" />
        <el-table-column prop="target_id" label="对象ID" width="80" />
        <el-table-column prop="detail" label="详情" min-width="240" show-overflow-tooltip />
        <el-table-column prop="ip" label="IP" width="130" />
        <el-table-column prop="created_at" label="时间" width="160">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
      </el-table>
      <el-pagination style="margin-top:12px;justify-content:flex-end" layout="total, prev, pager, next"
                     :total="total" :page-size="20" :current-page="page"
                     @current-change="p => { page = p; loadAudit() }" />
    </el-card>

    <el-card shadow="never" v-if="tab === 'users'">
      <el-table :data="users">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="username" label="用户名" width="140" />
        <el-table-column prop="email" label="邮箱" min-width="200" />
        <el-table-column label="角色" width="100">
          <template #default="{ row }">
            <el-tag :type="row.role === 'admin' ? 'danger' : 'info'" size="small">{{ row.role === 'admin' ? '管理员' : '用户' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="注册时间" width="160">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="160">
          <template #default="{ row }">
            <el-button size="small" text @click="setRole(row, row.role === 'admin' ? 'user' : 'admin')">
              {{ row.role === 'admin' ? '降为用户' : '设为管理员' }}
            </el-button>
            <el-button size="small" text :type="row.is_active ? 'danger' : 'success'" @click="toggleActive(row)">
              {{ row.is_active ? '停用' : '启用' }}
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api'
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()
const tab = ref('audit')
const logs = ref([])
const users = ref([])
const loading = ref(false)
const total = ref(0)
const page = ref(1)

watch(tab, load)
onMounted(load)

async function load() {
  if (tab.value === 'audit') loadAudit()
  else users.value = await api.get('/admin/users')
}

async function loadAudit() {
  loading.value = true
  try {
    const d = await api.get('/audit-logs', { params: { page: page.value, page_size: 20 } })
    logs.value = d.items
    total.value = d.total
  } finally { loading.value = false }
}

async function setRole(row, role) {
  await api.post(`/admin/users/${row.id}/set-role?role=${role}`)
  ElMessage.success('已更新')
  load()
}

async function toggleActive(row) {
  await api.post(`/admin/users/${row.id}/toggle-active`)
  ElMessage.success('已更新')
  load()
}

function fmt(s) { if (!s) return '-'; const d = new Date(s.endsWith('Z') ? s : s + 'Z'); return d.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }
</script>
