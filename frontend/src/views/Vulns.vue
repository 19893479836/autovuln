<template>
  <div>
    <el-card shadow="never">
      <el-table :data="rows" v-loading="loading" @row-click="r => $router.push(`/vulns/${r.id}`)" style="cursor:pointer">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="title" label="漏洞标题" min-width="220" show-overflow-tooltip />
        <el-table-column label="等级" width="100">
          <template #default="{ row }">
            <el-tag :type="sevTag(row.severity)" size="small">{{ row.severity.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="vuln_type" label="类型" width="120" />
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="stateTag(row.state)" size="small">{{ stateLabel[row.state] || row.state }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="asset_value" label="资产" min-width="160" show-overflow-tooltip />
        <el-table-column prop="cve_id" label="CVE" width="130" />
        <el-table-column prop="assignee" label="负责人" width="90" />
        <el-table-column prop="last_seen_at" label="最近发现" width="160">
          <template #default="{ row }">{{ fmt(row.last_seen_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="110" fixed="right">
          <template #default="{ row }">
            <el-dropdown @command="cmd => doAction(cmd, row)" trigger="click">
              <el-button size="small" text type="primary">操作<el-icon><ArrowDown /></el-icon></el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="confirm">确认</el-dropdown-item>
                  <el-dropdown-item command="fixing">标记修复中</el-dropdown-item>
                  <el-dropdown-item command="fixed">标记已修复</el-dropdown-item>
                  <el-dropdown-item command="fp" divided>标记误报</el-dropdown-item>
                  <el-dropdown-item command="ignore">忽略</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination style="margin-top:12px;justify-content:flex-end" layout="total, prev, pager, next"
                     :total="total" :page-size="query.page_size" :current-page="query.page"
                     @current-change="p => { query.page = p; load() }" />
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api'

const rows = ref([])
const total = ref(0)
const loading = ref(false)
const query = reactive({ severity: '', state: '', keyword: '', page: 1, page_size: 20 })

const sevTag = s => ({ critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }[s] || '')
const stateTag = s => ({ pending: 'info', confirmed: 'danger', fixing: 'warning', fixed: 'success',
  verified: 'success', false_positive: '', ignored: 'info' }[s] || '')
const stateLabel = { pending: '待确认', confirmed: '已确认', fixing: '修复中', fixed: '已修复',
  verified: '复测通过', false_positive: '误报', ignored: '已忽略' }

onMounted(load)

async function load() {
  loading.value = true
  try {
    const d = await api.get('/vulns', { params: query })
    rows.value = d.items
    total.value = d.total
  } finally { loading.value = false }
}

async function doAction(cmd, row) {
  const map = { confirm: 'confirmed', fixing: 'fixing', fixed: 'fixed', fp: 'false_positive', ignore: 'ignored' }
  await api.post(`/vulns/${row.id}/transition`, { to_state: map[cmd], comment: '前端操作' })
  ElMessage.success('状态已更新')
  load()
}

function fmt(s) { if (!s) return '-'; const d = new Date(s.endsWith('Z') ? s : s + 'Z'); return d.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }
</script>
