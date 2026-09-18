<template>
  <div>
    <el-card shadow="never">
      <div class="toolbar">
        <el-select v-model="query.state" placeholder="状态" clearable style="width:130px" @change="load">
          <el-option v-for="(l, v) in stateLabel" :key="v" :label="l" :value="v" />
        </el-select>
        <el-select v-model="query.task_type" placeholder="类型" clearable style="width:150px" @change="load">
          <el-option v-for="t in taskTypes" :key="t.value" :label="t.label" :value="t.value" />
        </el-select>
        <el-button type="danger" plain :disabled="!selection.length" @click="batchCancel">
          取消选中 ({{ selection.length }})
        </el-button>
      </div>
      <el-table :data="rows" v-loading="loading" @selection-change="s => selection = s">
        <el-table-column type="selection" width="40" />
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="asset_value" label="资产" min-width="160" show-overflow-tooltip />
        <el-table-column label="类型" width="140">
          <template #default="{ row }">{{ typeLabel[row.task_type] || row.task_type }}</template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="stateTag[row.state]" size="small">{{ stateLabel[row.state] || row.state }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="进度" width="160">
          <template #default="{ row }">
            <el-progress :percentage="row.progress" :status="row.state === 'failed' ? 'exception' : undefined" />
          </template>
        </el-table-column>
        <el-table-column prop="stage" label="当前阶段" min-width="200" show-overflow-tooltip />
        <el-table-column prop="round_no" label="轮次" width="70" align="center" />
        <el-table-column label="漏洞数" width="90" align="center">
          <template #default="{ row }"><el-tag type="danger" size="small">{{ row.vuln_count }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="160">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button v-if="row.state === 'running'" size="small" text type="warning" @click="control(row, 'pause')">暂停</el-button>
            <el-button v-if="row.state === 'paused'" size="small" text type="success" @click="control(row, 'resume')">恢复</el-button>
            <el-button v-if="['pending', 'running', 'paused'].includes(row.state)" size="small" text type="danger" @click="control(row, 'cancel')">取消</el-button>
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
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'

const rows = ref([])
const total = ref(0)
const loading = ref(false)
const selection = ref([])
const query = reactive({ state: '', task_type: '', page: 1, page_size: 20 })

const stateLabel = { pending: '排队中', running: '运行中', paused: '已暂停', cancelled: '已取消',
  completed: '已完成', failed: '失败' }
const stateTag = { pending: 'info', running: 'primary', paused: 'warning', cancelled: 'info',
  completed: 'success', failed: 'danger' }
const taskTypes = [
  { value: 'full', label: '全流程' }, { value: 'recon_subdomain', label: '子域名枚举' },
  { value: 'recon_port', label: '端口扫描' }, { value: 'recon_fingerprint', label: '指纹识别' },
  { value: 'recon_jsapi', label: 'JS/API 提取' }, { value: 'recon_path', label: '目录爆破' },
  { value: 'vuln_web', label: 'Web 漏洞扫描' }, { value: 'vuln_cve', label: '组件 CVE' },
  { value: 'vuln_poc', label: 'POC 验证' }, { value: 'vuln_weakpass', label: '弱口令/未授权' }
]
const typeLabel = Object.fromEntries(taskTypes.map(t => [t.value, t.label]))

onMounted(load)

async function load() {
  loading.value = true
  try {
    const d = await api.get('/scans', { params: query })
    rows.value = d.items
    total.value = d.total
  } finally { loading.value = false }
}

async function control(row, action) {
  await api.post(`/scans/${row.id}/${action}`)
  ElMessage.success({ pause: '已暂停', resume: '已恢复', cancel: '已取消' }[action])
  load()
}

async function batchCancel() {
  await ElMessageBox.confirm('确认取消选中的任务？', '警告', { type: 'warning' })
  for (const t of selection.value) {
    if (['pending', 'running', 'paused'].includes(t.state)) {
      try { await api.post(`/scans/${t.id}/cancel`) } catch {}
    }
  }
  ElMessage.success('已提交取消')
  load()
}

function fmt(s) {
  if (!s) return '-'
  // 后端存的是 UTC naive 时间，当作 UTC 解析后转本地时区
  const d = new Date(s.endsWith('Z') ? s : s + 'Z')
  return d.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}
</script>

<style scoped>
.toolbar { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
</style>
