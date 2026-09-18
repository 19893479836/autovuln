<template>
  <div>
    <el-card shadow="never" style="margin-bottom:16px">
      <div class="toolbar">
        <el-form inline>
          <el-form-item label="标题">
            <el-input v-model="form.title" placeholder="报告标题" style="width:240px" />
          </el-form-item>
          <el-form-item label="格式">
            <el-select v-model="form.fmt" style="width:120px">
              <el-option label="HTML" value="html" />
              <el-option label="PDF" value="pdf" />
              <el-option label="JSON" value="json" />
              <el-option label="Excel" value="excel" />
            </el-select>
          </el-form-item>
          <el-form-item label="范围">
            <el-select v-model="form.asset_ids" multiple clearable filterable placeholder="全部资产" style="width:280px">
              <el-option v-for="a in assets" :key="a.id" :label="a.value" :value="a.id" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="generate" :loading="genLoading">生成报告</el-button>
          </el-form-item>
        </el-form>
      </div>
    </el-card>

    <el-card shadow="never">
      <template #header><b>历史报告</b></template>
      <el-table :data="rows" v-loading="loading">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="title" label="标题" min-width="220" show-overflow-tooltip />
        <el-table-column label="格式" width="90">
          <template #default="{ row }">
            <el-tag :type="{ html: 'primary', pdf: 'danger', json: 'info', excel: 'success' }[row.fmt]" size="small">{{ row.fmt.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="统计" min-width="200">
          <template #default="{ row }">
            <span class="stat">共 {{ row.stats?.total || 0 }} 漏洞</span>
            <el-tag v-if="row.stats?.by_severity?.critical" type="danger" size="small" style="margin-left:6px">危 {{ row.stats.by_severity.critical }}</el-tag>
            <el-tag v-if="row.stats?.by_severity?.high" type="warning" size="small" style="margin-left:4px">高 {{ row.stats.by_severity.high }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="scope_desc" label="范围" min-width="160" show-overflow-tooltip />
        <el-table-column prop="created_at" label="生成时间" width="160">
          <template #default="{ row }">{{ fmt(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-button size="small" type="primary" text @click="download(row)">下载</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api'

const rows = ref([])
const assets = ref([])
const loading = ref(false)
const genLoading = ref(false)
const form = reactive({ title: '漏洞扫描报告', fmt: 'html', asset_ids: [] })

onMounted(async () => {
  load()
  const d = await api.get('/assets', { params: { page_size: 200 } })
  assets.value = d.items
})

async function load() {
  loading.value = true
  try { rows.value = await api.get('/reports') } finally { loading.value = false }
}

async function generate() {
  genLoading.value = true
  try {
    const r = await api.post('/reports/generate', {
      title: form.title, fmt: form.fmt, asset_ids: form.asset_ids.length ? form.asset_ids : null
    })
    ElMessage.success('报告生成成功')
    load()
    download(r)
  } finally { genLoading.value = false }
}

function download(row) {
  const url = `${location.origin}/api/reports/${row.id}/download`
  const token = localStorage.getItem('token')
  fetch(url, { headers: { Authorization: `Bearer ${token}` } })
    .then(res => res.blob())
    .then(blob => {
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = row.file_path.split(/[\\/]/).pop()
      a.click()
      URL.revokeObjectURL(a.href)
    })
}

function fmt(s) { if (!s) return '-'; const d = new Date(s.endsWith('Z') ? s : s + 'Z'); return d.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }
</script>

<style scoped>
.toolbar { display: flex; }
.stat { color: #666; }
</style>
