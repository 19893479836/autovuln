<template>
  <div>
    <el-card shadow="never" style="margin-bottom:16px">
      <div class="toolbar">
        <el-tabs v-model="tab">
          <el-tab-pane label="漏洞规则" name="web" />
          <el-tab-pane label="指纹规则" name="fp" />
          <el-tab-pane label="POC 脚本" name="poc" />
        </el-tabs>
        <div class="actions">
          <el-upload :show-file-list="false" :http-request="doImport" accept=".json">
            <el-button :icon="'Upload'">导入规则包</el-button>
          </el-upload>
          <el-button @click="syncRemote">在线更新</el-button>
        </div>
      </div>
    </el-card>

    <el-card shadow="never">
      <!-- 漏洞规则 -->
      <el-table v-if="tab === 'web'" :data="webRules" v-loading="loading">
        <el-table-column prop="rule_key" label="规则键" min-width="180" show-overflow-tooltip />
        <el-table-column prop="name" label="名称" min-width="180" show-overflow-tooltip />
        <el-table-column prop="vuln_type" label="类型" width="110" />
        <el-table-column label="等级" width="90">
          <template #default="{ row }"><el-tag :type="sevTag(row.severity)" size="small">{{ row.severity }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="path" label="路径" min-width="140" show-overflow-tooltip />
        <el-table-column label="误报抑制" width="110">
          <template #default="{ row }">
            <el-tag v-if="row.fp_suppress" type="danger" size="small">已抑制 ({{ row.fp_count }})</el-tag>
            <span v-else-if="row.fp_count" class="hint">{{ row.fp_count }} 次</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-switch :model-value="row.enabled" @change="v => toggleRule(row)" />
          </template>
        </el-table-column>
      </el-table>

      <!-- 指纹规则 -->
      <el-table v-else-if="tab === 'fp'" :data="fpRules" v-loading="loading">
        <el-table-column prop="name" label="指纹名" min-width="150" />
        <el-table-column prop="category" label="类别" width="100" />
        <el-table-column prop="cpe" label="CPE" min-width="200" show-overflow-tooltip />
        <el-table-column label="状态" width="90">
          <template #default="{ row }"><el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '停用' }}</el-tag></template>
        </el-table-column>
      </el-table>

      <!-- POC -->
      <el-table v-else :data="pocList" v-loading="loading">
        <el-table-column prop="poc_key" label="POC 键" min-width="180" show-overflow-tooltip />
        <el-table-column prop="name" label="名称" min-width="180" show-overflow-tooltip />
        <el-table-column prop="vuln_type" label="类型" width="110" />
        <el-table-column label="等级" width="90">
          <template #default="{ row }"><el-tag :type="sevTag(row.severity)" size="small">{{ row.severity }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="script_type" label="脚本类型" width="100" />
        <el-table-column label="状态" width="90">
          <template #default="{ row }"><el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '停用' }}</el-tag></template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api'

const tab = ref('web')
const webRules = ref([])
const fpRules = ref([])
const pocList = ref([])
const loading = ref(false)

watch(tab, load)
onMounted(load)

async function load() {
  loading.value = true
  try {
    if (tab.value === 'web') webRules.value = await api.get('/rules/web')
    else if (tab.value === 'fp') fpRules.value = await api.get('/rules/fingerprint')
    else pocList.value = await api.get('/rules/poc')
  } finally { loading.value = false }
}

async function toggleRule(row) {
  await api.post(`/rules/web/${row.id}/toggle`)
  ElMessage.success('已切换')
  load()
}

async function doImport({ file }) {
  const fd = new FormData()
  fd.append('file', file)
  const d = await api.post('/rules/import', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
  ElMessage.success(`导入完成：Web ${d.added.web} / 指纹 ${d.added.fingerprint} / POC ${d.added.poc}`)
  load()
}

async function syncRemote() {
  const d = await api.post('/rules/sync-remote')
  ElMessage.success(d.msg)
  load()
}

function sevTag(s) { return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }[s] || '' }
</script>

<style scoped>
.toolbar { display: flex; justify-content: space-between; align-items: center; }
.actions { display: flex; gap: 10px; }
.hint { color: #999; font-size: 12px; }
</style>
