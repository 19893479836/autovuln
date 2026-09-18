<template>
  <div>
    <el-card shadow="never">
      <div class="toolbar">
        <el-button type="primary" @click="importVisible = true">
          <el-icon><Upload /></el-icon>批量导入
        </el-button>
        <el-button @click="doAliveCheck" :loading="checking">
          <el-icon><Connection /></el-icon>存活监测
        </el-button>
        <el-input v-model="query.keyword" placeholder="搜索域名/IP/URL" clearable style="width:220px" @keyup.enter="load" />
        <el-select v-model="query.kind" placeholder="类型" clearable style="width:120px" @change="load">
          <el-option label="域名" value="domain" />
          <el-option label="IP" value="ip" />
          <el-option label="URL" value="url" />
        </el-select>
        <el-select v-model="query.status" placeholder="状态" clearable style="width:120px" @change="load">
          <el-option label="存活" value="active" />
          <el-option label="失效" value="offline" />
        </el-select>
        <el-button type="danger" plain :disabled="!selection.length" @click="batchDelete">
          删除选中 ({{ selection.length }})
        </el-button>
      </div>
      <el-table :data="rows" v-loading="loading" @selection-change="s => selection = s"
                @row-click="r => $router.push(`/assets/${r.id}`)" style="cursor:pointer">
        <el-table-column type="selection" width="40" />
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column label="资产" min-width="220">
          <template #default="{ row }">
            <el-tag size="small" :type="kindTag(row.kind)" style="margin-right:6px">{{ row.kind }}</el-tag>
            <b>{{ row.value }}</b>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="row.status === 'active' ? 'success' : row.status === 'offline' ? 'danger' : 'info'" size="small">
              {{ { active: '存活', offline: '失效', unknown: '未知' }[row.status] }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="重要级" width="90">
          <template #default="{ row }">
            <el-tag :type="{ high: 'danger', medium: 'warning', low: 'info' }[row.importance]" size="small">
              {{ { high: '高', medium: '中', low: '低' }[row.importance] }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="标签" min-width="140">
          <template #default="{ row }">
            <el-tag v-for="t in (row.tags || '').split(',').filter(Boolean)" :key="t" size="small" type="primary" style="margin:2px">{{ t }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="认证" width="80" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.has_cookie" type="warning" size="small">已配置</el-tag>
            <span v-else style="color:#bbb">-</span>
          </template>
        </el-table-column>
        <el-table-column prop="vuln_count" label="漏洞数" width="90" align="center">
          <template #default="{ row }">
            <el-badge :value="row.vuln_count" :hidden="!row.vuln_count" type="danger" />
          </template>
        </el-table-column>
        <el-table-column prop="last_seen_at" label="最近存活" width="160">
          <template #default="{ row }">{{ fmt(row.last_seen_at) }}</template>
        </el-table-column>
      </el-table>
      <el-pagination style="margin-top:12px;justify-content:flex-end" layout="total, prev, pager, next"
                     :total="total" :page-size="query.page_size" :current-page="query.page"
                     @current-change="p => { query.page = p; load() }" />
    </el-card>

    <!-- 导入对话框 -->
    <el-dialog v-model="importVisible" title="批量导入资产" width="560px">
      <el-form label-width="90px">
        <el-form-item label="目标列表">
          <el-input v-model="importForm.targets" type="textarea" :rows="8"
                    placeholder="每行一个：域名 / IP / URL&#10;自动去重合并，支持 project.example.com" />
        </el-form-item>
        <el-form-item label="标签">
          <el-input v-model="importForm.tags" placeholder="如：核心业务,生产环境（逗号分隔）" />
        </el-form-item>
        <el-form-item label="重要级">
          <el-radio-group v-model="importForm.importance">
            <el-radio value="high">高</el-radio>
            <el-radio value="medium">中</el-radio>
            <el-radio value="low">低</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="认证 Cookie">
          <el-input v-model="importForm.cookie" placeholder="登录后的会话 Cookie，如：session=abc123; uid=1（扫描时携带，可留空）" />
          <div class="hint">用于认证态扫描：配置后能扫描登录后才能访问的页面</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="importVisible = false">取消</el-button>
        <el-button type="primary" @click="doImport">导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'

const rows = ref([])
const total = ref(0)
const loading = ref(false)
const checking = ref(false)
const selection = ref([])
const importVisible = ref(false)
const query = reactive({ keyword: '', kind: '', status: '', page: 1, page_size: 20 })
const importForm = reactive({ targets: '', tags: '', importance: 'medium', cookie: '' })

onMounted(load)

async function load() {
  loading.value = true
  try {
    const d = await api.get('/assets', { params: query })
    rows.value = d.items
    total.value = d.total
  } finally { loading.value = false }
}

async function doImport() {
  const targets = importForm.targets.split('\n').map(s => s.trim()).filter(Boolean)
  if (!targets.length) return ElMessage.warning('请输入目标')
  const d = await api.post('/assets/import', {
    targets, tags: importForm.tags, importance: importForm.importance,
    cookie: importForm.cookie.trim()
  })
  ElMessage.success(`导入完成：新增 ${d.added}，已存在 ${d.existed}，无效 ${d.invalid}`)
  importVisible.value = false
  load()
}

async function doAliveCheck() {
  checking.value = true
  try {
    const d = await api.post('/assets/alive-check')
    ElMessage.success(`存活 ${d.active} / 失效 ${d.offline} / 共 ${d.total}`)
    load()
  } finally { checking.value = false }
}

async function batchDelete() {
  await ElMessageBox.confirm(`确认删除选中的 ${selection.value.length} 个资产？`, '警告', { type: 'warning' })
  for (const a of selection.value) await api.delete(`/assets/${a.id}`)
  ElMessage.success('已删除')
  load()
}

function kindTag(k) { return { domain: 'primary', ip: 'warning', url: 'success' }[k] || '' }
function fmt(s) { if (!s) return '-'; const d = new Date(s.endsWith('Z') ? s : s + 'Z'); return d.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }
</script>

<style scoped>
.toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 14px; flex-wrap: wrap; }
.hint { font-size: 12px; color: #999; line-height: 1.6; margin-top: 4px; }
</style>
