<template>
  <div v-if="asset">
    <el-page-header @back="$router.back()" :content="asset.value" style="margin-bottom:16px">
      <template #extra>
        <el-tag :type="asset.status === 'active' ? 'success' : 'danger'" style="margin-right:8px">
          {{ { active: '存活', offline: '失效', unknown: '未知' }[asset.status] }}
        </el-tag>
        <el-button type="primary" @click="showScan = true">发起扫描</el-button>
      </template>
    </el-page-header>

    <el-row :gutter="16">
      <el-col :span="6">
        <el-card shadow="never" style="margin-bottom:16px">
          <template #header><b>资产信息</b></template>
          <el-descriptions :column="1" size="small">
            <el-descriptions-item label="类型">{{ asset.kind }}</el-descriptions-item>
            <el-descriptions-item label="重要级">{{ asset.importance }}</el-descriptions-item>
            <el-descriptions-item label="标签">{{ asset.tags || '-' }}</el-descriptions-item>
            <el-descriptions-item label="创建时间">{{ fmt(asset.created_at) }}</el-descriptions-item>
            <el-descriptions-item label="最近存活">{{ fmt(asset.last_seen_at) }}</el-descriptions-item>
            <el-descriptions-item label="漏洞总数">
              <el-tag type="danger">{{ asset.vuln_count }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="认证 Cookie">
              <el-tag v-if="asset.has_cookie" type="warning" size="small">已配置（认证态扫描）</el-tag>
              <span v-else style="color:#bbb">未配置</span>
              <el-button size="small" text type="primary" style="margin-left:6px" @click="showAuth = true">
                {{ asset.has_cookie ? '修改' : '配置' }}
              </el-button>
            </el-descriptions-item>
          </el-descriptions>
        </el-card>
        <el-card shadow="never">
          <template #header>
            <div style="display:flex;justify-content:space-between;align-items:center">
              <b>扫描轮次</b>
              <el-button size="small" @click="loadRounds">刷新</el-button>
            </div>
          </template>
          <el-empty v-if="!rounds.length" description="暂无扫描记录" :image-size="60" />
          <div v-for="r in rounds" :key="r.round_no" class="round-row">
            <span>第 {{ r.round_no }} 轮</span>
            <el-tag size="small" v-for="t in r.types" :key="t" style="margin-left:4px">{{ t }}</el-tag>
            <el-button size="small" text type="primary" @click="compareWith(r.round_no)">对比</el-button>
          </div>
        </el-card>
      </el-col>
      <el-col :span="18">
        <el-card shadow="never">
          <template #header>
            <div style="display:flex;justify-content:space-between;align-items:center">
              <b>聚合信息</b>
              <div>
                <el-radio-group v-model="recKind" size="small" @change="loadRecords">
                  <el-radio-button value="">全部</el-radio-button>
                  <el-radio-button value="subdomain">子域名</el-radio-button>
                  <el-radio-button value="port">端口</el-radio-button>
                  <el-radio-button value="fingerprint">指纹</el-radio-button>
                  <el-radio-button value="jsapi">接口</el-radio-button>
                  <el-radio-button value="path">路径</el-radio-button>
                </el-radio-group>
              </div>
            </div>
          </template>
          <el-table :data="records" size="small" v-loading="recLoading">
            <el-table-column label="类型" width="110">
              <template #default="{ row }">
                <el-tag size="small" :type="kindMap[row.kind] || 'info'">{{ kindLabel[row.kind] || row.kind }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="key" label="键值" min-width="200" show-overflow-tooltip />
            <el-table-column prop="value" label="描述" min-width="140" show-overflow-tooltip />
            <el-table-column prop="source" label="来源" width="120" />
            <el-table-column prop="discovered_at" label="发现时间" width="160">
              <template #default="{ row }">{{ fmt(row.discovered_at) }}</template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <!-- 扫描对话框 -->
    <el-dialog v-model="showScan" title="发起扫描" width="480px">
      <el-form label-width="100px">
        <el-form-item label="扫描类型">
          <el-select v-model="scanForm.task_type" style="width:100%">
            <el-option label="全流程扫描（推荐）" value="full" />
            <el-option label="子域名枚举" value="recon_subdomain" />
            <el-option label="端口扫描" value="recon_port" />
            <el-option label="指纹识别" value="recon_fingerprint" />
            <el-option label="JS/API 提取" value="recon_jsapi" />
            <el-option label="动态爬虫(Playwright)" value="recon_crawler" />
            <el-option label="目录爆破" value="recon_path" />
            <el-option label="Web 漏洞扫描" value="vuln_web" />
            <el-option label="组件 CVE 检测" value="vuln_cve" />
            <el-option label="POC 验证" value="vuln_poc" />
            <el-option label="弱口令/未授权" value="vuln_weakpass" />
          </el-select>
        </el-form-item>
        <el-form-item label="请求间隔(ms)">
          <el-input-number v-model="scanForm.rate_limit" :min="50" :max="60000" :step="50" />
          <div class="hint">限速保护：值越大对目标压力越小</div>
        </el-form-item>
        <el-form-item label="任务名称">
          <el-input v-model="scanForm.name" placeholder="可选" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showScan = false">取消</el-button>
        <el-button type="primary" @click="doScan">启动</el-button>
      </template>
    </el-dialog>

    <!-- 认证 Cookie 配置对话框 -->
    <el-dialog v-model="showAuth" :title="asset.has_cookie ? '修改认证 Cookie' : '配置认证 Cookie'" width="520px">
      <el-form label-width="100px">
        <el-form-item label="Cookie">
          <el-input v-model="authForm.cookie" type="textarea" :rows="3"
                    placeholder="登录后的会话 Cookie，如：session=abc123; uid=1&#10;扫描时随所有请求携带，用于扫描登录后的页面" />
        </el-form-item>
        <el-form-item label="说明">
          <div class="hint">从浏览器开发者工具 → Network → 请求头复制 Cookie 值。仅用于你拥有授权测试权限的目标。</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAuth = false">取消</el-button>
        <el-button v-if="asset.has_cookie" @click="clearAuth">清除</el-button>
        <el-button type="primary" @click="saveAuth">保存</el-button>
      </template>
    </el-dialog>

    <!-- 轮次对比对话框 -->
    <el-dialog v-model="showCompare" title="跨轮次对比" width="720px">
      <div v-if="compareResult">
        <el-alert :title="`第 ${compareBase} 轮 → 第 ${compareResult.round_b} 轮：新增 ${compareResult.summary.added} / 已修复 ${compareResult.summary.fixed} / 复发 ${compareResult.summary.regressed}`"
                  type="info" :closable="false" style="margin-bottom:12px" />
        <el-tabs>
          <el-tab-pane label="新增" :name="'new'">
            <el-table :data="compareResult.added" size="small">
              <el-table-column prop="title" label="漏洞" min-width="200" />
              <el-table-column prop="severity" label="等级" width="90">
                <template #default="{ row }"><el-tag :type="sevTag(row.severity)" size="small">{{ row.severity }}</el-tag></template>
              </el-table-column>
            </el-table>
          </el-tab-pane>
          <el-tab-pane label="已修复" :name="'fixed'">
            <el-table :data="compareResult.fixed" size="small">
              <el-table-column prop="title" label="漏洞" min-width="200" />
              <el-table-column prop="severity" label="等级" width="90" />
            </el-table>
          </el-tab-pane>
          <el-tab-pane label="复发" :name="'reg'">
            <el-table :data="compareResult.regressed" size="small">
              <el-table-column prop="title" label="漏洞" min-width="200" />
              <el-table-column prop="severity" label="等级" width="90" />
            </el-table>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import api from '../api'

const route = useRoute()
const assetId = route.params.id
const asset = ref(null)
const records = ref([])
const recKind = ref('')
const recLoading = ref(false)
const rounds = ref([])
const showScan = ref(false)
const showCompare = ref(false)
const showAuth = ref(false)
const compareBase = ref(1)
const compareResult = ref(null)
const scanForm = reactive({ task_type: 'full', rate_limit: 300, name: '' })
const authForm = reactive({ cookie: '' })

const kindMap = { subdomain: 'primary', port: 'warning', fingerprint: 'success', jsapi: '', path: 'danger' }
const kindLabel = { subdomain: '子域名', port: '端口', fingerprint: '指纹', jsapi: '接口', path: '路径', cert: '证书' }

onMounted(async () => {
  asset.value = await api.get(`/assets/${assetId}`)
  loadRecords()
  loadRounds()
})

async function loadRecords() {
  recLoading.value = true
  try { records.value = await api.get(`/assets/${assetId}/records`, { params: { kind: recKind.value } }) }
  finally { recLoading.value = false }
}

async function loadRounds() {
  rounds.value = await api.get(`/scans/rounds/${assetId}`)
}

async function doScan() {
  const d = await api.post('/scans', { asset_id: Number(assetId), ...scanForm })
  ElMessage.success(`任务 #${d.id} 已创建，轮次 ${d.round_no}`)
  showScan.value = false
  loadRounds()
}

async function compareWith(roundNo) {
  compareBase.value = roundNo
  const target = roundNo > 1 ? roundNo - 1 : roundNo + 1
  compareResult.value = await api.post(`/vulns/round-compare?asset_id=${assetId}`,
    { round_a: target, round_b: roundNo })
  showCompare.value = true
}

async function saveAuth() {
  await api.put(`/assets/${assetId}`, { cookie: authForm.cookie.trim() })
  ElMessage.success(asset.value.has_cookie ? '认证 Cookie 已更新' : '认证 Cookie 已配置')
  showAuth.value = false
  asset.value = await api.get(`/assets/${assetId}`)
}

async function clearAuth() {
  await api.put(`/assets/${assetId}`, { cookie: '' })
  ElMessage.success('已清除认证 Cookie')
  showAuth.value = false
  asset.value = await api.get(`/assets/${assetId}`)
}

function sevTag(s) { return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }[s] || '' }
function fmt(s) { if (!s) return '-'; const d = new Date(s.endsWith('Z') ? s : s + 'Z'); return d.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }
</script>

<style scoped>
.round-row { display: flex; align-items: center; gap: 6px; padding: 6px 0; border-bottom: 1px dashed #eee; }
.hint { font-size: 12px; color: #999; line-height: 1.6; }
</style>
