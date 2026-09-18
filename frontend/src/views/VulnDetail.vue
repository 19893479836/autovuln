<template>
  <div v-if="vuln">
    <el-page-header @back="$router.back()" :content="vuln.title" style="margin-bottom:16px">
      <template #extra>
        <el-tag :type="sevTag(vuln.severity)" style="margin-right:8px">{{ vuln.severity.toUpperCase() }}</el-tag>
        <el-tag :type="stateTag(vuln.state)">{{ stateLabel[vuln.state] || vuln.state }}</el-tag>
        <el-button type="primary" plain style="margin-left:12px" @click="showTrans = true">状态流转</el-button>
      </template>
    </el-page-header>

    <el-row :gutter="16">
      <el-col :span="16">
        <el-card shadow="never" style="margin-bottom:16px">
          <template #header><b>漏洞详情</b></template>
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item label="类型">{{ vuln.vuln_type }}</el-descriptions-item>
            <el-descriptions-item label="置信度">{{ confLabel[vuln.confidence] }}</el-descriptions-item>
            <el-descriptions-item label="CVSS 评分">{{ vuln.cvss_score || '-' }}</el-descriptions-item>
            <el-descriptions-item label="CVE">{{ vuln.cve_id || '-' }}</el-descriptions-item>
            <el-descriptions-item label="资产">
              <el-link type="primary" @click="$router.push(`/assets/${vuln.asset_id}`)">{{ vuln.asset_value }}</el-link>
            </el-descriptions-item>
            <el-descriptions-item label="负责人">{{ vuln.assignee || '-' }}</el-descriptions-item>
            <el-descriptions-item label="URL" :span="2">
              <el-link v-if="vuln.url" type="primary" :href="vuln.url" target="_blank">{{ vuln.url }}</el-link>
              <span v-else>-</span>
            </el-descriptions-item>
            <el-descriptions-item label="修复期限">{{ fmt(vuln.due_date) }}</el-descriptions-item>
            <el-descriptions-item label="首次发现">{{ fmt(vuln.first_seen_at) }}</el-descriptions-item>
            <el-descriptions-item label="最近发现">{{ fmt(vuln.last_seen_at) }}</el-descriptions-item>
            <el-descriptions-item label="已解决">{{ fmt(vuln.resolved_at) }}</el-descriptions-item>
          </el-descriptions>
        </el-card>

        <el-card shadow="never" style="margin-bottom:16px">
          <template #header><b>描述与修复建议</b></template>
          <p class="desc">{{ vuln.description || '暂无描述' }}</p>
          <el-alert v-if="vuln.fix_suggestion" :title="vuln.fix_suggestion" type="success" :closable="false" />
        </el-card>

        <el-card shadow="never">
          <template #header><b>请求 / 响应证据</b></template>
          <el-tabs>
            <el-tab-pane label="请求">
              <pre class="raw">{{ vuln.request_raw || '（无请求证据）' }}</pre>
            </el-tab-pane>
            <el-tab-pane label="响应">
              <pre class="raw">{{ vuln.response_raw || '（无响应证据）' }}</pre>
            </el-tab-pane>
            <el-tab-pane label="Payload">
              <pre class="raw">{{ vuln.payload || '（无 Payload）' }}</pre>
            </el-tab-pane>
          </el-tabs>
        </el-card>
      </el-col>

      <el-col :span="8">
        <el-card shadow="never" style="margin-bottom:16px">
          <template #header><b>参考链接</b></template>
          <div v-for="(ref, i) in vuln.reference" :key="i">
            <el-link type="primary" :href="ref" target="_blank" style="margin:4px 0">{{ ref }}</el-link>
          </div>
          <el-empty v-if="!vuln.reference?.length" description="暂无参考链接" :image-size="50" />
        </el-card>
        <el-card shadow="never" style="margin-bottom:16px">
          <template #header><b>状态流转历史</b></template>
          <el-timeline>
            <el-timeline-item v-for="(h, i) in history" :key="i" :timestamp="fmt(h.time)" :type="h.to === 'verified' ? 'success' : 'primary'">
              <b>{{ stateLabel[h.from] || '无' }}</b> → <b>{{ stateLabel[h.to] || h.to }}</b>
              <div class="hint">操作人：{{ h.operator }}{{ h.comment ? ' ｜ ' + h.comment : '' }}</div>
            </el-timeline-item>
          </el-timeline>
        </el-card>
        <el-card shadow="never">
          <template #header><b>误报反馈</b></template>
          <p class="hint">标记误报后系统将反哺规则库，持续降低误报率</p>
          <el-button type="danger" plain size="small" @click="fpFeedback">标记为误报</el-button>
        </el-card>
      </el-col>
    </el-row>

    <el-dialog v-model="showTrans" title="状态流转" width="420px">
      <el-form label-width="90px">
        <el-form-item label="目标状态">
          <el-select v-model="transForm.to_state" style="width:100%">
            <el-option v-for="(label, val) in stateLabel" :key="val" :label="label" :value="val" />
          </el-select>
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="transForm.comment" type="textarea" :rows="3" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showTrans = false">取消</el-button>
        <el-button type="primary" @click="doTransition">提交</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import api from '../api'

const route = useRoute()
const vulnId = route.params.id
const vuln = ref(null)
const history = ref([])
const showTrans = ref(false)
const transForm = reactive({ to_state: 'confirmed', comment: '' })

const sevTag = s => ({ critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }[s] || '')
const stateTag = s => ({ pending: 'info', confirmed: 'danger', fixing: 'warning', fixed: 'success',
  verified: 'success', false_positive: '', ignored: 'info' }[s] || '')
const stateLabel = { pending: '待确认', confirmed: '已确认', fixing: '修复中', fixed: '已修复',
  verified: '复测通过', false_positive: '误报', ignored: '已忽略' }
const confLabel = { high: '高（确认）', medium: '中（疑似）', low: '低（参考）' }

onMounted(async () => {
  vuln.value = await api.get(`/vulns/${vulnId}`)
  history.value = await api.get(`/vulns/${vulnId}/history`)
})

async function doTransition() {
  await api.post(`/vulns/${vulnId}/transition`, transForm)
  ElMessage.success('状态已更新')
  showTrans.value = false
  vuln.value = await api.get(`/vulns/${vulnId}`)
  history.value = await api.get(`/vulns/${vulnId}/history`)
}

async function fpFeedback() {
  await api.post(`/vulns/${vulnId}/false-positive-feedback`)
  ElMessage.success('已标记误报，规则库已记录反馈')
  vuln.value = await api.get(`/vulns/${vulnId}`)
  history.value = await api.get(`/vulns/${vulnId}/history`)
}

function fmt(s) { if (!s) return '-'; const d = new Date(s.endsWith('Z') ? s : s + 'Z'); return d.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }
</script>

<style scoped>
.raw { background: #0d1b3e; color: #9ecbff; padding: 14px; border-radius: 6px; font-size: 12px;
  white-space: pre-wrap; word-break: break-all; max-height: 320px; overflow: auto; }
.desc { color: #444; line-height: 1.8; }
.hint { color: #888; font-size: 12px; }
</style>
