<template>
  <div>
    <el-row :gutter="16">
      <el-col :span="6" v-for="c in cards" :key="c.label">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-label">{{ c.label }}</div>
          <div class="stat-value" :style="{ color: c.color }">{{ c.value }}</div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="16" style="margin-top:16px">
      <el-col :span="14">
        <el-card shadow="never">
          <template #header><b>近 14 天漏洞发现趋势</b></template>
          <div ref="trendRef" style="height:300px"></div>
        </el-card>
      </el-col>
      <el-col :span="10">
        <el-card shadow="never">
          <template #header><b>漏洞等级分布</b></template>
          <div ref="sevRef" style="height:300px"></div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="16" style="margin-top:16px">
      <el-col :span="10">
        <el-card shadow="never">
          <template #header><b>漏洞类型 Top</b></template>
          <div ref="typeRef" style="height:280px"></div>
        </el-card>
      </el-col>
      <el-col :span="14">
        <el-card shadow="never">
          <template #header><b>高危资产 Top</b></template>
          <el-table :data="dash.top_assets" size="small" :show-header="false">
            <el-table-column prop="asset" />
            <el-table-column label="未修复高危数" width="140" align="right">
              <template #default="{ row }">
                <el-tag type="danger">{{ row.count }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref, nextTick } from 'vue'
import * as echarts from 'echarts'
import api from '../api'

const dash = reactive({ top_assets: [], top_types: [] })
const trendRef = ref()
const sevRef = ref()
const typeRef = ref()

const cards = reactive([
  { label: '资产总数', value: 0, color: '#1565c0' },
  { label: '漏洞总数', value: 0, color: '#e65100' },
  { label: '未修复漏洞', value: 0, color: '#c62828' },
  { label: '运行中任务', value: 0, color: '#2e7d32' }
])

onMounted(async () => {
  const d = await api.get('/dashboard')
  Object.assign(dash, d)
  cards[0].value = d.asset_total
  cards[1].value = d.vuln_total
  cards[2].value = d.open_vulns
  cards[3].value = d.task_running
  await nextTick()
  renderTrend(d.trend)
  renderSev(d.severity)
  renderTypes(d.top_types)
})

function renderTrend(trend) {
  const chart = echarts.init(trendRef.value)
  chart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: 40, right: 16, top: 20, bottom: 30 },
    xAxis: { type: 'category', data: Object.keys(trend) },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{
      type: 'line', smooth: true, areaStyle: { opacity: .2 },
      data: Object.values(trend), itemStyle: { color: '#1565c0' }
    }]
  })
}

function renderSev(sev) {
  const chart = echarts.init(sevRef.value)
  const colors = { critical: '#c62828', high: '#e65100', medium: '#f9a825', low: '#2e7d32', info: '#546e7a' }
  chart.setOption({
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie', radius: ['40%', '68%'],
      label: { formatter: '{b}: {c}' },
      data: Object.entries(sev).map(([k, v]) => ({
        name: k.toUpperCase(), value: v, itemStyle: { color: colors[k] }
      }))
    }]
  })
}

function renderTypes(types) {
  const chart = echarts.init(typeRef.value)
  chart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: 80, right: 20, top: 10, bottom: 30 },
    xAxis: { type: 'value', minInterval: 1 },
    yAxis: { type: 'category', data: types.map(t => t.type).reverse() },
    series: [{
      type: 'bar', data: types.map(t => t.count).reverse(),
      itemStyle: { color: '#1565c0' }, barWidth: 16
    }]
  })
}
</script>

<style scoped>
.stat-card { text-align: center; }
.stat-label { color: #888; font-size: 13px; }
.stat-value { font-size: 34px; font-weight: 700; margin-top: 6px; }
</style>
