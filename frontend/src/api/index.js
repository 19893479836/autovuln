import axios from 'axios'
import { ElMessage } from 'element-plus'
import router from '../router'

const api = axios.create({ baseURL: '/api', timeout: 60000 })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (resp) => resp.data,
  (err) => {
    const status = err.response?.status
    const detail = err.response?.data?.detail
    let msg = err.message || '请求失败'

    if (Array.isArray(detail)) {
      // FastAPI 422 校验错误：[{loc, msg, ...}] → 友好中文
      msg = detail.map((e) => {
        const field = (e.loc || []).slice(-1)[0]
        const zhField = {
          username: '用户名', password: '密码', email: '邮箱', invite_code: '邀请码',
          title: '标题', name: '名称', targets: '目标列表', vuln_ids: '漏洞列表',
          to_state: '目标状态', action: '操作', fmt: '格式'
        }[field] || field
        if (e.type === 'string_too_short') {
          return `${zhField}至少需要 ${e.ctx?.min_length} 个字符`
        }
        if (e.type === 'string_too_long') {
          return `${zhField}不能超过 ${e.ctx?.max_length} 个字符`
        }
        return `${zhField}：${e.msg}`
      }).join('；')
    } else if (typeof detail === 'string') {
      msg = detail
    } else if (detail) {
      msg = JSON.stringify(detail)
    }

    if (status === 401) {
      localStorage.removeItem('token')
      router.push('/login')
      ElMessage.error('登录已过期，请重新登录')
    } else {
      ElMessage.error(msg)
    }
    return Promise.reject(err)
  }
)

export default api
