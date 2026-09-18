<template>
  <div class="login-wrap">
    <div class="login-card">
      <div class="logo">
        <el-icon :size="40" color="#1565c0"><Aim /></el-icon>
        <h1>AutoVuln</h1>
        <p>自动化漏洞挖掘平台</p>
      </div>
      <el-tabs v-model="mode" stretch>
        <el-tab-pane label="登录" name="login">
          <el-form :model="form" @keyup.enter="doLogin">
            <el-form-item>
              <el-input v-model="form.username" placeholder="用户名" size="large" :prefix-icon="'User'" />
            </el-form-item>
            <el-form-item>
              <el-input v-model="form.password" type="password" placeholder="密码" size="large" :prefix-icon="'Lock'" show-password />
            </el-form-item>
            <el-button type="primary" size="large" style="width:100%" :loading="loading" @click="doLogin">登 录</el-button>
          </el-form>
        </el-tab-pane>
        <el-tab-pane label="注册" name="register">
          <el-form :model="form" @keyup.enter="doRegister">
            <el-form-item>
              <el-input v-model="form.username" placeholder="用户名（3-32位）" size="large" />
            </el-form-item>
            <el-form-item>
              <el-input v-model="form.email" placeholder="邮箱" size="large" />
            </el-form-item>
            <el-form-item>
              <el-input v-model="form.password" type="password" placeholder="密码（6-64位）" size="large" show-password />
            </el-form-item>
            <el-form-item>
              <el-input v-model="form.inviteCode" placeholder="邀请码（必填）" size="large" />
            </el-form-item>
            <el-button type="primary" size="large" style="width:100%" :loading="loading" @click="doRegister">注 册</el-button>
          </el-form>
        </el-tab-pane>
      </el-tabs>
    </div>
    <div class="footer">安全研究用途 · 请确保对目标具有合法授权</div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const auth = useAuthStore()
const mode = ref('login')
const loading = ref(false)
const form = reactive({ username: '', email: '', password: '', inviteCode: '' })

async function doLogin() {
  if (!form.username || !form.password) return ElMessage.warning('请输入用户名和密码')
  loading.value = true
  try {
    await auth.login(form.username, form.password)
    ElMessage.success('登录成功')
    router.push('/dashboard')
  } finally { loading.value = false }
}

async function doRegister() {
  if (!form.username || !form.email || !form.password) return ElMessage.warning('请填写完整信息')
  if (!form.inviteCode) return ElMessage.warning('请输入邀请码')
  loading.value = true
  try {
    await auth.register(form.username, form.email, form.password, form.inviteCode)
    ElMessage.success('注册成功')
    router.push('/dashboard')
  } finally { loading.value = false }
}
</script>

<style scoped>
.login-wrap { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center;
  background: linear-gradient(135deg, #0d1b3e 0%, #1565c0 100%); }
.login-card { width: 400px; background: #fff; border-radius: 12px; padding: 36px 40px; box-shadow: 0 12px 40px rgba(0,0,0,.25); }
.logo { text-align: center; margin-bottom: 24px; }
.logo h1 { font-size: 28px; color: #1565c0; margin: 8px 0 4px; letter-spacing: 1px; }
.logo p { color: #888; font-size: 13px; }
.footer { color: rgba(255,255,255,.7); margin-top: 20px; font-size: 12px; }
</style>
