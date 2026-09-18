import { defineStore } from 'pinia'
import api from '../api'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('token') || '',
    user: JSON.parse(localStorage.getItem('user') || 'null')
  }),
  getters: {
    isAdmin: (s) => s.user?.role === 'admin'
  },
  actions: {
    async login(username, password) {
      const data = await api.post('/auth/login', { username, password })
      this.setSession(data)
      return data
    },
    async register(username, email, password, inviteCode) {
      const data = await api.post('/auth/register', { username, email, password, invite_code: inviteCode })
      this.setSession(data)
      return data
    },
    setSession(data) {
      this.token = data.access_token
      this.user = data.user
      localStorage.setItem('token', data.access_token)
      localStorage.setItem('user', JSON.stringify(data.user))
    },
    logout() {
      this.token = ''
      this.user = null
      localStorage.removeItem('token')
      localStorage.removeItem('user')
    }
  }
})
