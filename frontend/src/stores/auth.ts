import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { login as loginApi, me, type UserInfo } from '../api/auth'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<UserInfo | null>(null)
  const token = ref(localStorage.getItem('access_token') || '')
  const isLoggedIn = computed(() => Boolean(token.value && user.value))
  const role = computed(() => user.value?.role || 'viewer')

  async function login(username: string, password: string) {
    const result = await loginApi(username, password)
    token.value = result.access_token
    user.value = result.user
    localStorage.setItem('access_token', token.value)
  }

  async function restore() {
    if (!token.value) return
    try {
      user.value = await me()
    } catch {
      logout()
    }
  }

  function logout() {
    token.value = ''
    user.value = null
    localStorage.removeItem('access_token')
  }

  return { user, token, role, isLoggedIn, login, restore, logout }
})
