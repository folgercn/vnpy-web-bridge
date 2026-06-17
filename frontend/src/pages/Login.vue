<template>
  <div class="login-page">
    <n-card class="login-card" title="VnPy Web Bridge">
      <n-form :model="form" label-placement="top">
        <n-form-item label="用户名">
          <n-input v-model:value="form.username" />
        </n-form-item>
        <n-form-item label="密码">
          <n-input v-model:value="form.password" type="password" @keydown.enter="submit" />
        </n-form-item>
        <n-button type="primary" block :loading="loading" @click="submit">登录</n-button>
      </n-form>
      <n-alert v-if="error" type="error" class="error">{{ error }}</n-alert>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const auth = useAuthStore()
const loading = ref(false)
const error = ref('')
const form = reactive({ username: '', password: '' })

async function submit() {
  loading.value = true
  error.value = ''
  try {
    await auth.login(form.username, form.password)
    router.push('/dashboard')
  } catch (exc) {
    error.value = exc instanceof Error ? exc.message : '登录失败'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: grid;
  place-items: center;
}

.login-card {
  width: min(380px, calc(100vw - 32px));
}

.error {
  margin-top: 14px;
}
</style>
