<template>
  <n-config-provider :theme="theme.isDark ? darkTheme : null">
    <n-message-provider>
      <n-dialog-provider>
        <router-view />
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup lang="ts">
import { darkTheme } from 'naive-ui'
import { useThemeStore } from './stores/theme'

const theme = useThemeStore()
theme.init()
</script>
