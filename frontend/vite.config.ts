import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined
          if (id.includes('/naive-ui/')) return 'vendor-naive'
          if (id.includes('/@css-render/')) return 'vendor-css-render'
          if (id.includes('/vooks/') || id.includes('/vueuc/')) return 'vendor-naive-utils'
          if (id.includes('/lightweight-charts/')) return 'vendor-charts'
          if (id.includes('/@vicons/')) return 'vendor-icons'
          if (id.includes('/vue/') || id.includes('/vue-router/') || id.includes('/pinia/')) return 'vendor-vue'
          return 'vendor'
        }
      }
    }
  },
  test: {
    environment: 'jsdom'
  }
})
