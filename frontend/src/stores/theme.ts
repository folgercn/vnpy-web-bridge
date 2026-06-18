import { computed, ref, watch } from 'vue'
import { defineStore } from 'pinia'

export type ThemeMode = 'system' | 'light' | 'dark'
export type EffectiveTheme = 'light' | 'dark'

const STORAGE_KEY = 'vnpy_theme_mode'

export const useThemeStore = defineStore('theme', () => {
  const mode = ref<ThemeMode>(readMode())
  const systemDark = ref(false)
  let mediaQuery: MediaQueryList | null = null

  const effectiveTheme = computed<EffectiveTheme>(() => {
    if (mode.value === 'system') return systemDark.value ? 'dark' : 'light'
    return mode.value
  })

  const isDark = computed(() => effectiveTheme.value === 'dark')

  function init() {
    if (typeof window === 'undefined') return
    if (mediaQuery) {
      applyTheme()
      return
    }
    mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    systemDark.value = mediaQuery.matches
    mediaQuery.addEventListener('change', updateSystemTheme)
    applyTheme()
  }

  function setMode(nextMode: ThemeMode) {
    mode.value = nextMode
  }

  function updateSystemTheme(event: MediaQueryListEvent) {
    systemDark.value = event.matches
  }

  function applyTheme() {
    if (typeof document === 'undefined') return
    document.documentElement.dataset.theme = effectiveTheme.value
    document.documentElement.style.colorScheme = effectiveTheme.value
  }

  watch(mode, (nextMode) => {
    if (typeof localStorage === 'undefined') return
    localStorage.setItem(STORAGE_KEY, nextMode)
  })

  watch(effectiveTheme, applyTheme)

  return { mode, effectiveTheme, isDark, init, setMode }
})

function readMode(): ThemeMode {
  if (typeof localStorage === 'undefined') return 'system'
  const saved = localStorage.getItem(STORAGE_KEY)
  if (saved === 'light' || saved === 'dark' || saved === 'system') return saved
  return 'system'
}
