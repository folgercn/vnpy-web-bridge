import { onBeforeUnmount, onMounted, ref } from 'vue'

export function useMediaQuery(query: string) {
  const matches = ref(false)
  let mediaQuery: MediaQueryList | null = null

  function update() {
    matches.value = Boolean(mediaQuery?.matches)
  }

  onMounted(() => {
    mediaQuery = window.matchMedia(query)
    update()
    mediaQuery.addEventListener('change', update)
  })

  onBeforeUnmount(() => {
    mediaQuery?.removeEventListener('change', update)
  })

  return matches
}
