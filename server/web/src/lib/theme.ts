import { computed, ref, watch } from 'vue'

// Theme preference (light / dark / follow the OS). The resolved theme is written to <html data-theme>,
// which switches the CSS token set; nothing else in the app needs to know about colours.
export type ThemePref = 'light' | 'dark' | 'system'
const STORAGE_KEY = 'rasp_theme'
function initial(): ThemePref {
  try { const v = localStorage.getItem(STORAGE_KEY); if (v === 'light' || v === 'dark' || v === 'system') return v } catch { /* ignore */ }
  return 'system'
}
const media = typeof window !== 'undefined' && window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null
const systemDark = ref(!!media?.matches)
media?.addEventListener('change', e => { systemDark.value = e.matches })

export const themePref = ref<ThemePref>(initial())
export const resolvedTheme = computed(() => (themePref.value === 'system' ? (systemDark.value ? 'dark' : 'light') : themePref.value))
watch(resolvedTheme, value => { document.documentElement.dataset.theme = value }, { immediate: true })
watch(themePref, value => { try { localStorage.setItem(STORAGE_KEY, value) } catch { /* ignore */ } })

const order: ThemePref[] = ['light', 'dark', 'system']
export function cycleTheme() { themePref.value = order[(order.indexOf(themePref.value) + 1) % order.length] }
