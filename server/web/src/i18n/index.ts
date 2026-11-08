import { ref, watch } from 'vue'
import zhCN from './zh-CN'
import enUS from './en-US'

// Small, dependency-free i18n: two typed catalogs (en-US must have exactly the zh-CN shape, so a
// missing translation fails `npm run build`), a reactive locale, and t() with {name} interpolation.
// Templates call t(...) directly; because t() reads `locale`, every caller re-renders on switch.
export type Locale = 'zh-CN' | 'en-US'
export const locales: { value: Locale; label: string; short: string }[] = [
  { value: 'zh-CN', label: '简体中文', short: '中' },
  { value: 'en-US', label: 'English', short: 'EN' },
]
const catalogs: Record<Locale, unknown> = { 'zh-CN': zhCN, 'en-US': enUS }
const STORAGE_KEY = 'rasp_locale'

function initial(): Locale {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved === 'zh-CN' || saved === 'en-US') return saved
  } catch { /* storage unavailable: fall through */ }
  return 'zh-CN'
}

export const locale = ref<Locale>(initial())
watch(locale, value => {
  document.documentElement.lang = value
  try { localStorage.setItem(STORAGE_KEY, value) } catch { /* per-viewer convenience only */ }
}, { immediate: true })

export function setLocale(value: Locale) { locale.value = value }

function lookup(tree: unknown, key: string): unknown {
  return key.split('.').reduce<unknown>((node, part) => (node && typeof node === 'object' ? (node as Record<string, unknown>)[part] : undefined), tree)
}

export function t(key: string, params?: Record<string, string | number>): string {
  const found = lookup(catalogs[locale.value], key) ?? lookup(catalogs['zh-CN'], key)
  const text = typeof found === 'string' ? found : key
  return params ? text.replace(/\{(\w+)\}/g, (_, name) => (name in params ? String(params[name]) : `{${name}}`)) : text
}

/**
 * Translation table for a fixed key set: { sql: t('attack.sql'), … } with live getters, so it can be
 * indexed or iterated (v-for) in templates and scripts alike and still follows locale changes.
 */
export function translated<K extends string>(prefix: string, keys: readonly K[]): Record<K, string> & Record<string, string> {
  const table = {} as Record<string, string>
  for (const key of keys) Object.defineProperty(table, key, { enumerable: true, get: () => t(`${prefix}.${key}`) })
  return table as Record<K, string> & Record<string, string>
}
