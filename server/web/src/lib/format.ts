import { locale, translated } from '../i18n'

export const attacks = translated('attack', ['sql', 'command', 'readFile', 'writeFile', 'ssrf', 'deserialization', 'jndi'] as const)
export const statuses = translated('status', ['new', 'confirmed', 'false_positive', 'fixed', 'ignored'] as const)
export const modes = translated('mode', ['monitor', 'block', 'off'] as const)

export const fmtTime = (value?: number) => value ? new Intl.DateTimeFormat(locale.value, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(value) : '—'
export const number = (value: number) => new Intl.NumberFormat(locale.value).format(value)
export function metricsOf(raw?: string): Record<string, unknown> {
  try { const value = JSON.parse(raw || '{}'); return value && typeof value === 'object' ? value : {} } catch { return {} }
}
export function pretty(value: unknown) {
  if (typeof value === 'string') { try { return JSON.stringify(JSON.parse(value), null, 2) } catch { return value } }
  return JSON.stringify(value, null, 2)
}
export function exportCSV(filename: string, headers: string[], rows: unknown[][]) {
  const cell = (v: unknown) => {
    let text = String(v ?? '')
    if (/^[\s]*[=+@-]/.test(text)) text = `'${text}`
    return `"${text.replaceAll('"', '""')}"`
  }
  const url = URL.createObjectURL(new Blob(['﻿' + [headers, ...rows].map(r => r.map(cell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' }))
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
