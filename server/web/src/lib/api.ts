import { ref } from 'vue'
import { t } from '../i18n'

// Tab-scoped bearer credentials; no credentials in URLs or persistent localStorage.
export const token = ref(sessionStorage.getItem('rasp_session') || '')
export const user = ref('')
export function clearSession() {
  token.value = ''; user.value = ''; sessionStorage.removeItem('rasp_session')
}
export function setSession(value: string, username: string) {
  token.value = value; user.value = username; sessionStorage.setItem('rasp_session', value)
}
export class ApiError extends Error {
  constructor(public status: number, message: string, public code = '', public data: unknown = null) { super(message) }
}
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body) headers.set('Content-Type', 'application/json')
  if (token.value) headers.set('Authorization', `Bearer ${token.value}`)
  const response = await fetch(`/api/v1${path}`, { ...options, headers, signal: options.signal ?? AbortSignal.timeout(20000) })
  if (response.status === 401 && path !== '/login') {
    clearSession()
    window.dispatchEvent(new Event('rasp:unauthorized'))
  }
  const data = await response.json().catch(() => null)
  if (!response.ok || !data || data.code !== 0) {
    const known: Record<string, string> = {
      'wrong username or password': 'errors.badLogin', 'login required': 'errors.loginRequired',
      'not found': 'errors.notFound', 'store error': 'errors.storeError',
    }
    const raw: string = data?.message || ''
    const message = known[raw] ? t(known[raw]) : raw || t('errors.requestFailed', { status: response.status })
    throw new ApiError(response.status, message, raw, data?.data ?? null)
  }
  return data.data as T
}
export function query(params: Record<string, unknown>) {
  const search = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => { if (value !== '' && value !== undefined && value !== null) search.set(key, String(value)) })
  return search.size ? `?${search}` : ''
}
export const write = <T = void>(path: string, method: string, body?: unknown, headers?: Record<string, string>) => api<T>(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
