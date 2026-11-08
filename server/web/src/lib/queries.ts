import { useQuery } from '@tanstack/vue-query'
import { api } from './api'
import type { AppInfo } from '../types'

export function useApps() {
  return useQuery({ queryKey: ['apps'], queryFn: async ({ signal }) => (await api<AppInfo[] | null>('/apps', { signal })) ?? [] })
}
