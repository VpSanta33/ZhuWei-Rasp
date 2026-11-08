<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useQuery } from '@tanstack/vue-query'
import { Search, Download, ChevronLeft, ChevronRight, SlidersHorizontal } from '@lucide/vue'
import { api, query } from '../lib/api'
import { useApps } from '../lib/queries'
import { attacks, statuses, exportCSV, fmtTime } from '../lib/format'
import { t } from '../i18n'
import AsyncState from '../components/AsyncState.vue'
import AlarmTable from '../components/AlarmTable.vue'
import AlarmDetail from '../components/AlarmDetail.vue'
import type { Alarm } from '../types'
const route = useRoute(), router = useRouter(), apps = useApps()
const selected = ref(''), keyword = ref(String(route.query.q || ''))
const pages = computed(() => Math.max(1, Math.ceil((alarms.data.value?.total || 0) / 20)))
const filters = computed(() => ({ app_id: String(route.query.app_id || ''), type: String(route.query.type || ''), action: String(route.query.action || ''), status: String(route.query.status || ''), q: String(route.query.q || ''), page: Math.max(1, Number(route.query.page) || 1), page_size: 20 }))
const alarms = useQuery({ queryKey: computed(() => ['alarms', filters.value]), queryFn: ({ signal }) => api<{ items: Alarm[] | null; total: number }>(`/alarms${query(filters.value)}`, { signal }) })
function filter(key: string, value: string) { void router.replace({ query: { ...route.query, [key]: value || undefined, page: undefined } }) }
function page(value: number) { void router.replace({ query: { ...route.query, page: value } }) }
watch(() => route.query.q, value => { keyword.value = String(value || '') })
const exporting = ref(false), exportError = ref('')
async function download() {
  exporting.value = true; exportError.value = ''
  try {
    // Export the complete current filter rather than silently exporting just the visible page.
    const rows: Alarm[] = []
    for (let current = 1; ; current++) {
      const result = await api<{ items: Alarm[] | null; total: number }>(`/alarms${query({ ...filters.value, page: current, page_size: 200 })}`)
      rows.push(...(result.items || []))
      if (!result.items?.length || rows.length >= result.total) break
    }
    exportCSV(t('alarms.csvName'), t('alarms.csvHeaders').split(','), rows.map(x => [x.event_id, attacks[x.attack_type] || x.attack_type, x.app_name, x.client_ip, t(`action.${x.action}`), statuses[x.status], x.url, fmtTime(x.event_time)]))
  } catch (e) { exportError.value = (e as Error).message } finally { exporting.value = false }
}
</script>
<template>
  <div class="page-heading"><div><div class="eyebrow">{{ t('alarms.eyebrow') }}</div><h1>{{ t('alarms.title') }}</h1><p>{{ t('alarms.subtitle') }}</p></div><button class="btn" :disabled="exporting || !alarms.data.value?.total" @click="download"><Download :size="16"/>{{ exporting ? t('alarms.exporting') : t('alarms.export') }}</button></div>
  <section class="panel">
    <form class="filter-bar" @submit.prevent="filter('q', keyword)">
      <div class="search-input"><Search :size="16"/><input v-model="keyword" :aria-label="t('alarms.search')" :placeholder="t('alarms.searchPlaceholder')"/><button class="search-submit" type="submit">{{ t('common.search') }}</button></div>
      <select :value="filters.app_id" :aria-label="t('alarms.byApp')" @change="filter('app_id', ($event.target as HTMLSelectElement).value)"><option value="">{{ t('common.allApps') }}</option><option v-for="app in apps.data.value" :key="app.id" :value="app.id">{{ app.name }} / {{ app.env }}</option></select>
      <select :value="filters.type" :aria-label="t('alarms.byType')" @change="filter('type', ($event.target as HTMLSelectElement).value)"><option value="">{{ t('alarms.allTypes') }}</option><option v-for="(label, key) in attacks" :key="key" :value="key">{{ label }}</option></select>
      <select :value="filters.action" :aria-label="t('alarms.byAction')" @change="filter('action', ($event.target as HTMLSelectElement).value)"><option value="">{{ t('alarms.allActions') }}</option><option value="block">{{ t('action.block') }}</option><option value="log">{{ t('action.log') }}</option></select>
      <select :value="filters.status" :aria-label="t('alarms.byStatus')" @change="filter('status', ($event.target as HTMLSelectElement).value)"><option value="">{{ t('alarms.allStatuses') }}</option><option v-for="(label, key) in statuses" :key="key" :value="key">{{ label }}</option></select>
    </form>
    <div class="table-caption"><span><SlidersHorizontal :size="15"/>{{ t('alarms.events') }}</span><span>{{ t('alarms.total', { n: alarms.data.value?.total || 0 }) }}</span></div>
    <p v-if="exportError" class="alert error" role="alert">{{ exportError }}</p>
    <AsyncState :loading="alarms.isPending.value" :error="alarms.error.value" :empty="!alarms.data.value?.items?.length" :message="t('alarms.empty')" @retry="alarms.refetch()"><AlarmTable :alarms="alarms.data.value?.items || []" @select="selected = $event.event_id"/></AsyncState>
    <footer class="pagination"><span>{{ t('alarms.perPage', { n: alarms.data.value?.total || 0 }) }}</span><div><button class="icon-btn" :aria-label="t('alarms.prev')" :disabled="filters.page <= 1" @click="page(filters.page - 1)"><ChevronLeft :size="17"/></button><span>{{ t('alarms.page', { page: filters.page, pages }) }}</span><button class="icon-btn" :aria-label="t('alarms.next')" :disabled="filters.page * 20 >= (alarms.data.value?.total || 0)" @click="page(filters.page + 1)"><ChevronRight :size="17"/></button></div></footer>
  </section>
  <AlarmDetail :id="selected" @close="selected = ''"/>
</template>
