<script setup lang="ts">
import { computed, ref } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { Search, Download, Package, Layers } from '@lucide/vue'
import { api, query } from '../lib/api'
import { useApps } from '../lib/queries'
import { exportCSV } from '../lib/format'
import { t } from '../i18n'
import AsyncState from '../components/AsyncState.vue'
import ModalPanel from '../components/ModalPanel.vue'
import type { ComponentInfo, ComponentUse } from '../types'
const apps = useApps(), appId = ref(''), keyword = ref(''), submitted = ref(''), multiOnly = ref(false), selected = ref<ComponentInfo>()
const inventory = useQuery({ queryKey: computed(() => ['components', appId.value, submitted.value]), queryFn: async ({ signal }) => (await api<ComponentInfo[] | null>(`/components${query({ app_id: appId.value, q: submitted.value, limit: 5000 })}`, { signal })) || [] })
const versions = computed(() => {
  const map = new Map<string, Set<string>>()
  for (const x of inventory.data.value || []) { const key = `${x.group}:${x.artifact}`; if (!map.has(key)) map.set(key, new Set()); map.get(key)!.add(x.version) }
  return map
})
const filtered = computed(() => (inventory.data.value || []).filter(x => !multiOnly.value || (versions.value.get(`${x.group}:${x.artifact}`)?.size || 0) > 1))
const uses = useQuery({ queryKey: computed(() => ['component-uses', selected.value?.group, selected.value?.artifact, selected.value?.version]), queryFn: async ({ signal }) => (await api<ComponentUse[] | null>(`/components/uses${query({ group: selected.value?.group, artifact: selected.value?.artifact, version: selected.value?.version })}`, { signal })) || [], enabled: computed(() => !!selected.value) })
function download() { exportCSV(t('components.csvName'), t('components.csvHeaders').split(','), filtered.value.map(x => [x.group, x.artifact, x.version, x.source, x.sha1, x.apps, x.instances])) }
</script>
<template>
  <div class="page-heading"><div><div class="eyebrow">{{ t('components.eyebrow') }}</div><h1>{{ t('components.title') }}</h1><p>{{ t('components.subtitle') }}</p></div><button class="btn" :disabled="!filtered.length" @click="download"><Download :size="16"/>{{ t('components.export') }}</button></div>
  <div class="summary-strip"><span><Package :size="18"/>{{ t('components.kinds') }}<strong>{{ versions.size }}</strong></span><span><Layers :size="18"/>{{ t('components.versions') }}<strong>{{ inventory.data.value?.length || 0 }}</strong></span></div>
  <section class="panel">
    <form class="filter-bar" @submit.prevent="submitted = keyword"><div class="search-input"><Search :size="16"/><input v-model="keyword" :aria-label="t('components.search')" :placeholder="t('components.searchPlaceholder')"/><button class="search-submit">{{ t('common.search') }}</button></div><select v-model="appId" :aria-label="t('components.byApp')"><option value="">{{ t('common.allApps') }}</option><option v-for="app in apps.data.value" :key="app.id" :value="String(app.id)">{{ app.name }} / {{ app.env }}</option></select><label class="checkbox-label"><input v-model="multiOnly" type="checkbox"/>{{ t('components.multiOnly') }}</label></form>
    <AsyncState :loading="inventory.isPending.value" :error="inventory.error.value" :empty="!filtered.length" :message="t('components.empty')" @retry="inventory.refetch()"><div class="table-wrap"><table>
      <thead><tr><th>{{ t('components.colComponent') }}</th><th>{{ t('components.colVersion') }}</th><th>{{ t('components.colSource') }}</th><th>{{ t('components.colApps') }}</th><th>{{ t('components.colInstances') }}</th><th>{{ t('components.colUses') }}</th></tr></thead>
      <tbody><tr v-for="item in filtered" :key="`${item.group}:${item.artifact}:${item.version}`"><td><strong class="mono">{{ item.artifact }}</strong><span class="cell-sub mono">{{ item.group || t('components.unknownGroup') }}</span></td><td><span class="badge neutral mono">{{ item.version || t('components.unknown') }}</span><span v-if="(versions.get(`${item.group}:${item.artifact}`)?.size || 0) > 1" class="cell-sub amber-text">{{ t('components.multiple') }}</span></td><td>{{ item.source }}</td><td class="wrap-cell">{{ item.apps }}</td><td class="tabular">{{ item.instances }}</td><td><button class="text-link" @click="selected = item">{{ t('components.viewUses') }}</button></td></tr></tbody>
    </table></div></AsyncState>
    <footer class="table-note">{{ t('components.note') }}</footer>
  </section>
  <ModalPanel :open="!!selected" :title="selected ? `${selected.artifact} · ${selected.version}` : t('components.usesTitle')" wide @close="selected = undefined"><p class="muted break mono">{{ t('components.sha1', { v: selected?.sha1 || t('components.notReported') }) }}</p><AsyncState :loading="uses.isPending.value" :error="uses.error.value" :empty="!uses.data.value?.length" @retry="uses.refetch()"><div class="table-wrap"><table><thead><tr><th>{{ t('components.app') }}</th><th>{{ t('components.host') }}</th><th>{{ t('components.path') }}</th></tr></thead><tbody><tr v-for="(item, i) in uses.data.value" :key="i"><td>{{ item.app_name }} / {{ item.env }}</td><td>{{ item.hostname }}</td><td class="mono wrap-cell">{{ item.path }}</td></tr></tbody></table></div></AsyncState></ModalPanel>
</template>
