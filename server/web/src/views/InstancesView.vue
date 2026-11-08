<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useQuery } from '@tanstack/vue-query'
import { Search, Server, Activity, CircleCheck, CircleDashed, ShieldX } from '@lucide/vue'
import { api, query } from '../lib/api'
import { useApps } from '../lib/queries'
import { fmtTime, pretty, metricsOf } from '../lib/format'
import { t } from '../i18n'
import AsyncState from '../components/AsyncState.vue'
import ModalPanel from '../components/ModalPanel.vue'
import type { Instance } from '../types'
const route = useRoute(), apps = useApps()
const appId = ref(String(route.query.app_id || '')), keyword = ref(''), status = ref(''), selected = ref<Instance>()
const instances = useQuery({ queryKey: computed(() => ['instances', appId.value]), queryFn: async ({ signal }) => (await api<Instance[] | null>(`/instances${query({ app_id: appId.value })}`, { signal })) || [], refetchInterval: 30000 })
const filtered = computed(() => (instances.data.value || []).filter(x => (!status.value || (status.value === 'online' ? x.online : !x.online)) && `${x.hostname} ${x.ips} ${x.runtime} ${x.agent_version}`.toLowerCase().includes(keyword.value.toLowerCase())))
const rejectedOf = (item: Instance) => Number(metricsOf(item.metrics).config_rejected || 0)
const rejected = computed(() => instances.data.value?.filter(x => rejectedOf(x) > 0).length || 0)
const online = computed(() => instances.data.value?.filter(x => x.online).length || 0)
</script>
<template>
  <div class="page-heading"><div><div class="eyebrow">{{ t('instances.eyebrow') }}</div><h1>{{ t('instances.title') }}</h1><p>{{ t('instances.subtitle') }}</p></div><span class="live-pill"><span class="dot"/>{{ t('instances.refresh') }}</span></div>
  <div class="summary-strip"><span><Server :size="18"/>{{ t('instances.total') }}<strong>{{ instances.data.value?.length || 0 }}</strong></span><span><CircleCheck :size="18" class="green-text"/>{{ t('common.online') }}<strong>{{ online }}</strong></span><span><CircleDashed :size="18"/>{{ t('common.offline') }}<strong>{{ (instances.data.value?.length || 0) - online }}</strong></span><span v-if="rejected"><ShieldX :size="18" class="danger-text"/>{{ t('instances.rejected') }}<strong class="danger-text">{{ rejected }}</strong></span></div>
  <section class="panel">
    <div class="filter-bar"><div class="search-input"><Search :size="16"/><input v-model="keyword" :aria-label="t('instances.search')" :placeholder="t('instances.searchPlaceholder')"/></div><select v-model="appId" :aria-label="t('instances.byApp')"><option value="">{{ t('common.allApps') }}</option><option v-for="app in apps.data.value" :key="app.id" :value="String(app.id)">{{ app.name }} / {{ app.env }}</option></select><select v-model="status" :aria-label="t('instances.byStatus')"><option value="">{{ t('instances.allStatuses') }}</option><option value="online">{{ t('common.online') }}</option><option value="offline">{{ t('common.offline') }}</option></select></div>
    <AsyncState :loading="instances.isPending.value" :error="instances.error.value" :empty="!filtered.length" :message="t('instances.empty')" @retry="instances.refetch()"><div class="table-wrap"><table>
      <thead><tr><th>{{ t('instances.colHost') }}</th><th>{{ t('instances.colApp') }}</th><th>{{ t('instances.colStatus') }}</th><th>{{ t('instances.colRuntime') }}</th><th>{{ t('instances.colVersion') }}</th><th>{{ t('instances.colHeartbeat') }}</th><th>{{ t('instances.colDetails') }}</th></tr></thead>
      <tbody><tr v-for="item in filtered" :key="item.agent_id"><td><strong>{{ item.hostname }}</strong><span class="cell-sub mono">{{ item.ips || item.agent_id }}</span></td><td><RouterLink class="text-link" :to="`/apps/${item.app_id}`">{{ item.app_name }}</RouterLink></td><td><span :class="['badge', item.online ? 'green' : 'neutral']"><span class="dot"/>{{ item.online ? t('common.online') : t('common.offline') }}</span><span v-if="rejectedOf(item)" class="badge red" :title="String(metricsOf(item.metrics).config_reject_reason || '')"><ShieldX :size="13"/>{{ t('instances.rejectedBadge', { n: rejectedOf(item) }) }}</span></td><td>{{ item.runtime }}<span class="cell-sub">{{ item.server_type }} · {{ item.os }}</span></td><td class="mono">{{ item.agent_version }}</td><td class="muted nowrap tabular">{{ fmtTime(item.last_heartbeat) }}</td><td><button class="text-link" @click="selected = item"><Activity :size="15"/>{{ t('instances.health') }}</button></td></tr></tbody>
    </table></div></AsyncState>
    <footer class="table-note">{{ t('instances.note') }}</footer>
  </section>
  <ModalPanel :open="!!selected" :title="t('instances.modalTitle')" wide @close="selected = undefined"><template v-if="selected">
    <dl class="detail-grid"><div><dt>{{ t('instances.host') }}</dt><dd>{{ selected.hostname }}</dd></div><div><dt>{{ t('instances.pid') }}</dt><dd class="tabular">{{ selected.pid }}</dd></div><div class="full"><dt>Agent ID</dt><dd class="mono break">{{ selected.agent_id }}</dd></div><div><dt>{{ t('instances.startMode') }}</dt><dd>{{ selected.start_mode }}</dd></div><div><dt>{{ t('instances.configVersion') }}</dt><dd class="mono break">{{ selected.config_version }}</dd></div><div><dt>{{ t('instances.registered') }}</dt><dd class="tabular">{{ fmtTime(selected.registered_at) }}</dd></div><div><dt>{{ t('instances.lastHeartbeat') }}</dt><dd class="tabular">{{ fmtTime(selected.last_heartbeat) }}</dd></div></dl>
    <p v-if="rejectedOf(selected)" class="alert error" role="alert"><ShieldX :size="18"/><span>{{ t('instances.rejectedAlert', { n: rejectedOf(selected), reason: String(metricsOf(selected.metrics).config_reject_reason || t('instances.unknownReason')) }) }}</span></p>
    <h3 class="section-label">{{ t('instances.metrics') }}</h3><pre>{{ pretty(selected.metrics || '{}') }}</pre>
  </template></ModalPanel>
</template>
