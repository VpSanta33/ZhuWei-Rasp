<script setup lang="ts">
import { computed } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { RadioTower, CircleCheck, Clock3, ShieldX, CircleDashed } from '@lucide/vue'
import { api, query } from '../lib/api'
import { fmtTime, modes, pretty, metricsOf } from '../lib/format'
import AsyncState from './AsyncState.vue'
import { t } from '../i18n'
import type { Instance } from '../types'

// What the platform currently delivers to this app's agents (policy + whitelist + kill switch, signed on
// delivery), and whether each instance has actually picked it up.
const props = defineProps<{ appId: string }>()
type Effective = { version: string; mode: string; kill_switch: boolean; rules?: unknown[]; whitelist?: unknown[]; [key: string]: unknown }
const effective = useQuery({ queryKey: computed(() => ['effective', props.appId]), queryFn: ({ signal }) => api<Effective>(`/apps/${props.appId}/effective`, { signal }), refetchInterval: 15000 })
const instances = useQuery({ queryKey: computed(() => ['instances', props.appId]), queryFn: async ({ signal }) => (await api<Instance[] | null>(`/instances${query({ app_id: props.appId })}`, { signal })) || [], refetchInterval: 15000 })
type Sync = 'synced' | 'pending' | 'rejected' | 'offline'
function syncOf(item: Instance): Sync {
  if (!item.online) return 'offline'
  if (item.config_version === effective.data.value?.version) return 'synced'
  return Number(metricsOf(item.metrics).config_rejected || 0) > 0 ? 'rejected' : 'pending'
}
const labels: Record<Sync, { key: string; tone: string }> = {
  synced: { key: 'delivery.stateSynced', tone: 'green' }, pending: { key: 'delivery.statePending', tone: 'amber' },
  rejected: { key: 'delivery.stateRejected', tone: 'red' }, offline: { key: 'delivery.stateOffline', tone: 'neutral' },
}
const rows = computed(() => (instances.data.value || []).map(item => ({ item, sync: syncOf(item) })))
const online = computed(() => rows.value.filter(r => r.sync !== 'offline').length)
const synced = computed(() => rows.value.filter(r => r.sync === 'synced').length)
</script>
<template>
  <AsyncState :loading="effective.isPending.value" :error="effective.error.value" @retry="effective.refetch()">
    <template v-if="effective.data.value">
      <header class="panel-head flush"><div><h2>{{ t('delivery.title') }} <span class="badge neutral mono">{{ effective.data.value.version }}</span></h2><p>{{ t('delivery.subtitle') }}</p></div><span class="live-pill"><RadioTower :size="14"/>{{ t('delivery.auto') }}</span></header>
      <div class="summary-strip"><span><CircleCheck :size="18" class="green-text"/>{{ t('delivery.synced') }}<strong>{{ synced }} / {{ online }}</strong></span><span>{{ t('delivery.mode') }}<strong>{{ modes[effective.data.value.mode] || effective.data.value.mode }}</strong></span><span>{{ t('delivery.rules') }}<strong>{{ effective.data.value.rules?.length || 0 }}</strong></span><span>{{ t('delivery.whitelist') }}<strong>{{ effective.data.value.whitelist?.length || 0 }}</strong></span><span v-if="effective.data.value.kill_switch" class="danger-text"><ShieldX :size="18"/>{{ t('delivery.killSwitch') }}</span></div>
      <p v-if="online && synced < online" class="alert warning"><Clock3 :size="18"/><span>{{ t('delivery.pendingWarn', { n: online - synced }) }}</span></p>
      <AsyncState :loading="instances.isPending.value" :error="instances.error.value" :empty="!rows.length" :message="t('delivery.empty')" @retry="instances.refetch()">
        <div class="table-wrap"><table><caption class="sr-only">{{ t('delivery.caption') }}</caption><thead><tr><th>{{ t('delivery.host') }}</th><th>{{ t('delivery.state') }}</th><th>{{ t('delivery.version') }}</th><th>{{ t('delivery.heartbeat') }}</th></tr></thead><tbody><tr v-for="{ item, sync } in rows" :key="item.agent_id"><td><strong>{{ item.hostname }}</strong><span class="cell-sub mono">{{ item.ips || item.agent_id }}</span></td><td><span :class="['badge', labels[sync].tone]"><CircleDashed v-if="sync === 'offline'" :size="13"/><span v-else class="dot"/>{{ t(labels[sync].key) }}</span></td><td class="mono">{{ item.config_version || '—' }}</td><td class="muted nowrap tabular">{{ fmtTime(item.last_heartbeat) }}</td></tr></tbody></table></div>
      </AsyncState>
      <details class="effective-json"><summary>{{ t('delivery.json') }}</summary><pre>{{ pretty(effective.data.value) }}</pre></details>
    </template>
  </AsyncState>
</template>
