<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import ModalPanel from './ModalPanel.vue'
import AsyncState from './AsyncState.vue'
import { api, write } from '../lib/api'
import { attacks, statuses, fmtTime, pretty } from '../lib/format'
import { notify } from '../lib/feedback'
import { t } from '../i18n'
import type { Alarm } from '../types'
const props = defineProps<{ id: string }>()
defineEmits<{ close: [] }>()
const client = useQueryClient()
const busy = ref(false), error = ref(''), confirmWhitelist = ref(false)
watch(() => props.id, () => { error.value = ''; confirmWhitelist.value = false })
const detail = useQuery({ queryKey: computed(() => ['alarm', props.id]), queryFn: ({ signal }) => api<Alarm>(`/alarms/${encodeURIComponent(props.id)}`, { signal }), enabled: computed(() => !!props.id) })
const request = computed(() => {
  try { return (JSON.parse(detail.data.value?.raw || '{}').request || {}) as { async?: boolean; thread?: string } } catch { return {} }
})
async function update(status: string) {
  busy.value = true; error.value = ''
  try {
    await write(`/alarms/${encodeURIComponent(props.id)}/status`, 'POST', { status })
    await Promise.all([client.invalidateQueries({ queryKey: ['alarm'] }), client.invalidateQueries({ queryKey: ['alarms'] })])
    notify(t('alarmDetail.updated'))
  } catch (e) { error.value = (e as Error).message } finally { busy.value = false }
}
async function whitelist() {
  busy.value = true; error.value = ''
  try {
    await write(`/alarms/${encodeURIComponent(props.id)}/whitelist`, 'POST')
    await client.invalidateQueries(); confirmWhitelist.value = false; notify(t('alarmDetail.whitelisted'))
  } catch (e) { error.value = (e as Error).message } finally { busy.value = false }
}
</script>
<template>
  <ModalPanel :open="!!id" :title="t('alarmDetail.title')" wide @close="$emit('close')">
    <AsyncState :loading="detail.isPending.value" :error="detail.error.value" @retry="detail.refetch()">
      <template v-if="detail.data.value">
        <div class="detail-title"><h2>{{ attacks[detail.data.value.attack_type] || detail.data.value.attack_type }}</h2><span :class="['badge', detail.data.value.action === 'block' ? 'red' : 'amber']"><span class="dot"/>{{ t(`action.${detail.data.value.action === 'block' ? 'block' : 'log'}`) }}</span></div>
        <dl class="detail-grid">
          <div><dt>{{ t('alarmDetail.app') }}</dt><dd>{{ detail.data.value.app_name }}</dd></div>
          <div><dt>{{ t('alarmDetail.time') }}</dt><dd class="tabular">{{ fmtTime(detail.data.value.event_time) }}</dd></div>
          <div><dt>{{ t('alarmDetail.ip') }}</dt><dd class="mono">{{ detail.data.value.client_ip || '—' }}</dd></div>
          <div><dt>{{ t('alarmDetail.hostConfidence') }}</dt><dd>{{ detail.data.value.hostname }} / {{ detail.data.value.confidence }}%</dd></div>
          <div class="full"><dt>{{ t('alarmDetail.url') }}</dt><dd class="mono break">{{ detail.data.value.url || '—' }}</dd></div>
          <div class="full"><dt>{{ t('alarmDetail.reason') }}</dt><dd>{{ detail.data.value.reason || '—' }}</dd></div>
          <div><dt>{{ t('alarmDetail.algorithm') }}</dt><dd>{{ detail.data.value.algorithm }}</dd></div>
          <div><dt>{{ t('alarmDetail.thread') }}</dt><dd><span class="mono">{{ request.thread || t('alarmDetail.requestThread') }}</span><span v-if="request.async" class="badge neutral" :title="t('alarmDetail.asyncTitle')">{{ t('alarmDetail.async') }}</span></dd></div>
          <div><dt>{{ t('alarmDetail.status') }}</dt><dd>{{ statuses[detail.data.value.status] }}</dd></div>
        </dl>
        <h3 class="section-label">{{ t('alarmDetail.matched') }}</h3><pre>{{ detail.data.value.matched_input || t('alarmDetail.noMatched') }}</pre>
        <details><summary>{{ t('alarmDetail.raw') }}</summary><pre>{{ pretty(detail.data.value.raw || '{}') }}</pre></details>
        <p v-if="error" class="alert error" role="alert">{{ error }}</p>
        <div class="form-actions"><label>{{ t('alarmDetail.verdict') }} <select :value="detail.data.value.status" :disabled="busy" @change="update(($event.target as HTMLSelectElement).value)"><option v-for="(label, value) in statuses" :key="value" :value="value">{{ label }}</option></select></label><button class="btn" :disabled="busy || !detail.data.value.url" @click="confirmWhitelist = true">{{ t('alarmDetail.whitelist') }}</button></div>
        <div v-if="confirmWhitelist" class="confirm-box"><p>{{ t('alarmDetail.whitelistConfirm') }}</p><div class="actions"><button class="btn" :disabled="busy" @click="confirmWhitelist = false">{{ t('common.cancel') }}</button><button class="btn primary" :disabled="busy" @click="whitelist">{{ t('alarmDetail.confirmWhitelist') }}</button></div></div>
      </template>
    </AsyncState>
  </ModalPanel>
</template>
