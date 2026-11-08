<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { ShieldAlert, Bell, Save, ScrollText, KeyRound, Copy } from '@lucide/vue'
import { api, write } from '../lib/api'
import { fmtTime } from '../lib/format'
import { notify } from '../lib/feedback'
import { t } from '../i18n'
import AsyncState from '../components/AsyncState.vue'
import ModalPanel from '../components/ModalPanel.vue'
import type { Settings, Audit, SigningInfo } from '../types'
const client = useQueryClient(), busy = ref(false), error = ref(''), confirming = ref(false), dirty = ref(false)
const settings = useQuery({ queryKey: ['settings'], queryFn: ({ signal }) => api<Settings>('/settings', { signal }) })
const audit = useQuery({ queryKey: ['audit'], queryFn: async ({ signal }) => (await api<Audit[] | null>('/audit?limit=200', { signal })) || [] })
const form = reactive({ notify_webhook: '', notify_level: 'block', alarm_retention_days: '180' })
watch(() => settings.data.value, value => { if (value && !dirty.value) Object.assign(form, { notify_webhook: value.notify_webhook, notify_level: value.notify_level, alarm_retention_days: value.alarm_retention_days }) }, { immediate: true })
const signing = useQuery({ queryKey: ['signing'], queryFn: ({ signal }) => api<SigningInfo>('/signing', { signal }), staleTime: Infinity })
async function copyKey(value: string) { try { await navigator.clipboard.writeText(value); notify(t('settings.keyCopied')) } catch { error.value = t('common.copyFailed') } }
const killed = computed(() => settings.data.value?.kill_switch === 'true')
async function save(values: Partial<Settings>) {
  busy.value = true; error.value = ''
  try { await write('/settings', 'PUT', values); dirty.value = false; confirming.value = false; await client.invalidateQueries(); notify(t('settings.saved')) }
  catch (e) { error.value = (e as Error).message } finally { busy.value = false }
}
</script>
<template>
  <div class="page-heading"><div><div class="eyebrow">{{ t('settings.eyebrow') }}</div><h1>{{ t('settings.title') }}</h1><p>{{ t('settings.subtitle') }}</p></div></div>
  <AsyncState :loading="settings.isPending.value" :error="settings.error.value" @retry="settings.refetch()">
    <section class="panel settings-panel"><header class="settings-heading"><span class="mini-icon red-icon"><ShieldAlert :size="20"/></span><div><h2>{{ t('settings.killTitle') }}</h2><p>{{ t('settings.killSub') }}</p></div><span :class="['badge', killed ? 'red' : 'green']"><span class="dot"/>{{ killed ? t('settings.killed') : t('settings.notKilled') }}</span></header><div class="settings-bottom"><p>{{ killed ? t('settings.killedText') : t('settings.notKilledText') }}</p><button :class="['btn', killed ? 'primary' : 'danger']" :disabled="busy" @click="confirming = true">{{ killed ? t('settings.restore') : t('settings.enable') }}</button></div></section>
    <section class="panel settings-panel"><header class="settings-heading"><span class="mini-icon info-icon"><Bell :size="20"/></span><div><h2>{{ t('settings.notifyTitle') }}</h2><p>{{ t('settings.notifySub') }}</p></div></header><form class="settings-form" @submit.prevent="save({ ...form, alarm_retention_days: String(form.alarm_retention_days) })" @input="dirty = true"><label class="field">{{ t('settings.webhook') }}<input v-model="form.notify_webhook" type="url" placeholder="https://…" maxlength="2000"/><small>{{ t('settings.webhookHint') }}</small></label><div class="form-row"><label class="field">{{ t('settings.level') }}<select v-model="form.notify_level" @change="dirty = true"><option value="block">{{ t('settings.levelBlock') }}</option><option value="all">{{ t('settings.levelAll') }}</option></select></label><label class="field">{{ t('settings.retention') }}<input v-model="form.alarm_retention_days" type="number" min="1" max="3650" required/></label></div><div class="form-actions"><button class="btn primary" :disabled="busy || !dirty"><Save :size="16"/>{{ busy ? t('settings.saving') : t('settings.save') }}</button></div></form></section>
  </AsyncState>
  <section class="panel settings-panel"><header class="settings-heading"><span class="mini-icon green-icon"><KeyRound :size="20"/></span><div><h2>{{ t('settings.signingTitle') }}</h2><p>{{ t('settings.signingSub') }}</p></div><span v-if="signing.data.value" class="badge green"><span class="dot"/>{{ signing.data.value.alg }}</span></header><AsyncState :loading="signing.isPending.value" :error="signing.error.value" @retry="signing.refetch()"><template v-if="signing.data.value"><div class="settings-body"><dl class="detail-grid"><div><dt>{{ t('settings.keyId') }}</dt><dd class="mono">{{ signing.data.value.key_id }}</dd></div><div><dt>{{ t('settings.agentKey') }}</dt><dd class="mono">policy.public_key</dd></div></dl><div class="code-head"><span>{{ t('settings.publicKey') }}</span><button class="text-link" @click="copyKey(signing.data.value.public_key)"><Copy :size="15"/>{{ t('settings.copyKey') }}</button></div><pre class="break">{{ signing.data.value.public_key }}</pre><p class="alert info"><KeyRound :size="18"/><span>{{ t('settings.keyHint') }}</span></p></div></template></AsyncState></section>
  <p v-if="error" class="alert error" role="alert">{{ error }}</p>
  <section class="panel"><header class="panel-head"><div><h2><ScrollText :size="18"/>{{ t('settings.auditTitle') }}</h2><p>{{ t('settings.auditSub') }}</p></div></header><AsyncState :loading="audit.isPending.value" :error="audit.error.value" :empty="!audit.data.value?.length" :message="t('settings.auditEmpty')" @retry="audit.refetch()"><div class="table-wrap"><table><thead><tr><th>{{ t('settings.colTime') }}</th><th>{{ t('settings.colUser') }}</th><th>{{ t('settings.colAction') }}</th><th>{{ t('settings.colTarget') }}</th><th>{{ t('settings.colDetail') }}</th></tr></thead><tbody><tr v-for="item in audit.data.value" :key="item.id"><td class="muted nowrap tabular">{{ fmtTime(item.at) }}</td><td>{{ item.user }}</td><td><span class="badge neutral mono">{{ item.action }}</span></td><td class="wrap-cell">{{ item.target }}</td><td class="wrap-cell muted">{{ item.detail || '—' }}</td></tr></tbody></table></div></AsyncState></section>
  <ModalPanel :open="confirming" :title="killed ? t('settings.restoreModal') : t('settings.killModal')" @close="!busy && (confirming = false)"><p>{{ killed ? t('settings.restoreConfirm') : t('settings.killConfirm') }}</p><p v-if="!killed" class="alert warning">{{ t('settings.killWarn') }}</p><p v-if="error" class="alert error" role="alert">{{ error }}</p><div class="form-actions"><button class="btn" :disabled="busy" @click="confirming = false">{{ t('common.cancel') }}</button><button :class="['btn', killed ? 'primary' : 'danger solid']" :disabled="busy" @click="save({ kill_switch: killed ? 'false' : 'true' })">{{ busy ? t('settings.updating') : t('settings.confirmAction') }}</button></div></ModalPanel>
</template>
