<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from 'vue'
import { useRoute, useRouter, onBeforeRouteLeave } from 'vue-router'
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { ArrowLeft, Copy, Save, Trash2, ShieldCheck, Terminal, Settings2, Code2, Eye, EyeOff, ShieldAlert, RadioTower, RotateCcw } from '@lucide/vue'
import { api, write, ApiError } from '../lib/api'
import { attacks, modes, pretty } from '../lib/format'
import { notify } from '../lib/feedback'
import { t } from '../i18n'
import AsyncState from '../components/AsyncState.vue'
import ModalPanel from '../components/ModalPanel.vue'
import DeliveryPanel from '../components/DeliveryPanel.vue'
import type { Install, Policy, BlockConfirm } from '../types'
const route = useRoute(), router = useRouter(), client = useQueryClient()
const id = computed(() => String(route.params.id))
const detail = useQuery({ queryKey: computed(() => ['app', id.value]), queryFn: ({ signal }) => api<Install>(`/apps/${id.value}`, { signal }) })
const policy = useQuery({ queryKey: computed(() => ['policy', id.value]), queryFn: ({ signal }) => api<{ policy: Policy; policy_rev: number }>(`/apps/${id.value}/policy`, { signal }) })
const blockGate = ref<BlockConfirm>(), typedName = ref('')
const tab = ref('install'), draft = ref<Policy>(), json = ref(''), dirty = ref(false), advanced = ref(false), busy = ref(false), error = ref(''), confirmation = ref(''), deleting = ref(false), showSecrets = ref(false)
watch(() => policy.data.value, data => { if (data && !dirty.value) { draft.value = JSON.parse(JSON.stringify(data.policy)); json.value = pretty(data.policy) } }, { immediate: true })
const properties = computed(() => showSecrets.value ? detail.data.value?.properties : detail.data.value?.properties.replace(/^app\.secret=.*$/m, 'app.secret=••••••••••••••••'))
function beforeUnload(event: BeforeUnloadEvent) { if (dirty.value) event.preventDefault() }
window.addEventListener('beforeunload', beforeUnload)
onBeforeUnmount(() => window.removeEventListener('beforeunload', beforeUnload))
onBeforeRouteLeave(() => !dirty.value || window.confirm(t('appDetail.leaveConfirm')))
function switchEditor() {
  if (!advanced.value) json.value = pretty(draft.value)
  else { try { draft.value = JSON.parse(json.value); error.value = '' } catch { error.value = t('appDetail.invalidJson'); return } }
  advanced.value = !advanced.value
}
async function copy(value: string) { try { await navigator.clipboard.writeText(value); notify(t('common.copied')) } catch { error.value = t('common.copyFailed') } }
function review() {
  try {
    if (advanced.value) draft.value = JSON.parse(json.value)
    if (!draft.value || typeof draft.value !== 'object' || !['off', 'monitor', 'block'].includes(draft.value.mode)) throw new Error(t('appDetail.needMode'))
    error.value = ''; confirmation.value = 'policy'
  } catch (e) { error.value = e instanceof SyntaxError ? t('appDetail.invalidJsonRetry') : (e as Error).message }
}
// The server answers 409 confirm_required when rules would start blocking; it then expects the app name
// in X-Rasp-Confirm. The second step lists exactly which rules will block and how many instances are online.
async function save(confirmName?: string) {
  busy.value = true; error.value = ''
  try {
    await write(`/apps/${id.value}/policy`, 'PUT', draft.value, confirmName ? { 'X-Rasp-Confirm': confirmName } : undefined)
    dirty.value = false; confirmation.value = ''; blockGate.value = undefined; typedName.value = ''
    await client.invalidateQueries(); notify(t('appDetail.published'))
  } catch (e) {
    if (e instanceof ApiError && e.status === 409 && e.code === 'confirm_required') {
      blockGate.value = e.data as BlockConfirm; typedName.value = ''; confirmation.value = 'block'
    } else error.value = (e as Error).message
  } finally { busy.value = false }
}
const nameMatches = computed(() => !!blockGate.value && typedName.value.trim() === blockGate.value.app)
// Loads the built-in default policy into the editor; nothing is published until “发布策略”.
async function loadDefault() {
  busy.value = true; error.value = ''
  try {
    draft.value = await api<Policy>('/policy/default'); json.value = pretty(draft.value); dirty.value = true
    notify(t('appDetail.defaultLoaded'))
  } catch (e) { error.value = (e as Error).message } finally { busy.value = false }
}
async function remove() {
  busy.value = true; error.value = ''
  try { await write(`/apps/${id.value}`, 'DELETE'); dirty.value = false; deleting.value = false; await client.invalidateQueries(); await router.push('/apps'); notify(t('appDetail.deleted')) }
  catch (e) { error.value = (e as Error).message } finally { busy.value = false }
}
</script>
<template>
  <RouterLink to="/apps" class="back-link"><ArrowLeft :size="16"/>{{ t('appDetail.back') }}</RouterLink>
  <AsyncState :loading="detail.isPending.value" :error="detail.error.value" @retry="detail.refetch()"><template v-if="detail.data.value">
    <div class="page-heading"><div><div class="eyebrow">{{ t('appDetail.eyebrow') }}</div><h1>{{ detail.data.value.app.name }}<span class="badge neutral">{{ detail.data.value.app.env }}</span></h1><p>{{ detail.data.value.app.description || t('appDetail.fallback') }}</p></div><button class="btn danger" @click="deleting = true"><Trash2 :size="16"/>{{ t('appDetail.delete') }}</button></div>
    <div class="tabs" role="tablist" :aria-label="t('appDetail.tabs')"><button v-for="item in [{ id: 'install', name: 'appDetail.tabInstall', icon: Terminal }, { id: 'policy', name: 'appDetail.tabPolicy', icon: ShieldCheck }, { id: 'delivery', name: 'appDetail.tabDelivery', icon: RadioTower }]" :id="`tab-${item.id}`" :key="item.id" role="tab" :aria-selected="tab === item.id" :aria-controls="`panel-${item.id}`" :class="{ active: tab === item.id }" @click="tab = item.id"><component :is="item.icon" :size="16"/>{{ t(item.name) }}</button><RouterLink :to="`/instances?app_id=${id}`">{{ t('appDetail.viewInstances') }}</RouterLink><RouterLink :to="`/alarms?app_id=${id}`">{{ t('appDetail.viewAlarms') }}</RouterLink></div>
    <section v-if="tab === 'install'" id="panel-install" role="tabpanel" aria-labelledby="tab-install" class="panel detail-panel">
      <div class="step-heading"><span>01</span><div><h2>{{ t('appDetail.step1') }}</h2><p>{{ t('appDetail.step1Text') }}</p></div></div>
      <div class="code-head"><span>rasp.properties</span><div class="actions"><button class="text-link" @click="showSecrets = !showSecrets"><EyeOff v-if="showSecrets" :size="15"/><Eye v-else :size="15"/>{{ showSecrets ? t('appDetail.hideSecret') : t('appDetail.showSecret') }}</button><button class="text-link" @click="copy(detail.data.value.properties)"><Copy :size="15"/>{{ t('appDetail.copyConfig') }}</button></div></div>
      <pre>{{ properties }}</pre>
      <div class="step-heading"><span>02</span><div><h2>{{ t('appDetail.step2') }}</h2><p>{{ t('appDetail.step2Text') }}</p></div></div>
      <div class="code-head"><span>Shell</span><button class="text-link" @click="copy(detail.data.value.command)"><Copy :size="15"/>{{ t('appDetail.copyCommand') }}</button></div>
      <pre>{{ detail.data.value.command }}</pre>
      <div class="alert info"><ShieldCheck :size="18"/><span>{{ t('appDetail.installHint') }}</span></div>
    </section>
    <section v-else-if="tab === 'delivery'" id="panel-delivery" role="tabpanel" aria-labelledby="tab-delivery" class="panel detail-panel"><DeliveryPanel :app-id="id"/></section>
    <section v-else id="panel-policy" role="tabpanel" aria-labelledby="tab-policy" class="panel detail-panel"><AsyncState :loading="policy.isPending.value" :error="policy.error.value" @retry="policy.refetch()"><template v-if="draft">
      <header class="panel-head flush"><div><h2>{{ t('appDetail.policyTitle') }} <span class="badge neutral">REV {{ policy.data.value?.policy_rev }}</span></h2><p>{{ t('appDetail.policySub') }}</p></div><div class="heading-actions"><button class="btn" :disabled="busy" @click="loadDefault"><RotateCcw :size="16"/>{{ t('appDetail.restoreDefault') }}</button><button class="btn" @click="switchEditor"><Code2 v-if="!advanced" :size="16"/><Settings2 v-else :size="16"/>{{ advanced ? t('appDetail.basic') : t('appDetail.advanced') }}</button></div></header>
      <label v-if="advanced" class="field">{{ t('appDetail.fullJson') }}<textarea v-model="json" rows="26" class="code-editor" spellcheck="false" @input="dirty = true"/></label>
      <template v-else>
        <div class="policy-mode"><h3>{{ t('appDetail.runMode') }}</h3><div class="mode-grid"><label v-for="mode in ['monitor', 'block', 'off'] as const" :key="mode" :class="['mode-option', { selected: draft.mode === mode }]"><input v-model="draft.mode" type="radio" name="mode" :value="mode" @change="dirty = true"/><strong>{{ modes[mode] }}</strong><small>{{ mode === 'monitor' ? t('appDetail.modeMonitorText') : mode === 'block' ? t('appDetail.modeBlockText') : t('appDetail.modeOffText') }}</small></label></div></div>
        <h3 class="section-label">{{ t('appDetail.checks') }}</h3>
        <div class="check-list"><div v-for="(check, type) in draft.checks" :key="type"><span>{{ attacks[type] || type }}<small class="mono">{{ type }}</small></span><label class="toggle-label"><input v-model="check.enabled" type="checkbox" @change="dirty = true"/>{{ t('appDetail.enableCheck') }}</label><label><span class="sr-only">{{ t('appDetail.maxAction', { name: attacks[type] || type }) }}</span><select v-model="check.action" @change="dirty = true"><option value="block">{{ t('appDetail.allowBlock') }}</option><option value="log">{{ t('appDetail.logOnly') }}</option><option value="ignore">{{ t('appDetail.ignore') }}</option></select></label></div></div>
        <p class="muted help-text">{{ t('appDetail.capHint') }}</p>
      </template>
      <div class="form-actions"><span v-if="dirty" class="amber-text">{{ t('appDetail.unsaved') }}</span><button class="btn primary" :disabled="busy || !dirty" @click="review"><Save :size="16"/>{{ t('appDetail.publish') }}</button></div>
    </template></AsyncState></section>
    <p v-if="error" class="alert error" role="alert">{{ error }}</p>
    <ModalPanel :open="confirmation === 'policy'" :title="t('appDetail.confirmTitle')" @close="!busy && (confirmation = '')"><p>{{ t('appDetail.confirmText', { app: detail.data.value.app.name, mode: draft ? modes[draft.mode] : '' }) }}</p><p v-if="draft?.mode === 'block'" class="alert warning">{{ t('appDetail.confirmBlockWarn') }}</p><p v-if="draft?.mode === 'off'" class="alert warning">{{ t('appDetail.confirmOffWarn') }}</p><p v-if="error" class="alert error" role="alert">{{ error }}</p><div class="form-actions"><button class="btn" :disabled="busy" @click="confirmation = ''">{{ t('common.cancel') }}</button><button class="btn primary" :disabled="busy" @click="save()">{{ busy ? t('appDetail.publishing') : t('appDetail.confirmPublish') }}</button></div></ModalPanel>
    <ModalPanel :open="confirmation === 'block' && !!blockGate" :title="t('appDetail.gateTitle')" @close="!busy && (confirmation = '')"><template v-if="blockGate"><p class="alert warning"><ShieldAlert :size="18"/><span>{{ t('appDetail.gateText', { rules: blockGate.rules.length, app: blockGate.app, env: blockGate.env, instances: blockGate.instances }) }}</span></p><ul class="rule-chips" :aria-label="t('appDetail.gateRules')"><li v-for="rule in blockGate.rules" :key="rule" class="badge red mono">{{ rule }}</li></ul><label class="field"><span>{{ t('appDetail.gateInput', { app: blockGate.app }) }}</span><input v-model="typedName" autocomplete="off" spellcheck="false" :placeholder="blockGate.app" @keydown.enter.prevent="nameMatches && !busy && save(blockGate.app)"/></label><p v-if="error" class="alert error" role="alert">{{ error }}</p><div class="form-actions"><button class="btn" :disabled="busy" @click="confirmation = ''">{{ t('common.cancel') }}</button><button class="btn danger solid" :disabled="busy || !nameMatches" @click="save(blockGate.app)">{{ busy ? t('appDetail.publishing') : t('appDetail.gateSubmit') }}</button></div></template></ModalPanel>
    <ModalPanel :open="deleting" :title="t('appDetail.deleteTitle')" @close="!busy && (deleting = false)"><p>{{ t('appDetail.deleteText', { app: detail.data.value.app.name }) }}</p><p v-if="error" class="alert error" role="alert">{{ error }}</p><div class="form-actions"><button class="btn" :disabled="busy" @click="deleting = false">{{ t('common.cancel') }}</button><button class="btn danger solid" :disabled="busy" @click="remove">{{ busy ? t('appDetail.deleting') : t('appDetail.confirmDelete') }}</button></div></ModalPanel>
  </template></AsyncState>
</template>
