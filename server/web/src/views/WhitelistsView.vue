<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { Plus, Trash2 } from '@lucide/vue'
import { api, write, query } from '../lib/api'
import { useApps } from '../lib/queries'
import { attacks, fmtTime } from '../lib/format'
import { notify } from '../lib/feedback'
import { t } from '../i18n'
import AsyncState from '../components/AsyncState.vue'
import ModalPanel from '../components/ModalPanel.vue'
import type { Whitelist } from '../types'
const apps = useApps(), client = useQueryClient(), appId = ref(''), open = ref(false), busy = ref(false), error = ref(''), deleting = ref<Whitelist>()
const form = reactive({ app_id: 0, url: '', match: 'exact', types: 'all', note: '' })
const list = useQuery({ queryKey: computed(() => ['whitelists', appId.value]), queryFn: async ({ signal }) => (await api<Whitelist[] | null>(`/whitelists${query({ app_id: appId.value })}`, { signal })) || [] })
const matchLabel = (m: string) => t(`whitelists.match${m.charAt(0).toUpperCase()}${m.slice(1)}`)
function create() { Object.assign(form, { app_id: 0, url: '', match: 'exact', types: 'all', note: '' }); error.value = ''; open.value = true }
async function save() {
  error.value = ''
  if (form.match === 'regex') { try { new RegExp(form.url) } catch { error.value = t('whitelists.badRegex'); return } }
  busy.value = true
  try { await write('/whitelists', 'POST', form); await client.invalidateQueries({ queryKey: ['whitelists'] }); open.value = false; notify(t('whitelists.created')) }
  catch (e) { error.value = (e as Error).message } finally { busy.value = false }
}
async function remove() {
  if (!deleting.value) return
  busy.value = true; error.value = ''
  try { await write(`/whitelists/${deleting.value.id}`, 'DELETE'); await client.invalidateQueries({ queryKey: ['whitelists'] }); deleting.value = undefined; notify(t('whitelists.deleted')) }
  catch (e) { error.value = (e as Error).message } finally { busy.value = false }
}
</script>
<template>
  <div class="page-heading"><div><div class="eyebrow">{{ t('whitelists.eyebrow') }}</div><h1>{{ t('whitelists.title') }}</h1><p>{{ t('whitelists.subtitle') }}</p></div><button class="btn primary" @click="create"><Plus :size="17"/>{{ t('whitelists.create') }}</button></div>
  <section class="panel">
    <div class="filter-bar"><select v-model="appId" :aria-label="t('whitelists.byApp')"><option value="">{{ t('whitelists.allScopes') }}</option><option value="0">{{ t('whitelists.globalOnly') }}</option><option v-for="app in apps.data.value" :key="app.id" :value="String(app.id)">{{ app.name }} / {{ app.env }}</option></select><span class="muted">{{ t('whitelists.scopeHint') }}</span></div>
    <AsyncState :loading="list.isPending.value" :error="list.error.value" :empty="!list.data.value?.length" :message="t('whitelists.empty')" @retry="list.refetch()"><div class="table-wrap"><table>
      <thead><tr><th>{{ t('whitelists.colUrl') }}</th><th>{{ t('whitelists.colScope') }}</th><th>{{ t('whitelists.colMatch') }}</th><th>{{ t('whitelists.colTypes') }}</th><th>{{ t('whitelists.colNote') }}</th><th>{{ t('whitelists.colCreated') }}</th><th>{{ t('common.operations') }}</th></tr></thead>
      <tbody><tr v-for="item in list.data.value" :key="item.id"><td class="mono wrap-cell">{{ item.url }}</td><td><span :class="['badge', item.app_id ? 'neutral' : 'blue']">{{ item.app_id ? apps.data.value?.find(x => x.id === item.app_id)?.name || t('whitelists.appN', { n: item.app_id }) : t('whitelists.global') }}</span></td><td>{{ matchLabel(item.match) }}</td><td>{{ item.types === 'all' ? t('whitelists.allTypes') : item.types.split(',').map(x => attacks[x] || x).join(' · ') }}</td><td>{{ item.note || '—' }}<span class="cell-sub">{{ item.created_by }}</span></td><td class="muted nowrap tabular">{{ fmtTime(item.created_at) }}</td><td><button class="icon-btn danger-text" :aria-label="t('whitelists.deleteLabel', { url: item.url })" @click="deleting = item; error = ''"><Trash2 :size="16"/></button></td></tr></tbody>
    </table></div></AsyncState>
  </section>
  <ModalPanel :open="open" :title="t('whitelists.create')" @close="!busy && (open = false)"><form class="form-stack" @submit.prevent="save"><label class="field">{{ t('whitelists.scope') }}<select v-model="form.app_id"><option :value="0">{{ t('whitelists.scopeGlobal') }}</option><option v-for="app in apps.data.value" :key="app.id" :value="app.id">{{ app.name }} / {{ app.env }}</option></select></label><label class="field">{{ t('whitelists.url') }}<input v-model="form.url" required maxlength="1024" :placeholder="t('whitelists.urlPlaceholder')"/></label><div class="form-row"><label class="field">{{ t('whitelists.match') }}<select v-model="form.match"><option v-for="m in ['exact', 'prefix', 'regex']" :key="m" :value="m">{{ matchLabel(m) }}</option></select></label><label class="field">{{ t('whitelists.types') }}<select v-model="form.types"><option value="all">{{ t('whitelists.allTypes') }}</option><option v-for="(label, value) in attacks" :key="value" :value="value">{{ label }}</option></select></label></div><label class="field">{{ t('whitelists.note') }}<textarea v-model="form.note" rows="2" :placeholder="t('whitelists.notePlaceholder')" maxlength="1000"/></label><p class="alert warning">{{ t('whitelists.warn') }}</p><p v-if="error" class="alert error" role="alert">{{ error }}</p><div class="form-actions"><button type="button" class="btn" :disabled="busy" @click="open = false">{{ t('common.cancel') }}</button><button class="btn primary" :disabled="busy">{{ busy ? t('whitelists.creating') : t('whitelists.submit') }}</button></div></form></ModalPanel>
  <ModalPanel :open="!!deleting" :title="t('whitelists.deleteTitle')" @close="!busy && (deleting = undefined)"><p>{{ t('whitelists.deleteText', { url: deleting?.url || '' }) }}</p><p v-if="error" class="alert error" role="alert">{{ error }}</p><div class="form-actions"><button class="btn" :disabled="busy" @click="deleting = undefined">{{ t('common.cancel') }}</button><button class="btn danger solid" :disabled="busy" @click="remove">{{ t('whitelists.confirmDelete') }}</button></div></ModalPanel>
</template>
