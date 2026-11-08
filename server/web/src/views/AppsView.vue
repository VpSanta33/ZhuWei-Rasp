<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useQueryClient } from '@tanstack/vue-query'
import { Plus, Search, Boxes, ArrowUpRight, Server, UserRound } from '@lucide/vue'
import { useApps } from '../lib/queries'
import { write } from '../lib/api'
import { notify } from '../lib/feedback'
import { t } from '../i18n'
import AsyncState from '../components/AsyncState.vue'
import ModalPanel from '../components/ModalPanel.vue'
import type { Install } from '../types'
const apps = useApps(), router = useRouter(), client = useQueryClient()
const keyword = ref(''), environment = ref(''), open = ref(false), busy = ref(false), error = ref('')
const form = reactive({ name: '', env: 'prod', owner: '', description: '', language: 'java' })
const filtered = computed(() => (apps.data.value || []).filter(x => (!environment.value || x.env === environment.value) && `${x.name} ${x.owner}`.toLowerCase().includes(keyword.value.toLowerCase())))
function create() { Object.assign(form, { name: '', env: 'prod', owner: '', description: '', language: 'java' }); error.value = ''; open.value = true }
async function save() {
  busy.value = true; error.value = ''
  try { const result = await write<Install>('/apps', 'POST', form); await client.invalidateQueries({ queryKey: ['apps'] }); open.value = false; notify(t('apps.created')); await router.push(`/apps/${result.app.id}`) }
  catch (e) { error.value = (e as Error).message } finally { busy.value = false }
}
</script>
<template>
  <div class="page-heading"><div><div class="eyebrow">{{ t('apps.eyebrow') }}</div><h1>{{ t('apps.title') }}<span class="heading-count">{{ apps.data.value?.length || 0 }}</span></h1><p>{{ t('apps.subtitle') }}</p></div><button class="btn primary" @click="create"><Plus :size="17"/>{{ t('apps.create') }}</button></div>
  <div class="standalone-filter"><div class="search-input"><Search :size="16"/><input v-model="keyword" :aria-label="t('apps.search')" :placeholder="t('apps.searchPlaceholder')"/></div><select v-model="environment" :aria-label="t('apps.byEnv')"><option value="">{{ t('apps.allEnvs') }}</option><option v-for="env in [...new Set(apps.data.value?.map(x => x.env))]" :key="env" :value="env">{{ env }}</option></select><span class="muted">{{ t('apps.count', { n: filtered.length }) }}</span></div>
  <AsyncState :loading="apps.isPending.value" :error="apps.error.value" :empty="!filtered.length" :message="t('apps.empty')" @retry="apps.refetch()">
    <template #action><button class="btn primary" @click="create"><Plus :size="16"/>{{ t('apps.first') }}</button></template>
    <div class="app-grid"><RouterLink v-for="app in filtered" :key="app.id" :to="`/apps/${app.id}`" class="panel app-card">
      <header><span class="app-glyph"><Boxes :size="22"/></span><span class="badge neutral">{{ app.env }}</span><ArrowUpRight :size="18" class="muted"/></header>
      <h2>{{ app.name }}</h2><p class="app-description">{{ app.description || t('apps.noDescription') }}</p>
      <div class="app-card-stats"><span><Server :size="15"/>{{ t('apps.onlineInstances', { online: app.online, total: app.total }) }}</span><span class="language-badge">{{ app.language.toUpperCase() }}</span></div>
      <footer><span><UserRound :size="14"/>{{ app.owner || t('apps.noOwner') }}</span><span :class="['badge', app.online ? 'green' : 'neutral']"><span class="dot"/>{{ app.online ? t('apps.hasOnline') : t('apps.noOnline') }}</span></footer>
    </RouterLink></div>
  </AsyncState>
  <ModalPanel :open="open" :title="t('apps.modalTitle')" @close="!busy && (open = false)"><p class="muted modal-intro">{{ t('apps.modalIntro') }}</p><form class="form-stack" @submit.prevent="save"><label class="field">{{ t('apps.name') }}<input v-model="form.name" maxlength="128" required :placeholder="t('apps.namePlaceholder')"/></label><div class="form-row"><label class="field">{{ t('apps.env') }}<select v-model="form.env"><option value="prod">{{ t('apps.envProd') }}</option><option value="staging">{{ t('apps.envStaging') }}</option><option value="test">{{ t('apps.envTest') }}</option><option value="dev">{{ t('apps.envDev') }}</option></select></label><label class="field">{{ t('apps.owner') }}<input v-model="form.owner" maxlength="128" :placeholder="t('apps.ownerPlaceholder')"/></label></div><label class="field">{{ t('apps.description') }}<textarea v-model="form.description" rows="3" maxlength="1000" :placeholder="t('apps.descriptionPlaceholder')"/></label><p v-if="error" class="alert error" role="alert">{{ error }}</p><div class="form-actions"><button type="button" class="btn" :disabled="busy" @click="open = false">{{ t('common.cancel') }}</button><button class="btn primary" :disabled="busy">{{ busy ? t('apps.creating') : t('apps.submit') }}</button></div></form></ModalPanel>
</template>
