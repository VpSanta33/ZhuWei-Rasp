<script setup lang="ts">
import { LoaderCircle, CircleAlert, Inbox } from '@lucide/vue'
import { t } from '../i18n'
defineProps<{ loading?: boolean; error?: Error | null; empty?: boolean; message?: string }>()
defineEmits<{ retry: [] }>()
</script>
<template>
  <div v-if="loading" class="state" role="status"><LoaderCircle class="spin" :size="24"/><p>{{ t('common.loading') }}</p></div>
  <div v-else-if="error" class="state" role="alert"><span class="empty-icon danger"><CircleAlert :size="24"/></span><h3>{{ t('common.loadFailed') }}</h3><p>{{ error.message }}</p><button class="btn" @click="$emit('retry')">{{ t('common.retry') }}</button></div>
  <div v-else-if="empty" class="state"><span class="empty-icon"><Inbox :size="24"/></span><h3>{{ message || t('common.empty') }}</h3><p>{{ t('common.emptyHint') }}</p><slot name="action"/></div>
  <slot v-else/>
</template>
