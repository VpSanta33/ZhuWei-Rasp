<script setup lang="ts">
import { ArrowUpRight } from '@lucide/vue'
import type { Alarm } from '../types'
import { attacks, statuses, fmtTime } from '../lib/format'
import { t } from '../i18n'
defineProps<{ alarms: Alarm[] }>()
defineEmits<{ select: [alarm: Alarm] }>()
</script>
<template>
  <div class="table-wrap"><table>
    <thead><tr><th>{{ t('alarms.colType') }}</th><th>{{ t('alarms.colApp') }}</th><th>{{ t('alarms.colIp') }}</th><th>{{ t('alarms.colAction') }}</th><th>{{ t('alarms.colStatus') }}</th><th>{{ t('alarms.colTime') }}</th><th><span class="sr-only">{{ t('common.operations') }}</span></th></tr></thead>
    <tbody><tr v-for="alarm in alarms" :key="alarm.event_id">
      <td><button class="text-link strong" @click="$emit('select', alarm)">{{ attacks[alarm.attack_type] || alarm.attack_type }}</button><span class="cell-sub mono truncate" :title="alarm.url">{{ alarm.url || alarm.algorithm }}</span></td>
      <td>{{ alarm.app_name || '—' }}</td>
      <td class="mono">{{ alarm.client_ip || '—' }}</td>
      <td><span :class="['badge', alarm.action === 'block' ? 'red' : 'amber']"><span class="dot"/>{{ t(`action.${alarm.action === 'block' ? 'block' : 'log'}`) }}</span></td>
      <td><span :class="['badge', alarm.status === 'new' ? 'blue' : 'neutral']">{{ statuses[alarm.status] || alarm.status }}</span></td>
      <td class="muted nowrap tabular">{{ fmtTime(alarm.event_time) }}</td>
      <td><button class="icon-btn" :aria-label="t('alarms.view', { id: alarm.event_id })" @click="$emit('select', alarm)"><ArrowUpRight :size="17"/></button></td>
    </tr></tbody>
  </table></div>
</template>
