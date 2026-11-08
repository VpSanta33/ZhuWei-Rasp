<script setup lang="ts">
import { computed, ref } from 'vue'
import { useQuery } from '@tanstack/vue-query'
import { ShieldCheck, Boxes, Server, ShieldBan, ArrowUpRight, Activity, Radar, ChevronRight, TriangleAlert } from '@lucide/vue'
import { api, query } from '../lib/api'
import { attacks, number } from '../lib/format'
import { t } from '../i18n'
import AsyncState from '../components/AsyncState.vue'
import AlarmTable from '../components/AlarmTable.vue'
import AlarmDetail from '../components/AlarmDetail.vue'
import type { Stats, Alarm } from '../types'
const days = ref(7), selected = ref('')
const stats = useQuery({ queryKey: computed(() => ['stats', days.value]), queryFn: ({ signal }) => api<Stats>(`/stats?days=${days.value}`, { signal }), refetchInterval: 30000 })
const recent = useQuery({ queryKey: computed(() => ['alarms', 'recent', days.value]), queryFn: ({ signal }) => api<{ items: Alarm[] | null; total: number }>(`/alarms${query({ page_size: 5, since: Date.now() - days.value * 86400000 })}`, { signal }), refetchInterval: 30000 })
const s = computed(() => stats.data.value)
const total = computed(() => (s.value?.by_action || []).reduce((n, x) => n + x.count, 0))
const blocked = computed(() => s.value?.by_action?.find(x => x.key === 'block')?.count || 0)
const rate = computed(() => s.value?.instances_total ? Math.round(s.value.instances_online / s.value.instances_total * 100) : 0)
const points = computed(() => {
  const counts = new Map((s.value?.by_day || []).map(x => [x.key, x.count]))
  return Array.from({ length: days.value }, (_, i) => {
    const date = new Date(); date.setDate(date.getDate() - days.value + 1 + i)
    const key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
    return { label: key.slice(5).replace('-', '/'), count: counts.get(key) || 0 }
  })
})
const max = computed(() => Math.max(4, ...points.value.map(x => x.count)))
const path = computed(() => points.value.map((x, i) => `${i ? 'L' : 'M'}${40 + i * 700 / Math.max(1, points.value.length - 1)},${180 - x.count / max.value * 150}`).join(' '))
const types = computed(() => (s.value?.by_attack_type || []).slice(0, 5))
const typeColors = ['var(--chart-1)', 'var(--chart-2)', 'var(--chart-3)', 'var(--chart-4)', 'var(--chart-5)', 'var(--chart-6)']
const donut = computed(() => {
  let cursor = 0
  const sum = (s.value?.by_attack_type || []).reduce((n, x) => n + x.count, 0)
  if (!sum) return 'conic-gradient(var(--border) 0% 100%)'
  const values = (s.value?.by_attack_type || []).map((x, i) => { const start = cursor; cursor += x.count / sum * 100; return `${typeColors[i % typeColors.length]} ${start}% ${cursor}%` })
  return `conic-gradient(${values.join(',')})`
})
</script>
<template>
  <div class="page-heading">
    <div><div class="eyebrow">{{ t('overview.eyebrow') }}</div><h1>{{ t('overview.title') }}<span class="live-pill"><span class="dot"/>{{ t('overview.live') }}</span></h1><p>{{ t('overview.subtitle') }}</p></div>
    <div class="heading-actions"><label class="sr-only" for="overview-days">{{ t('overview.range') }}</label><select id="overview-days" v-model="days"><option :value="1">{{ t('overview.range1') }}</option><option :value="7">{{ t('overview.range7') }}</option><option :value="30">{{ t('overview.range30') }}</option></select><RouterLink class="btn primary" to="/apps"><Boxes :size="16"/>{{ t('overview.connect') }}</RouterLink></div>
  </div>
  <AsyncState :loading="stats.isPending.value" :error="stats.error.value" @retry="stats.refetch()">
    <template v-if="s">
      <div :class="['protection-banner', { warning: s.kill_switch || s.instances_breaker > 0 }]">
        <span class="banner-icon"><TriangleAlert v-if="s.kill_switch || s.instances_breaker" :size="22"/><ShieldCheck v-else :size="22"/></span>
        <div><strong>{{ s.kill_switch ? t('overview.bannerKill') : s.instances_breaker ? t('overview.bannerBreaker') : s.instances_online ? t('overview.bannerRunning') : t('overview.bannerReady') }}</strong><p>{{ s.kill_switch ? t('overview.bannerKillText') : s.instances_online ? t('overview.bannerRunningText', { n: s.instances_online }) : t('overview.bannerReadyText') }}</p></div>
        <RouterLink :to="s.kill_switch ? '/settings' : '/instances'" class="banner-link">{{ t('overview.viewStatus') }} <ArrowUpRight :size="16"/></RouterLink>
      </div>
      <div class="metric-grid">
        <article class="metric-card"><div class="metric-label">{{ t('overview.apps') }}<span class="metric-icon"><Boxes :size="18"/></span></div><div class="metric-value">{{ number(s.apps_total) }}<span>{{ t('overview.appsUnit') }}</span></div><div class="metric-foot">{{ t('overview.appsFoot') }}<RouterLink to="/apps" :aria-label="t('overview.viewApps')"><ArrowUpRight :size="16"/></RouterLink></div></article>
        <article class="metric-card"><div class="metric-label">{{ t('overview.instances') }}<span class="metric-icon info-icon"><Server :size="18"/></span></div><div class="metric-value">{{ number(s.instances_online) }}<span>/ {{ s.instances_total }}</span></div><div class="metric-foot"><span><span class="status-dot"/>{{ t('overview.onlineRate', { n: rate }) }}</span><RouterLink to="/instances" :aria-label="t('overview.viewInstances')"><ArrowUpRight :size="16"/></RouterLink></div></article>
        <article class="metric-card"><div class="metric-label">{{ t('overview.threats') }}<span class="metric-icon amber-icon"><Radar :size="18"/></span></div><div class="metric-value">{{ number(total) }}<span>{{ t('overview.timesUnit') }}</span></div><div class="metric-foot">{{ t('overview.threatsFoot') }}<RouterLink to="/alarms" :aria-label="t('overview.viewAlarms')"><ArrowUpRight :size="16"/></RouterLink></div></article>
        <article class="metric-card"><div class="metric-label">{{ t('overview.blocked') }}<span class="metric-icon red-icon"><ShieldBan :size="18"/></span></div><div class="metric-value">{{ number(blocked) }}<span>{{ t('overview.timesUnit') }}</span></div><div class="metric-foot"><span>{{ total ? t('overview.blockedShare', { n: Math.round(blocked / total * 100) }) : t('overview.noBlocks') }}</span><ShieldCheck :size="15" class="green-text"/></div></article>
      </div>
      <div class="chart-grid">
        <section class="panel trend-panel">
          <header class="panel-head"><div><h2>{{ t('overview.trend') }}</h2><p>{{ t('overview.trendSub') }}</p></div><span class="chart-legend"><span class="legend-dot"/>{{ t('overview.trendLegend') }}</span></header>
          <div class="trend-summary"><strong>{{ number(total) }}</strong><span>{{ t('overview.trendEvents') }}</span><span class="chart-period">{{ t('overview.lastDays', { n: days }) }}</span></div>
          <div class="trend-chart"><svg viewBox="0 0 770 220" role="img" :aria-label="t('overview.trendAria', { days, total })" preserveAspectRatio="none"><defs><linearGradient id="chart-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="var(--chart-1)" stop-opacity=".22"/><stop offset="100%" stop-color="var(--chart-1)" stop-opacity="0"/></linearGradient></defs><g v-for="tick in [0, 1, 2, 3]" :key="tick"><line x1="40" x2="740" :y1="30 + tick * 50" :y2="30 + tick * 50" stroke="var(--border)" stroke-dasharray="4 5"/><text x="0" :y="34 + tick * 50" class="chart-text">{{ Math.round(max * (1 - tick / 3)) }}</text></g><path :d="`${path} L740,180 L40,180 Z`" fill="url(#chart-fill)"/><path :d="path" fill="none" stroke="var(--chart-1)" stroke-width="2.5" vector-effect="non-scaling-stroke"/><g v-for="(point, i) in points" :key="point.label"><circle :cx="40 + i * 700 / Math.max(1, points.length - 1)" :cy="180 - point.count / max * 150" r="3.5" fill="var(--surface)" stroke="var(--chart-1)" stroke-width="2"><title>{{ t('overview.pointTitle', { label: point.label, n: point.count }) }}</title></circle><text v-if="days <= 7 || i % 5 === 0 || i === days - 1" :x="40 + i * 700 / Math.max(1, points.length - 1)" y="211" text-anchor="middle" class="chart-text">{{ point.label }}</text></g></svg></div>
          <details class="chart-data"><summary>{{ t('overview.trendData') }}</summary><div class="table-wrap"><table><thead><tr><th>{{ t('overview.date') }}</th><th>{{ t('overview.events') }}</th></tr></thead><tbody><tr v-for="point in points" :key="point.label"><td>{{ point.label }}</td><td>{{ point.count }}</td></tr></tbody></table></div></details>
        </section>
        <section class="panel type-panel">
          <header class="panel-head"><div><h2>{{ t('overview.types') }}</h2><p>{{ t('overview.typesSub') }}</p></div><Activity :size="18" class="muted"/></header>
          <div class="donut" :style="{ background: donut }" role="img" :aria-label="types.map(x => t('overview.typeAria', { name: attacks[x.key] || x.key, n: x.count })).join(', ') || t('overview.noAttacks')"><div><strong>{{ number(total) }}</strong><span>{{ t('overview.threatEvents') }}</span></div></div>
          <div class="type-list"><div v-for="(type, i) in types" :key="type.key"><span><i :style="{ background: typeColors[i] }"/>{{ attacks[type.key] || type.key }}</span><strong>{{ number(type.count) }}<small>{{ total ? Math.round(type.count / total * 100) : 0 }}%</small></strong></div><p v-if="!types.length" class="muted center">{{ t('overview.noAttacks') }}</p></div>
        </section>
      </div>
      <section class="panel"><header class="panel-head"><div><h2>{{ t('overview.recent') }}<span class="count-label">{{ recent.data.value?.total || 0 }}</span></h2><p>{{ t('overview.recentSub') }}</p></div><RouterLink class="text-link" to="/alarms">{{ t('overview.allAlarms') }} <ChevronRight :size="16"/></RouterLink></header><AsyncState :loading="recent.isPending.value" :error="recent.error.value" :empty="!recent.data.value?.items?.length" :message="t('overview.recentEmpty')" @retry="recent.refetch()"><AlarmTable :alarms="recent.data.value?.items || []" @select="selected = $event.event_id"/></AsyncState></section>
      <div class="overview-bottom">
        <section class="panel mini-panel"><div class="mini-icon"><Server :size="20"/></div><div><h3>{{ t('overview.health') }}</h3><p>{{ s.instances_breaker ? t('overview.breakerCount', { n: s.instances_breaker }) : t('overview.noBreaker') }}</p></div><RouterLink to="/instances" :aria-label="t('overview.viewHealth')"><ArrowUpRight :size="18"/></RouterLink></section>
        <section class="panel mini-panel"><div class="mini-icon info-icon"><ShieldCheck :size="20"/></div><div><h3>{{ t('overview.policies') }}</h3><p>{{ t('overview.policiesSub') }}</p></div><RouterLink to="/apps" :aria-label="t('overview.configurePolicies')"><ArrowUpRight :size="18"/></RouterLink></section>
      </div>
    </template>
  </AsyncState>
  <AlarmDetail :id="selected" @close="selected = ''"/>
</template>
