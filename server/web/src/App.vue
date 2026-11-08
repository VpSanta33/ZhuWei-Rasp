<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { ShieldCheck, LayoutDashboard, Siren, Boxes, Server, Package, ListChecks, Settings2, LogOut, Menu, X, ChevronRight, RefreshCw, ArrowUpRight, CheckCheck, BookOpen } from '@lucide/vue'
import { api, token, user, clearSession, write } from './lib/api'
import { notice } from './lib/feedback'
import { t } from './i18n'
import PreferenceControls from './components/PreferenceControls.vue'
const route = useRoute(), router = useRouter(), client = useQueryClient()
const mobileOpen = ref(false), refreshing = ref(false)
const isLogin = computed(() => route.path === '/login')
const me = useQuery({ queryKey: ['me'], queryFn: ({ signal }) => api<{ user: string }>('/me', { signal }), enabled: computed(() => !!token.value) })
const username = computed(() => me.data.value?.user || user.value || t('nav.defaultUser'))
const navigation = [
  { label: 'nav.groupWorkspace', items: [{ path: '/overview', label: 'nav.overview', icon: LayoutDashboard }] },
  { label: 'nav.groupOps', items: [{ path: '/alarms', label: 'nav.alarms', icon: Siren }, { path: '/whitelists', label: 'nav.whitelists', icon: ListChecks }] },
  { label: 'nav.groupAssets', items: [{ path: '/apps', label: 'nav.apps', icon: Boxes }, { path: '/instances', label: 'nav.instances', icon: Server }, { path: '/components', label: 'nav.components', icon: Package }] },
  { label: 'nav.groupSystem', items: [{ path: '/settings', label: 'nav.settings', icon: Settings2 }] },
]
const isActive = (path: string) => route.path === path || (path === '/apps' && route.path.startsWith('/apps/'))
watch(() => route.fullPath, () => { mobileOpen.value = false })
async function refresh() { refreshing.value = true; try { await client.invalidateQueries() } finally { refreshing.value = false } }
async function logout() {
  try { await write('/logout', 'POST') } catch { /* clear local session even when server is unreachable */ }
  clearSession(); client.clear(); await router.replace('/login')
}
</script>
<template>
  <RouterView v-if="isLogin"/>
  <div v-else class="app-shell">
    <a href="#main-content" class="skip-link">{{ t('nav.skip') }}</a>
    <button v-if="mobileOpen" class="sidebar-scrim" :aria-label="t('nav.closeNav')" @click="mobileOpen = false"/>
    <aside :class="['sidebar', { open: mobileOpen }]" :aria-label="t('nav.mainNav')">
      <div class="sidebar-top">
        <RouterLink to="/overview" class="brand"><span class="brand-symbol"><ShieldCheck :size="22" :stroke-width="2"/></span><span class="brand-name">ZhuWei<span class="brand-caption">{{ t('brand.caption') }}</span></span></RouterLink>
        <button class="icon-btn close-nav" :aria-label="t('nav.closeNav')" @click="mobileOpen = false"><X :size="20"/></button>
      </div>
      <div class="workspace-select"><span class="workspace-icon">Z</span><div><strong>{{ t('nav.workspace') }}</strong><small>{{ t('nav.workspaceSub') }}</small></div><span class="workspace-dot"/></div>
      <nav>
        <section v-for="group in navigation" :key="group.label" class="nav-group">
          <p>{{ t(group.label) }}</p>
          <RouterLink v-for="item in group.items" :key="item.path" :to="item.path" :class="['nav-link', { active: isActive(item.path) }]" :aria-current="isActive(item.path) ? 'page' : undefined"><component :is="item.icon" :size="18" :stroke-width="1.8"/><span>{{ t(item.label) }}</span></RouterLink>
        </section>
      </nav>
      <div class="sidebar-bottom">
        <div class="agent-help"><span class="help-icon"><BookOpen :size="17"/></span><strong>{{ t('nav.helpTitle') }}</strong><p>{{ t('nav.helpText') }}</p><RouterLink to="/apps">{{ t('nav.helpLink') }} <ArrowUpRight :size="14"/></RouterLink></div>
        <div class="profile"><span class="avatar">{{ username.slice(0, 1).toUpperCase() }}</span><div><strong>{{ username }}</strong><small>{{ t('nav.admin') }}</small></div><button class="icon-btn" :aria-label="t('nav.logout')" :title="t('nav.logout')" @click="logout"><LogOut :size="17"/></button></div>
      </div>
    </aside>
    <div class="main-shell">
      <header class="topbar">
        <div class="breadcrumbs"><button class="icon-btn mobile-menu" :aria-label="t('nav.openNav')" :aria-expanded="mobileOpen" @click="mobileOpen = true"><Menu :size="21"/></button><span>{{ t(String(route.meta.group || 'nav.groupWorkspace')) }}</span><ChevronRight :size="14"/><strong>{{ t(String(route.meta.title || 'nav.overview')) }}</strong></div>
        <div class="topbar-actions"><span class="console-label"><span class="dot"/>{{ t('brand.console') }}</span><PreferenceControls/><button class="icon-btn" :aria-label="t('nav.refresh')" :title="t('nav.refresh')" :disabled="refreshing" @click="refresh"><RefreshCw :size="17" :class="{ spin: refreshing }"/></button><span class="topbar-divider"/><span class="avatar small" aria-hidden="true">{{ username.slice(0, 1).toUpperCase() }}</span></div>
      </header>
      <main id="main-content" class="main-content" tabindex="-1">
        <RouterView v-slot="{ Component }"><component :is="Component" :key="route.path"/></RouterView>
        <footer class="page-footer"><span>{{ t('brand.product') }} <span class="footer-dot">·</span> {{ t('brand.footer') }}</span><span>{{ t('brand.slogan') }} <ShieldCheck :size="13"/></span></footer>
      </main>
    </div>
  </div>
  <Transition name="toast"><div v-if="notice" class="toast" role="status"><CheckCheck :size="18"/>{{ notice }}</div></Transition>
</template>
