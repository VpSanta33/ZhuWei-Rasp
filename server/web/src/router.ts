import { createRouter, createWebHashHistory } from 'vue-router'
import { watch } from 'vue'
import { token } from './lib/api'
import { locale, t } from './i18n'

export const router = createRouter({
  history: createWebHashHistory(),
  scrollBehavior: () => ({ top: 0 }),
  routes: [
    { path: '/', redirect: '/overview' },
    { path: '/login', component: () => import('./views/LoginView.vue'), meta: { title: 'nav.login' } },
    { path: '/overview', component: () => import('./views/OverviewView.vue'), meta: { title: 'nav.overview', group: 'nav.groupWorkspace' } },
    { path: '/alarms', component: () => import('./views/AlarmsView.vue'), meta: { title: 'nav.alarms', group: 'nav.groupOps' } },
    { path: '/apps', component: () => import('./views/AppsView.vue'), meta: { title: 'nav.apps', group: 'nav.groupAssets' } },
    { path: '/apps/:id', component: () => import('./views/AppDetailView.vue'), meta: { title: 'nav.appDetail', group: 'nav.groupAssets' } },
    { path: '/instances', component: () => import('./views/InstancesView.vue'), meta: { title: 'nav.instances', group: 'nav.groupAssets' } },
    { path: '/components', component: () => import('./views/ComponentsView.vue'), meta: { title: 'nav.components', group: 'nav.groupAssets' } },
    { path: '/whitelists', component: () => import('./views/WhitelistsView.vue'), meta: { title: 'nav.whitelists', group: 'nav.groupOps' } },
    { path: '/settings', component: () => import('./views/SettingsView.vue'), meta: { title: 'nav.settings', group: 'nav.groupSystem' } },
    { path: '/:pathMatch(.*)*', component: () => import('./views/NotFoundView.vue'), meta: { title: 'nav.notFound' } },
  ],
})
router.beforeEach(to => {
  if (to.path !== '/login' && !token.value) return { path: '/login', query: { redirect: to.fullPath } }
  if (to.path === '/login' && token.value) return '/overview'
})
// route meta holds i18n keys; the tab title follows both navigation and language switches
const setTitle = () => { document.title = `${t(String(router.currentRoute.value.meta.title || 'nav.overview'))} · ZhuWei RASP` }
router.afterEach(setTitle)
watch(locale, setTitle)
