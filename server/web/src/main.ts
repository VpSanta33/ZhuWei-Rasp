import { createApp } from 'vue'
import { VueQueryPlugin, QueryClient } from '@tanstack/vue-query'
import { router } from './router'
import App from './App.vue'
import './styles.css'
import './lib/theme'

export const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 15000, retry: false, refetchOnWindowFocus: true } } })
createApp(App).use(VueQueryPlugin, { queryClient }).use(router).mount('#app')
window.addEventListener('rasp:unauthorized', () => {
  queryClient.clear()
  // A 401 can arrive before the initial navigation has resolved (currentRoute is still the start
  // location "/"), so take the intended page from the hash URL, which hash history keeps up to date.
  const target = window.location.hash.replace(/^#/, '') || router.currentRoute.value.fullPath
  if (!target.startsWith('/login')) void router.replace({ path: '/login', query: { redirect: target } })
})
