<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useQueryClient } from '@tanstack/vue-query'
import { ShieldCheck, ArrowRight, Eye, EyeOff, LoaderCircle, Fingerprint, Activity, LockKeyhole } from '@lucide/vue'
import { write, setSession } from '../lib/api'
import { t } from '../i18n'
import PreferenceControls from '../components/PreferenceControls.vue'
const username = ref('admin'), password = ref(''), show = ref(false), busy = ref(false), error = ref('')
const route = useRoute(), router = useRouter(), client = useQueryClient()
async function login() {
  busy.value = true; error.value = ''
  try {
    const result = await write<{ token: string; user: string }>('/login', 'POST', { username: username.value.trim(), password: password.value })
    client.clear(); setSession(result.token, result.user)
    const redirect = String(route.query.redirect || '/overview')
    await router.replace(redirect.startsWith('/') && !redirect.startsWith('//') && !redirect.startsWith('/login') ? redirect : '/overview')
  } catch (e) { error.value = (e as Error).message } finally { busy.value = false }
}
</script>
<template>
  <div class="login-page">
    <section class="login-story">
      <div class="brand"><span class="brand-symbol"><ShieldCheck :size="24"/></span><span class="brand-name">ZhuWei<span class="brand-caption">{{ t('brand.caption') }}</span></span></div>
      <div class="login-story-content">
        <span class="eyebrow">{{ t('login.tagline') }}</span>
        <h1>{{ t('login.headline1') }}<br/>{{ t('login.headline2') }}</h1>
        <p>{{ t('login.story1') }}<br/>{{ t('login.story2') }}</p>
        <div class="security-orbit" aria-hidden="true"><div class="orbit-circle outer"/><div class="orbit-circle inner"/><div class="orbit-core"><ShieldCheck :size="60" :stroke-width="1.3"/></div><span class="orbit-node one"><Fingerprint :size="22"/></span><span class="orbit-node two"><Activity :size="22"/></span><span class="orbit-node three"><LockKeyhole :size="22"/></span></div>
      </div>
      <div class="login-story-footer"><span class="dot"/> JAVA AGENT <span> / </span> REAL-TIME PROTECTION</div>
    </section>
    <section class="login-form-side">
      <PreferenceControls class="login-prefs"/>
      <div class="login-form">
        <span class="badge blue">{{ t('login.badge') }}</span>
        <h2>{{ t('login.welcome') }}</h2>
        <p class="muted">{{ t('login.subtitle') }}</p>
        <form @submit.prevent="login">
          <label class="field">{{ t('login.username') }}<input v-model="username" name="username" autocomplete="username" required maxlength="128" autofocus :placeholder="t('login.usernamePlaceholder')"/></label>
          <label class="field">{{ t('login.password') }}<span class="password-field"><input v-model="password" name="password" :type="show ? 'text' : 'password'" autocomplete="current-password" required :placeholder="t('login.passwordPlaceholder')"/><button type="button" class="icon-btn" :aria-label="show ? t('login.hidePassword') : t('login.showPassword')" @click="show = !show"><EyeOff v-if="show" :size="18"/><Eye v-else :size="18"/></button></span></label>
          <p v-if="error" class="alert error" role="alert">{{ error }}</p>
          <button class="btn primary login-submit" :disabled="busy"><LoaderCircle v-if="busy" class="spin" :size="18"/><template v-else>{{ t('login.submit') }} <ArrowRight :size="18"/></template></button>
        </form>
        <p class="login-hint"><LockKeyhole :size="14"/>{{ t('login.hint') }}</p>
      </div>
      <footer>{{ t('login.footer') }}</footer>
    </section>
  </div>
</template>
