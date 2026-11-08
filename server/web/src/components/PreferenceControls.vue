<script setup lang="ts">
import { computed } from 'vue'
import { Sun, Moon, Monitor, Languages } from '@lucide/vue'
import { locale, locales, setLocale, t, type Locale } from '../i18n'
import { themePref, cycleTheme } from '../lib/theme'

const themeIcon = computed(() => ({ light: Sun, dark: Moon, system: Monitor })[themePref.value])
const themeName = computed(() => t({ light: 'prefs.themeLight', dark: 'prefs.themeDark', system: 'prefs.themeSystem' }[themePref.value]))
</script>
<template>
  <div class="prefs">
    <label class="lang-select">
      <Languages :size="16" aria-hidden="true"/>
      <span class="sr-only">{{ t('prefs.language') }}</span>
      <select :value="locale" :aria-label="t('prefs.language')" @change="setLocale(($event.target as HTMLSelectElement).value as Locale)">
        <option v-for="item in locales" :key="item.value" :value="item.value">{{ item.label }}</option>
      </select>
    </label>
    <button class="icon-btn" type="button" :aria-label="t('prefs.themeSwitch', { name: themeName })" :title="t('prefs.themeSwitch', { name: themeName })" @click="cycleTheme">
      <component :is="themeIcon" :size="17"/>
    </button>
  </div>
</template>
