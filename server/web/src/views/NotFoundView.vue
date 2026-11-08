<script setup lang="ts">
import { t } from '../i18n'
</script>
<template><section class="state not-found"><span class="eyebrow">{{ t('notFound.eyebrow') }}</span><h1>{{ t('notFound.title') }}</h1><p>{{ t('notFound.text') }}</p><RouterLink to="/overview" class="btn primary">{{ t('notFound.back') }}</RouterLink></section></template>
