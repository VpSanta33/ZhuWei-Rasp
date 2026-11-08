<script setup lang="ts">
import { ref, watch, onBeforeUnmount, nextTick, useId } from 'vue'
import { X } from '@lucide/vue'
import { t } from '../i18n'
const props = defineProps<{ open: boolean; title: string; wide?: boolean }>()
const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement>()
// unique per instance: several dialogs can be mounted on one page and each needs its own accessible name
const titleId = `modal-title-${useId()}`
let previous: HTMLElement | null = null
watch(() => props.open, async open => {
  await nextTick()
  if (open) {
    previous = document.activeElement as HTMLElement
    dialog.value?.showModal()
    document.body.style.overflow = 'hidden'
  } else {
    dialog.value?.close(); document.body.style.overflow = ''; previous?.focus()
  }
}, { immediate: true })
onBeforeUnmount(() => { document.body.style.overflow = '' })
// Native modal dialogs keep the page inert but still let Tab leave to the browser UI; wrap focus explicitly.
const focusable = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])'
function trap(event: KeyboardEvent) {
  if (event.key !== 'Tab' || !dialog.value) return
  const items = [...dialog.value.querySelectorAll<HTMLElement>(focusable)].filter(el => el.offsetParent !== null || el === document.activeElement)
  if (!items.length) return
  const first = items[0], last = items[items.length - 1], active = document.activeElement
  if (event.shiftKey && (active === first || !dialog.value.contains(active))) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && (active === last || !dialog.value.contains(active))) { event.preventDefault(); first.focus() }
}
</script>
<template>
  <dialog ref="dialog" :class="['modal', { wide }]" :aria-labelledby="titleId" @cancel.prevent="emit('close')" @keydown="trap" @click="e => { if (e.target === dialog) emit('close') }">
    <header class="modal-head"><h2 :id="titleId">{{ title }}</h2><button class="icon-btn" :aria-label="t('common.close')" @click="emit('close')"><X :size="20"/></button></header>
    <div class="modal-body"><slot/></div>
  </dialog>
</template>
