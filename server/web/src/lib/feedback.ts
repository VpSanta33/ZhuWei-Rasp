import { ref } from 'vue'
export const notice = ref('')
let timer: ReturnType<typeof setTimeout>
export function notify(message: string) {
  clearTimeout(timer); notice.value = message
  timer = setTimeout(() => { notice.value = '' }, 4500)
}
