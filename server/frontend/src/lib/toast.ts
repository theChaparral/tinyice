import { signal } from '@preact/signals'

export type Toast = {
  id: number
  kind: 'error' | 'info' | 'success'
  message: string
}

export const toasts = signal<Toast[]>([])

let nextId = 1

export function showToast(kind: Toast['kind'], message: string, timeoutMs = 5000) {
  const id = nextId++
  toasts.value = [...toasts.value, { id, kind, message }]
  if (timeoutMs > 0) {
    setTimeout(() => dismissToast(id), timeoutMs)
  }
  return id
}

export function dismissToast(id: number) {
  toasts.value = toasts.value.filter((t) => t.id !== id)
}

export function reportError(e: unknown, fallback = 'Request failed'): void {
  const msg = e instanceof Error && e.message ? e.message : fallback
  showToast('error', msg)
  // eslint-disable-next-line no-console
  console.error(e)
}
