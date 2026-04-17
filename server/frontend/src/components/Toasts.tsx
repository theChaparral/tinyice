import { toasts, dismissToast } from '../lib/toast'

/**
 * Toasts renders any currently-active toast notifications in the bottom-right
 * corner. Mount once at the top of each page that wants to surface
 * api-level errors (see showToast / reportError in lib/toast.ts).
 */
export function Toasts() {
  if (toasts.value.length === 0) return null
  return (
    <div class="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 max-w-sm">
      {toasts.value.map((t) => {
        let ring = 'border-border'
        if (t.kind === 'error') ring = 'border-danger/50'
        if (t.kind === 'success') ring = 'border-green-500/50'
        return (
          <div
            key={t.id}
            class={`bg-surface-overlay border ${ring} rounded-xl px-4 py-3 shadow-lg text-sm text-text-primary flex items-start gap-3`}
          >
            <div class="flex-1 font-mono text-xs whitespace-pre-wrap break-words">{t.message}</div>
            <button
              class="text-text-tertiary hover:text-text-primary font-mono text-xs"
              onClick={() => dismissToast(t.id)}
              aria-label="Dismiss"
            >
              ×
            </button>
          </div>
        )
      })}
    </div>
  )
}
