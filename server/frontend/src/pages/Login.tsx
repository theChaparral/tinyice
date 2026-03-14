import { signal } from '@preact/signals'

const error = signal('')
const loading = signal(false)

export function Login() {
  async function handleSubmit(e: Event) {
    e.preventDefault()
    error.value = ''
    loading.value = true

    const form = e.target as HTMLFormElement
    const formData = new FormData(form)

    try {
      const res = await fetch('/login', {
        method: 'POST',
        body: formData,
      })

      if (res.ok || res.redirected) {
        window.location.href = '/admin'
      } else {
        const text = await res.text()
        error.value = text || 'Invalid credentials'
      }
    } catch {
      error.value = 'Network error. Please try again.'
    } finally {
      loading.value = false
    }
  }

  return (
    <div class="min-h-screen bg-surface-base flex items-center justify-center px-4">
      <div class="w-full max-w-sm">
        {/* Logo */}
        <div class="flex items-center justify-center gap-3 mb-8">
          <div class="h-8 w-8 rounded bg-accent flex items-center justify-center">
            <span class="font-mono text-xs font-bold text-surface-base leading-none">Ti</span>
          </div>
          <span class="font-mono text-sm font-bold tracking-widest text-text-primary">TINYICE</span>
        </div>

        {/* Card */}
        <form
          onSubmit={handleSubmit}
          class="bg-surface-raised border border-border rounded-xl p-8 w-full max-w-sm"
        >
          <div class="flex flex-col gap-4">
            <input
              type="text"
              name="username"
              placeholder="Username"
              required
              autocomplete="username"
              class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-3 text-text-primary font-mono text-sm placeholder:text-text-tertiary focus:outline-none focus:border-accent/40 transition-colors"
            />
            <input
              type="password"
              name="password"
              placeholder="Password"
              required
              autocomplete="current-password"
              class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-3 text-text-primary font-mono text-sm placeholder:text-text-tertiary focus:outline-none focus:border-accent/40 transition-colors"
            />
            <button
              type="submit"
              disabled={loading.value}
              class="bg-accent text-surface-base font-mono font-bold tracking-[1px] rounded-lg py-3 w-full text-sm hover:bg-accent/90 transition-colors disabled:opacity-50"
            >
              {loading.value ? 'SIGNING IN...' : 'SIGN IN'}
            </button>
          </div>

          {error.value && (
            <p class="text-danger text-sm mt-3 text-center">{error.value}</p>
          )}
        </form>
      </div>
    </div>
  )
}
