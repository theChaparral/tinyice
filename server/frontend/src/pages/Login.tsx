import { signal } from '@preact/signals'
import { PasskeyButton } from '@/components/PasskeyButton'
import { OIDCButtons } from '@/components/OIDCButtons'

const error = signal('')
const loading = signal(false)

declare global {
  interface Window {
    __TINYICE__: {
      passkeysEnabled?: boolean
      oidcProviders?: Array<{ id: string; name: string; icon: string }>
      [key: string]: any
    }
  }
}

const pageData = window.__TINYICE__ || {}

export function Login() {
  const hasPasskeys = pageData.passkeysEnabled && typeof PublicKeyCredential !== 'undefined'
  const hasOIDC = pageData.oidcProviders && pageData.oidcProviders.length > 0
  const hasAlternateAuth = hasPasskeys || hasOIDC

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
        headers: { 'Accept': 'application/json' },
      })

      if (res.ok || res.redirected) {
        window.location.href = '/admin'
      } else {
        try {
          const data = await res.json()
          error.value = data.error || 'Invalid credentials'
        } catch {
          error.value = 'Invalid credentials'
        }
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
        <div class="bg-surface-raised border border-border rounded-xl p-8 w-full max-w-sm">
          <div class="flex flex-col gap-4">
            {/* Passkey button */}
            {hasPasskeys && <PasskeyButton />}

            {/* OIDC provider buttons */}
            {hasOIDC && <OIDCButtons providers={pageData.oidcProviders!} />}

            {/* Divider */}
            {hasAlternateAuth && (
              <div class="flex items-center gap-3 my-1">
                <div class="flex-1 h-px bg-border" />
                <span class="text-text-tertiary text-xs font-mono">or</span>
                <div class="flex-1 h-px bg-border" />
              </div>
            )}

            {/* Username/Password form */}
            <form onSubmit={handleSubmit} class="flex flex-col gap-4">
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
            </form>

            {error.value && (
              <p class="text-danger text-sm text-center">{error.value}</p>
            )}

            {/* Request Access hint */}
            {hasOIDC && (
              <p class="text-text-tertiary text-xs text-center mt-2">
                Don't have an account? Sign in with a provider above to request access.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
