import { signal } from '@preact/signals'
import { startAuthentication } from '@simplewebauthn/browser'

const loading = signal(false)
const error = signal('')

export function PasskeyButton() {
  async function handleLogin() {
    loading.value = true
    error.value = ''

    try {
      const beginRes = await fetch('/api/passkey/login/begin', { method: 'POST' })
      if (!beginRes.ok) throw new Error('Failed to start passkey login')
      const data = await beginRes.json()

      const credential = await startAuthentication(data.publicKey)

      const finishRes = await fetch(`/api/passkey/login/finish?challengeKey=${encodeURIComponent(data.challengeKey)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credential),
      })

      if (!finishRes.ok) {
        const err = await finishRes.json()
        throw new Error(err.error || 'Passkey login failed')
      }

      const result = await finishRes.json()
      window.location.href = result.redirect || '/admin'
    } catch (e: any) {
      if (e.name === 'NotAllowedError') {
        error.value = 'Passkey authentication was cancelled'
      } else {
        error.value = e.message || 'Passkey login failed'
      }
    } finally {
      loading.value = false
    }
  }

  return (
    <div>
      <button
        type="button"
        onClick={handleLogin}
        disabled={loading.value}
        class="w-full flex items-center justify-center gap-2 bg-[rgba(255,255,255,0.05)] border border-border rounded-lg py-3 px-4 text-text-primary font-mono text-sm hover:bg-[rgba(255,255,255,0.08)] transition-colors disabled:opacity-50"
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z" />
          <circle cx="16.5" cy="7.5" r=".5" fill="currentColor" />
        </svg>
        {loading.value ? 'Authenticating...' : 'Sign in with Passkey'}
      </button>
      {error.value && <p class="text-danger text-xs mt-2 text-center">{error.value}</p>}
    </div>
  )
}
