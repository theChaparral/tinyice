import { signal, computed } from '@preact/signals'
import { startRegistration } from '@simplewebauthn/browser'

const step = signal(0)
const token = signal('')
const username = signal('admin')
const password = signal('')
const confirmPassword = signal('')
const error = signal('')
const loading = signal(false)
const setupResult = signal<any>(null)
const passkeyRegistered = signal(false)

const passwordsMatch = computed(() => password.value === confirmPassword.value)

export function Setup() {
  async function verifyToken() {
    loading.value = true
    error.value = ''
    try {
      const res = await fetch('/setup/verify-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token.value }),
      })
      const data = await res.json()
      if (data.valid) {
        step.value = 1
      } else {
        error.value = data.error || 'Invalid token'
      }
    } catch {
      error.value = 'Network error'
    } finally {
      loading.value = false
    }
  }

  async function completeSetup() {
    if (!passwordsMatch.value) {
      error.value = 'Passwords do not match'
      return
    }
    if (password.value.length < 8) {
      error.value = 'Password must be at least 8 characters'
      return
    }

    loading.value = true
    error.value = ''
    try {
      const res = await fetch('/setup/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: token.value,
          username: username.value,
          password: password.value,
        }),
      })
      const data = await res.json()
      if (data.success) {
        setupResult.value = data
        step.value = 2
      } else {
        error.value = data.error || 'Setup failed'
      }
    } catch {
      error.value = 'Network error'
    } finally {
      loading.value = false
    }
  }

  async function registerPasskey() {
    loading.value = true
    error.value = ''
    try {
      const beginRes = await fetch('/api/passkey/register/begin', { method: 'POST' })
      if (!beginRes.ok) throw new Error('Failed to start registration')
      const options = await beginRes.json()

      const credential = await startRegistration(options)

      const finishRes = await fetch('/api/passkey/register/finish?name=Setup+Passkey', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credential),
      })

      if (finishRes.ok) {
        passkeyRegistered.value = true
      } else {
        const err = await finishRes.json()
        throw new Error(err.error || 'Registration failed')
      }
    } catch (e: any) {
      if (e.name !== 'NotAllowedError') {
        error.value = e.message
      }
    } finally {
      loading.value = false
    }
  }

  const inputClass = "bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-3 text-text-primary font-mono text-sm placeholder:text-text-tertiary focus:outline-none focus:border-accent/40 transition-colors w-full"
  const btnClass = "bg-accent text-surface-base font-mono font-bold tracking-[1px] rounded-lg py-3 w-full text-sm hover:bg-accent/90 transition-colors disabled:opacity-50"
  const btnSecondary = "bg-[rgba(255,255,255,0.05)] border border-border text-text-primary font-mono text-sm rounded-lg py-3 w-full hover:bg-[rgba(255,255,255,0.08)] transition-colors"

  return (
    <div class="min-h-screen bg-surface-base flex items-center justify-center px-4">
      <div class="w-full max-w-md">
        {/* Logo */}
        <div class="flex items-center justify-center gap-3 mb-8">
          <div class="h-8 w-8 rounded bg-accent flex items-center justify-center">
            <span class="font-mono text-xs font-bold text-surface-base leading-none">Ti</span>
          </div>
          <span class="font-mono text-sm font-bold tracking-widest text-text-primary">TINYICE SETUP</span>
        </div>

        <div class="bg-surface-raised border border-border rounded-xl p-8">
          {/* Step 0: Token */}
          {step.value === 0 && (
            <div class="flex flex-col gap-4">
              <h2 class="text-text-primary font-mono text-lg font-bold">Welcome to TinyIce</h2>
              <p class="text-text-secondary text-sm">Enter the setup token from your terminal to begin.</p>
              <input
                type="text"
                value={token.value}
                onInput={(e) => token.value = (e.target as HTMLInputElement).value}
                placeholder="Setup Token"
                class={inputClass}
                autoFocus
              />
              <button onClick={verifyToken} disabled={loading.value || !token.value} class={btnClass}>
                {loading.value ? 'Verifying...' : 'Continue'}
              </button>
            </div>
          )}

          {/* Step 1: Credentials */}
          {step.value === 1 && (
            <div class="flex flex-col gap-4">
              <h2 class="text-text-primary font-mono text-lg font-bold">Set Admin Credentials</h2>
              <p class="text-text-secondary text-sm">Choose your admin username and password.</p>
              <input
                type="text"
                value={username.value}
                onInput={(e) => username.value = (e.target as HTMLInputElement).value}
                placeholder="Username"
                autocomplete="username"
                class={inputClass}
              />
              <input
                type="password"
                value={password.value}
                onInput={(e) => password.value = (e.target as HTMLInputElement).value}
                placeholder="Password (min 8 characters)"
                autocomplete="new-password"
                class={inputClass}
              />
              <input
                type="password"
                value={confirmPassword.value}
                onInput={(e) => confirmPassword.value = (e.target as HTMLInputElement).value}
                placeholder="Confirm Password"
                autocomplete="new-password"
                class={`${inputClass} ${confirmPassword.value && !passwordsMatch.value ? 'border-danger' : ''}`}
              />
              <button onClick={completeSetup} disabled={loading.value || !username.value || !password.value || !passwordsMatch.value} class={btnClass}>
                {loading.value ? 'Creating...' : 'Create Admin Account'}
              </button>
            </div>
          )}

          {/* Step 2: Passkey (optional) */}
          {step.value === 2 && (
            <div class="flex flex-col gap-4">
              <h2 class="text-text-primary font-mono text-lg font-bold">
                {passkeyRegistered.value ? 'Passkey Registered!' : 'Register a Passkey'}
              </h2>

              {setupResult.value && (
                <div class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg p-4 text-sm font-mono">
                  <p class="text-text-secondary mb-2">Source passwords (save these):</p>
                  <p class="text-text-primary">Default: <span class="text-accent">{setupResult.value.default_source_pass}</span></p>
                  <p class="text-text-primary">Mount /live: <span class="text-accent">{setupResult.value.live_mount_pass}</span></p>
                </div>
              )}

              {!passkeyRegistered.value && typeof PublicKeyCredential !== 'undefined' && (
                <>
                  <p class="text-text-secondary text-sm">Add a passkey for quick, passwordless login. You can skip this and add one later.</p>
                  <button onClick={registerPasskey} disabled={loading.value} class={btnSecondary}>
                    {loading.value ? 'Registering...' : 'Register Passkey'}
                  </button>
                </>
              )}

              {passkeyRegistered.value && (
                <p class="text-green-400 text-sm">Your passkey has been registered successfully.</p>
              )}

              <a href="/admin" class={btnClass + ' text-center no-underline block'}>
                {passkeyRegistered.value ? 'Go to Dashboard' : 'Skip & Go to Dashboard'}
              </a>
            </div>
          )}

          {error.value && (
            <p class="text-danger text-sm mt-3 text-center">{error.value}</p>
          )}

          {/* Progress dots */}
          <div class="flex justify-center gap-2 mt-6">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                class={`w-2 h-2 rounded-full ${step.value >= i ? 'bg-accent' : 'bg-border'}`}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
