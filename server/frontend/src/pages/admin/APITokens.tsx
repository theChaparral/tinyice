import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'
import { api } from '../../lib/api'

const copied = signal(false)

function fallbackCopy(text: string) {
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.select()
  document.execCommand('copy')
  document.body.removeChild(textarea)
  copied.value = true
  setTimeout(() => { copied.value = false }, 2000)
}

interface TokenInfo {
  id: number
  name: string
  username: string
  created_at: string
  last_used_at: string
  last_used_ip: string
  expires_at: string
  prefix: string
}

interface TokenCreateResponse {
  id: number
  token: string
  name: string
}

const tokens = signal<TokenInfo[]>([])
const loading = signal(true)
const showCreate = signal(false)
const createdToken = signal<string | null>(null)
const createdName = signal('')
const formName = signal('')
const formExpiry = signal('never')

function relativeTime(dateStr: string): string {
  if (!dateStr || dateStr === '0001-01-01T00:00:00Z') return 'Never'
  const now = Date.now()
  const then = new Date(dateStr).getTime()
  const diff = now - then
  if (diff < 0) {
    const absDiff = -diff
    const days = Math.floor(absDiff / 86400000)
    if (days > 365) return `in ${Math.floor(days / 365)}y`
    if (days > 30) return `in ${Math.floor(days / 30)}mo`
    if (days > 0) return `in ${days}d`
    const hours = Math.floor(absDiff / 3600000)
    if (hours > 0) return `in ${hours}h`
    const minutes = Math.floor(absDiff / 60000)
    if (minutes > 0) return `in ${minutes}m`
    return 'just now'
  }
  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} minute${minutes !== 1 ? 's' : ''} ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} hour${hours !== 1 ? 's' : ''} ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days} day${days !== 1 ? 's' : ''} ago`
  const months = Math.floor(days / 30)
  if (months < 12) return `${months} month${months !== 1 ? 's' : ''} ago`
  const years = Math.floor(months / 12)
  return `${years} year${years !== 1 ? 's' : ''} ago`
}

function formatDate(dateStr: string): string {
  if (!dateStr || dateStr === '0001-01-01T00:00:00Z') return 'Never'
  return new Date(dateStr).toLocaleDateString()
}

async function loadTokens() {
  loading.value = true
  try {
    tokens.value = await api.get<TokenInfo[]>('/api/tokens')
  } catch { /* empty */ }
  loading.value = false
}

async function createToken() {
  const name = formName.value.trim()
  if (!name) return
  let expires_at: string | undefined
  if (formExpiry.value !== 'never') {
    const now = new Date()
    const days = parseInt(formExpiry.value, 10)
    now.setDate(now.getDate() + days)
    expires_at = now.toISOString()
  }
  try {
    const result = await api.post<TokenCreateResponse>('/api/tokens', { name, expires_at })
    createdToken.value = result.token
    createdName.value = result.name
    showCreate.value = false
    formName.value = ''
    formExpiry.value = 'never'
    loadTokens()
  } catch { /* empty */ }
}

async function deleteToken(id: number, name: string) {
  if (!confirm(`Delete token "${name}"? This cannot be undone.`)) return
  try {
    await api.del(`/api/tokens?id=${id}`)
    loadTokens()
  } catch { /* empty */ }
}

export function APITokens() {
  useEffect(() => { loadTokens() }, [])

  return (
    <div class="p-7">
      {/* Header */}
      <div class="flex items-start justify-between mb-6">
        <div>
          <div class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1">MANAGE</div>
          <h1 class="text-xl font-bold text-text-primary">API Keys</h1>
        </div>
        <button
          onClick={() => { showCreate.value = true }}
          class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg"
        >
          CREATE TOKEN
        </button>
      </div>

      {/* Content */}
      {loading.value ? (
        <p class="text-text-tertiary text-sm">Loading...</p>
      ) : tokens.value.length === 0 ? (
        <p class="text-text-tertiary text-sm text-center py-12">No API tokens created yet</p>
      ) : (
        <div class="border border-border rounded-xl overflow-hidden">
          <table class="w-full">
            <thead>
              <tr class="border-b border-border">
                <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Name</th>
                <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Token</th>
                <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Owner</th>
                <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Created</th>
                <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Last Used</th>
                <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Expires</th>
                <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-right px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {tokens.value.map((t) => (
                <tr key={t.id} class="border-b border-[rgba(255,255,255,0.03)]">
                  <td class="px-4 py-3.5 text-sm font-bold text-text-primary">{t.name}</td>
                  <td class="px-4 py-3.5 font-mono text-sm text-text-tertiary">{t.prefix}...</td>
                  <td class="px-4 py-3.5 text-sm text-text-secondary">{t.username}</td>
                  <td class="px-4 py-3.5 text-sm text-text-secondary">{relativeTime(t.created_at)}</td>
                  <td class="px-4 py-3.5 text-sm text-text-secondary">
                    {t.last_used_at && t.last_used_at !== '0001-01-01T00:00:00Z'
                      ? <>{relativeTime(t.last_used_at)}{t.last_used_ip ? <span class="text-text-tertiary ml-1">({t.last_used_ip})</span> : null}</>
                      : 'Never'}
                  </td>
                  <td class="px-4 py-3.5 text-sm text-text-secondary">{formatDate(t.expires_at)}</td>
                  <td class="px-4 py-3.5 text-right">
                    <button
                      onClick={() => deleteToken(t.id, t.name)}
                      class="border border-border text-danger font-mono text-xs px-3 py-1.5 rounded-lg hover:border-danger/30"
                      title="Delete token"
                    >
                      <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="3 6 5 6 21 6" />
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                      </svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Token Modal */}
      {showCreate.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div class="bg-surface-overlay border border-border rounded-xl p-6 max-w-md w-full mx-4">
            <h2 class="text-lg font-bold text-text-primary mb-4">Create API Token</h2>

            <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary uppercase block mb-1.5">Name</label>
            <input
              type="text"
              value={formName.value}
              onInput={(e) => { formName.value = (e.target as HTMLInputElement).value }}
              placeholder="My integration"
              class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none mb-4"
            />

            <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary uppercase block mb-1.5">Expiry</label>
            <select
              value={formExpiry.value}
              onChange={(e) => { formExpiry.value = (e.target as HTMLSelectElement).value }}
              class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none mb-6"
            >
              <option value="never">Never</option>
              <option value="30">30 days</option>
              <option value="90">90 days</option>
              <option value="365">1 year</option>
            </select>

            <div class="flex gap-3 justify-end">
              <button
                onClick={() => { showCreate.value = false; formName.value = ''; formExpiry.value = 'never' }}
                class="border border-border text-text-secondary font-mono text-xs px-4 py-2.5 rounded-lg hover:border-border-hover"
              >
                CANCEL
              </button>
              <button
                onClick={createToken}
                class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg"
              >
                CREATE
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Token Created Modal */}
      {createdToken.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div class="bg-surface-overlay border border-border rounded-xl p-6 max-w-md w-full mx-4">
            <h2 class="text-lg font-bold text-text-primary mb-2">Token Created</h2>
            <p class="text-sm text-danger mb-4">Copy this token now. It won't be shown again.</p>

            <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary uppercase block mb-1.5">Name</label>
            <p class="text-sm text-text-primary mb-3">{createdName.value}</p>

            <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary uppercase block mb-1.5">Token</label>
            <div class="flex gap-2 mb-6">
              <code class="flex-1 bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 font-mono text-sm text-text-primary break-all select-all">
                {createdToken.value}
              </code>
              <button
                onClick={() => {
                  const token = createdToken.value
                  if (!token) return
                  if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(token).then(() => {
                      copied.value = true
                      setTimeout(() => { copied.value = false }, 2000)
                    }).catch(() => {
                      // Fallback for non-secure contexts
                      fallbackCopy(token)
                    })
                  } else {
                    fallbackCopy(token)
                  }
                }}
                class={`border font-mono text-xs px-4 py-2.5 rounded-lg shrink-0 transition-colors ${
                  copied.value
                    ? 'border-green-500/30 text-green-400'
                    : 'border-border text-text-secondary hover:border-border-hover'
                }`}
              >
                {copied.value ? 'COPIED' : 'COPY'}
              </button>
            </div>

            <div class="flex justify-end">
              <button
                onClick={() => { createdToken.value = null; createdName.value = ''; copied.value = false }}
                class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg"
              >
                DONE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
