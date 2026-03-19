import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'

interface PendingUserData {
  id: string
  email: string
  name: string
  provider: string
  requested_at: string
}

const pendingUsers = signal<PendingUserData[]>([])
const loading = signal(true)
const approveModal = signal<PendingUserData | null>(null)
const approveUsername = signal('')
const approveRole = signal('dj')

async function fetchPending() {
  try {
    const res = await fetch('/api/pending-users')
    if (res.ok) {
      pendingUsers.value = await res.json()
    }
  } finally {
    loading.value = false
  }
}

async function approve(user: PendingUserData) {
  const res = await fetch('/api/pending-users/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: user.id, username: approveUsername.value, role: approveRole.value }),
  })
  if (res.ok) {
    approveModal.value = null
    approveUsername.value = ''
    fetchPending()
  }
}

async function deny(id: string) {
  await fetch('/api/pending-users/deny', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id }),
  })
  fetchPending()
}

export function PendingUsers() {
  useEffect(() => { fetchPending() }, [])

  return (
    <div class="p-6 max-w-4xl">
      <h1 class="text-text-primary font-mono text-xl font-bold mb-6">Pending Access Requests</h1>

      {loading.value && <p class="text-text-secondary">Loading...</p>}

      {!loading.value && pendingUsers.value.length === 0 && (
        <p class="text-text-tertiary">No pending requests.</p>
      )}

      {pendingUsers.value.length > 0 && (
        <div class="flex flex-col gap-3">
          {pendingUsers.value.map((user) => (
            <div key={user.id} class="bg-surface-raised border border-border rounded-lg p-4 flex items-center justify-between">
              <div>
                <p class="text-text-primary font-mono text-sm font-bold">{user.name || user.email}</p>
                <p class="text-text-secondary text-xs">{user.email} via {user.provider}</p>
                <p class="text-text-tertiary text-xs">{new Date(user.requested_at).toLocaleString()}</p>
              </div>
              <div class="flex gap-2">
                <button
                  onClick={() => { approveModal.value = user; approveUsername.value = user.email.split('@')[0] }}
                  class="bg-green-600 text-white font-mono text-xs px-3 py-1.5 rounded hover:bg-green-500 transition-colors"
                >
                  Approve
                </button>
                <button
                  onClick={() => deny(user.id)}
                  class="bg-red-600 text-white font-mono text-xs px-3 py-1.5 rounded hover:bg-red-500 transition-colors"
                >
                  Deny
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Approve Modal */}
      {approveModal.value && (
        <div class="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div class="bg-surface-raised border border-border rounded-xl p-6 w-full max-w-sm">
            <h2 class="text-text-primary font-mono text-lg font-bold mb-4">Approve User</h2>
            <p class="text-text-secondary text-sm mb-4">Approving {approveModal.value.email}</p>
            <div class="flex flex-col gap-3">
              <input
                type="text"
                value={approveUsername.value}
                onInput={(e) => approveUsername.value = (e.target as HTMLInputElement).value}
                placeholder="Username"
                class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2 text-text-primary font-mono text-sm"
              />
              <select
                value={approveRole.value}
                onChange={(e) => approveRole.value = (e.target as HTMLSelectElement).value}
                class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2 text-text-primary font-mono text-sm"
              >
                <option value="dj">DJ (stream only)</option>
                <option value="admin">Admin</option>
                <option value="superadmin">Super Admin</option>
              </select>
              <div class="flex gap-2 mt-2">
                <button
                  onClick={() => approve(approveModal.value!)}
                  class="flex-1 bg-green-600 text-white font-mono text-sm py-2 rounded hover:bg-green-500"
                >
                  Approve
                </button>
                <button
                  onClick={() => approveModal.value = null}
                  class="flex-1 bg-[rgba(255,255,255,0.05)] text-text-primary font-mono text-sm py-2 rounded hover:bg-[rgba(255,255,255,0.08)]"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
