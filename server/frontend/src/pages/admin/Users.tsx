import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'
import { api } from '../../lib/api'

interface User {
  username: string
  role: 'superadmin' | 'admin'
}

const users = signal<User[]>([])
const loading = signal(true)
const showForm = signal(false)
const editingUser = signal<string | null>(null)
const formUsername = signal('')
const formPassword = signal('')
const formRole = signal<'superadmin' | 'admin'>('admin')

async function load() {
  loading.value = true
  try {
    users.value = await api.get<User[]>('/api/users')
  } catch { /* empty */ }
  loading.value = false
}

function openAdd() {
  editingUser.value = null
  formUsername.value = ''
  formPassword.value = ''
  formRole.value = 'admin'
  showForm.value = true
}

function openEdit(u: User) {
  editingUser.value = u.username
  formUsername.value = u.username
  formPassword.value = ''
  formRole.value = u.role
  showForm.value = true
}

async function saveUser() {
  if (editingUser.value) {
    const body: Record<string, string> = { username: editingUser.value, role: formRole.value }
    if (formPassword.value) body.password = formPassword.value
    await api.put('/api/users', body)
  } else {
    await api.post('/api/users', {
      username: formUsername.value,
      password: formPassword.value,
      role: formRole.value,
    })
  }
  showForm.value = false
  load()
}

async function removeUser(username: string) {
  await api.del(`/api/users?username=${encodeURIComponent(username)}`)
  load()
}

export function Users() {
  useEffect(() => { load() }, [])

  return (
    <div class="p-7">
      <div class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1">MANAGE</div>
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-text-primary">Users</h1>
        <button
          onClick={openAdd}
          class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg"
        >
          ADD USER
        </button>
      </div>

      {/* Table */}
      <div class="border border-border rounded-xl overflow-hidden">
        <table class="w-full">
          <thead>
            <tr class="border-b border-border">
              <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Username</th>
              <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Role</th>
              <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-right px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading.value ? (
              <tr><td colSpan={3} class="px-4 py-8 text-center text-text-tertiary text-sm">Loading...</td></tr>
            ) : users.value.length === 0 ? (
              <tr><td colSpan={3} class="px-4 py-8 text-center text-text-tertiary text-sm">No users</td></tr>
            ) : (
              users.value.map((u) => (
                <tr key={u.username} class="border-b border-[rgba(255,255,255,0.03)]">
                  <td class="px-4 py-3.5 font-mono text-sm text-text-primary">{u.username}</td>
                  <td class="px-4 py-3.5">
                    <span class={`inline-block font-mono text-[10px] tracking-[1px] uppercase px-2 py-0.5 rounded ${
                      u.role === 'superadmin' ? 'bg-accent/15 text-accent' : 'bg-surface-overlay text-text-secondary'
                    }`}>
                      {u.role}
                    </span>
                  </td>
                  <td class="px-4 py-3.5 text-right">
                    <div class="flex items-center justify-end gap-1">
                      <button
                        onClick={() => openEdit(u)}
                        title="Edit user"
                        class="border border-border text-text-secondary font-mono text-xs px-2 py-1.5 rounded-lg hover:border-border-hover"
                      >
                        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" /><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" /></svg>
                      </button>
                      <button
                        onClick={() => removeUser(u.username)}
                        title="Remove user"
                        class="border border-border text-danger font-mono text-xs px-2 py-1.5 rounded-lg hover:border-danger/30"
                      >
                        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" /></svg>
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Add/Edit User Modal */}
      {showForm.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div class="bg-surface-overlay border border-border rounded-xl p-6 max-w-md w-full mx-4">
            <h2 class="text-lg font-bold text-text-primary mb-4">
              {editingUser.value ? 'Edit User' : 'Add User'}
            </h2>
            <div class="flex flex-col gap-3">
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">USERNAME</label>
                <input
                  type="text"
                  value={formUsername.value}
                  onInput={(e) => { formUsername.value = (e.target as HTMLInputElement).value }}
                  disabled={!!editingUser.value}
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none disabled:opacity-50"
                />
              </div>
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">
                  PASSWORD{editingUser.value ? ' (LEAVE BLANK TO KEEP)' : ''}
                </label>
                <input
                  type="password"
                  value={formPassword.value}
                  onInput={(e) => { formPassword.value = (e.target as HTMLInputElement).value }}
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
              </div>
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">ROLE</label>
                <select
                  value={formRole.value}
                  onChange={(e) => { formRole.value = (e.target as HTMLSelectElement).value as 'superadmin' | 'admin' }}
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                >
                  <option value="admin">Admin</option>
                  <option value="superadmin">Superadmin</option>
                </select>
              </div>
            </div>
            <div class="flex justify-end gap-2 mt-6">
              <button
                onClick={() => { showForm.value = false }}
                class="border border-border text-text-secondary font-mono text-xs px-4 py-2.5 rounded-lg hover:border-border-hover"
              >
                CANCEL
              </button>
              <button
                onClick={saveUser}
                class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg"
              >
                SAVE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
