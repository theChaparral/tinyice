import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'
import { api } from '../../lib/api'

interface Stream {
  mount: string
  sourceIp: string
  format: string
  listeners: number
  live: boolean
}

const streams = signal<Stream[]>([])
const loading = signal(true)
const showModal = signal(false)
const formMount = signal('')
const formPassword = signal('')
const formBurst = signal(65536)

async function load() {
  loading.value = true
  try {
    streams.value = await api.get<Stream[]>('/api/streams')
  } catch { /* empty */ }
  loading.value = false
}

async function addMount() {
  await api.post('/api/streams', {
    mount: formMount.value,
    password: formPassword.value,
    burstSize: formBurst.value,
  })
  showModal.value = false
  formMount.value = ''
  formPassword.value = ''
  formBurst.value = 65536
  load()
}

async function removeMount(mount: string) {
  await api.del(`/api/streams/${encodeURIComponent(mount)}`)
  load()
}

async function kickSource(mount: string) {
  await api.post(`/api/streams/${encodeURIComponent(mount)}/kick`, { type: 'source' })
  load()
}

async function kickListeners(mount: string) {
  await api.post(`/api/streams/${encodeURIComponent(mount)}/kick`, { type: 'listeners' })
  load()
}

export function Streams() {
  useEffect(() => { load() }, [])

  return (
    <div class="p-7">
      <div class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1">MANAGE</div>
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-text-primary">Streams</h1>
        <button
          onClick={() => { showModal.value = true }}
          class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg"
        >
          ADD MOUNT
        </button>
      </div>

      {/* Table */}
      <div class="border border-border rounded-xl overflow-hidden">
        <table class="w-full">
          <thead>
            <tr class="border-b border-border">
              <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Status</th>
              <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Mount</th>
              <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Source IP</th>
              <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Format</th>
              <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">Listeners</th>
              <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-right px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading.value ? (
              <tr><td colSpan={6} class="px-4 py-8 text-center text-text-tertiary text-sm">Loading...</td></tr>
            ) : streams.value.length === 0 ? (
              <tr><td colSpan={6} class="px-4 py-8 text-center text-text-tertiary text-sm">No streams configured</td></tr>
            ) : (
              streams.value.map((s) => (
                <tr key={s.mount} class="border-b border-[rgba(255,255,255,0.03)]">
                  <td class="px-4 py-3.5">
                    <span class={`inline-block w-2 h-2 rounded-full ${s.live ? 'bg-live' : 'bg-text-tertiary'}`} />
                  </td>
                  <td class="px-4 py-3.5 font-mono font-bold text-sm text-text-primary">{s.mount}</td>
                  <td class="px-4 py-3.5 text-sm text-text-secondary">{s.sourceIp || 'No source'}</td>
                  <td class="px-4 py-3.5 text-sm text-text-secondary">{s.format || '—'}</td>
                  <td class="px-4 py-3.5 font-mono text-sm text-text-primary">{s.listeners}</td>
                  <td class="px-4 py-3.5 text-right">
                    <div class="flex items-center justify-end gap-1">
                      <button
                        onClick={() => kickSource(s.mount)}
                        title="Kick source"
                        class="border border-border text-text-secondary font-mono text-xs px-2 py-1.5 rounded-lg hover:border-border-hover"
                      >
                        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.36 6.64A9 9 0 005.64 18.36M5.64 5.64A9 9 0 0018.36 18.36" /><line x1="1" y1="1" x2="23" y2="23" /></svg>
                      </button>
                      <button
                        onClick={() => kickListeners(s.mount)}
                        title="Kick listeners"
                        class="border border-border text-text-secondary font-mono text-xs px-2 py-1.5 rounded-lg hover:border-border-hover"
                      >
                        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4-4v2" /><circle cx="9" cy="7" r="4" /><line x1="18" y1="8" x2="23" y2="13" /><line x1="23" y1="8" x2="18" y2="13" /></svg>
                      </button>
                      <button
                        onClick={() => removeMount(s.mount)}
                        title="Remove mount"
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

      {/* Add Mount Modal */}
      {showModal.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div class="bg-surface-overlay border border-border rounded-xl p-6 max-w-md w-full mx-4">
            <h2 class="text-lg font-bold text-text-primary mb-4">Add Mount</h2>
            <div class="flex flex-col gap-3">
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">MOUNT PATH</label>
                <input
                  type="text"
                  value={formMount.value}
                  onInput={(e) => { formMount.value = (e.target as HTMLInputElement).value }}
                  placeholder="/stream"
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
              </div>
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">SOURCE PASSWORD</label>
                <input
                  type="password"
                  value={formPassword.value}
                  onInput={(e) => { formPassword.value = (e.target as HTMLInputElement).value }}
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
              </div>
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">BURST SIZE</label>
                <input
                  type="number"
                  value={formBurst.value}
                  onInput={(e) => { formBurst.value = parseInt((e.target as HTMLInputElement).value) || 0 }}
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
              </div>
            </div>
            <div class="flex justify-end gap-2 mt-6">
              <button
                onClick={() => { showModal.value = false }}
                class="border border-border text-text-secondary font-mono text-xs px-4 py-2.5 rounded-lg hover:border-border-hover"
              >
                CANCEL
              </button>
              <button
                onClick={addMount}
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
