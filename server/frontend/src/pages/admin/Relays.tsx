import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'
import { api } from '../../lib/api'
import { Toggle } from '../../components/Toggle'

interface Relay {
  url: string
  mount: string
  burst_size: number
  enabled: boolean
  active: boolean
}

const relays = signal<Relay[]>([])
const loading = signal(true)
const showForm = signal(false)
const formUrl = signal('')
const formMount = signal('')
const formPassword = signal('')
const formBurst = signal(65536)

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return `${h}h ${m}m`
}

async function load() {
  loading.value = true
  try {
    relays.value = await api.get<Relay[]>('/api/relays')
  } catch { /* empty */ }
  loading.value = false
}

async function addRelay() {
  await api.post('/api/relays', {
    url: formUrl.value,
    mount: formMount.value,
    password: formPassword.value || undefined,
    burst_size: formBurst.value,
  })
  showForm.value = false
  formUrl.value = ''
  formMount.value = ''
  formPassword.value = ''
  formBurst.value = 65536
  load()
}

async function toggleRelay(mount: string) {
  await api.post('/api/relays/toggle', { mount })
  load()
}

async function removeRelay(mount: string) {
  await api.del(`/api/relays?mount=${encodeURIComponent(mount)}`)
  load()
}

function statusColor(r: Relay): string {
  if (r.active) return 'bg-live'
  if (r.enabled) return 'bg-yellow-400'
  return 'bg-text-tertiary'
}

export function Relays() {
  useEffect(() => { load() }, [])

  return (
    <div class="p-7">
      <div class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1">MANAGE</div>
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-text-primary">Relays</h1>
        <button
          onClick={() => { showForm.value = true }}
          class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg"
        >
          ADD RELAY
        </button>
      </div>

      {loading.value ? (
        <p class="text-text-tertiary text-sm">Loading...</p>
      ) : relays.value.length === 0 ? (
        <p class="text-text-tertiary text-sm">No relays configured</p>
      ) : (
        <div class="grid gap-3">
          {relays.value.map((r) => (
            <div key={r.mount} class="border border-border rounded-xl bg-surface-raised p-5">
              <div class="flex items-start justify-between">
                <div class="flex-1 min-w-0">
                  <div class="flex items-center gap-2 mb-2">
                    <span class={`inline-block w-2 h-2 rounded-full ${statusColor(r)}`} />
                    <span class="font-mono text-sm font-bold text-text-primary truncate">{r.mount}</span>
                  </div>
                  <div class="font-mono text-xs text-text-secondary truncate mb-3">{r.url}</div>
                  <div class="flex items-center gap-4 text-xs text-text-tertiary">
                    <span>{r.active ? 'Connected' : r.enabled ? 'Connecting...' : 'Disabled'}</span>
                  </div>
                </div>
                <div class="flex items-center gap-3 ml-4">
                  <Toggle checked={r.enabled} onChange={() => toggleRelay(r.mount)} label="Enable relay" />
                  <button
                    onClick={() => removeRelay(r.mount)}
                    title="Remove relay"
                    class="border border-border text-danger font-mono text-xs px-2 py-1.5 rounded-lg hover:border-danger/30"
                  >
                    <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" /></svg>
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add Relay Modal */}
      {showForm.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div class="bg-surface-overlay border border-border rounded-xl p-6 max-w-md w-full mx-4">
            <h2 class="text-lg font-bold text-text-primary mb-4">Add Relay</h2>
            <div class="flex flex-col gap-3">
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">UPSTREAM URL</label>
                <input
                  type="text"
                  value={formUrl.value}
                  onInput={(e) => { formUrl.value = (e.target as HTMLInputElement).value }}
                  placeholder="http://upstream:8000/stream"
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
              </div>
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">LOCAL MOUNT</label>
                <input
                  type="text"
                  value={formMount.value}
                  onInput={(e) => { formMount.value = (e.target as HTMLInputElement).value }}
                  placeholder="/relay"
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
              </div>
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">PASSWORD (OPTIONAL)</label>
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
                onClick={() => { showForm.value = false }}
                class="border border-border text-text-secondary font-mono text-xs px-4 py-2.5 rounded-lg hover:border-border-hover"
              >
                CANCEL
              </button>
              <button
                onClick={addRelay}
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
