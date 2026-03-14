import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'
import { api } from '../../lib/api'
import { Toggle } from '../../components/Toggle'

interface Transcoder {
  id: string
  inputMount: string
  outputMount: string
  format: string
  bitrate: number
  enabled: boolean
  listeners: number
  status: string
}

const transcoders = signal<Transcoder[]>([])
const loading = signal(true)
const showForm = signal(false)
const formInput = signal('')
const formOutput = signal('')
const formFormat = signal('mp3')
const formBitrate = signal(128)

async function load() {
  loading.value = true
  try {
    transcoders.value = await api.get<Transcoder[]>('/api/transcoders')
  } catch { /* empty */ }
  loading.value = false
}

async function addTranscoder() {
  await api.post('/api/transcoders', {
    inputMount: formInput.value,
    outputMount: formOutput.value,
    format: formFormat.value,
    bitrate: formBitrate.value,
  })
  showForm.value = false
  formInput.value = ''
  formOutput.value = ''
  formFormat.value = 'mp3'
  formBitrate.value = 128
  load()
}

async function toggleTranscoder(id: string) {
  await api.put(`/api/transcoders/${encodeURIComponent(id)}/toggle`)
  load()
}

async function removeTranscoder(id: string) {
  await api.del(`/api/transcoders/${encodeURIComponent(id)}`)
  load()
}

export function Transcoders() {
  useEffect(() => { load() }, [])

  return (
    <div class="p-7">
      <div class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1">MANAGE</div>
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-text-primary">Transcoders</h1>
        <button
          onClick={() => { showForm.value = true }}
          class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg"
        >
          ADD TRANSCODER
        </button>
      </div>

      {loading.value ? (
        <p class="text-text-tertiary text-sm">Loading...</p>
      ) : transcoders.value.length === 0 ? (
        <p class="text-text-tertiary text-sm">No transcoders configured</p>
      ) : (
        <div class="grid gap-3">
          {transcoders.value.map((t) => (
            <div key={t.id} class="border border-border rounded-xl bg-surface-raised p-5">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-3 flex-1 min-w-0">
                  {/* Visual flow */}
                  <span class="font-mono text-sm font-bold text-text-primary truncate">{t.inputMount}</span>
                  <span class="text-text-tertiary">
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7" /></svg>
                  </span>
                  <span class="inline-flex items-center gap-1.5">
                    <span class="font-mono text-[10px] tracking-[1px] px-2 py-0.5 rounded bg-accent/10 text-accent uppercase">{t.format} {t.bitrate}k</span>
                  </span>
                  <span class="text-text-tertiary">
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7" /></svg>
                  </span>
                  <span class="font-mono text-sm font-bold text-text-primary truncate">{t.outputMount}</span>
                </div>
                <div class="flex items-center gap-4 ml-4">
                  <div class="flex items-center gap-2">
                    <span class={`inline-block w-2 h-2 rounded-full ${t.status === 'running' ? 'bg-live' : 'bg-text-tertiary'}`} />
                    <span class="text-xs text-text-tertiary">{t.listeners} listeners</span>
                  </div>
                  <Toggle checked={t.enabled} onChange={() => toggleTranscoder(t.id)} label="Enable transcoder" />
                  <button
                    onClick={() => removeTranscoder(t.id)}
                    title="Remove transcoder"
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

      {/* Add Transcoder Modal */}
      {showForm.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div class="bg-surface-overlay border border-border rounded-xl p-6 max-w-md w-full mx-4">
            <h2 class="text-lg font-bold text-text-primary mb-4">Add Transcoder</h2>
            <div class="flex flex-col gap-3">
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">INPUT MOUNT</label>
                <input
                  type="text"
                  value={formInput.value}
                  onInput={(e) => { formInput.value = (e.target as HTMLInputElement).value }}
                  placeholder="/stream"
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
              </div>
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">OUTPUT MOUNT</label>
                <input
                  type="text"
                  value={formOutput.value}
                  onInput={(e) => { formOutput.value = (e.target as HTMLInputElement).value }}
                  placeholder="/stream-128"
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
              </div>
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">FORMAT</label>
                <select
                  value={formFormat.value}
                  onChange={(e) => { formFormat.value = (e.target as HTMLSelectElement).value }}
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                >
                  <option value="mp3">MP3</option>
                  <option value="opus">Opus</option>
                </select>
              </div>
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">BITRATE (KBPS)</label>
                <input
                  type="number"
                  value={formBitrate.value}
                  onInput={(e) => { formBitrate.value = parseInt((e.target as HTMLInputElement).value) || 0 }}
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
                onClick={addTranscoder}
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
