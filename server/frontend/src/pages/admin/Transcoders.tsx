import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'
import { api } from '../../lib/api'
import { reportError, showToast } from '../../lib/toast'

interface Transcoder {
  name: string
  input: string
  output: string
  format: string
  bitrate: number
  enabled: boolean
  active: boolean
  frames_processed: number
  bytes_encoded: number
  uptime: string
  sample_rate?: number
  channels?: number
  opus_application?: string
  opus_vbr?: boolean
  opus_complexity?: number
  opus_frame_size_ms?: number
}

const transcoders = signal<Transcoder[]>([])
const loading = signal(true)
const showForm = signal(false)
const editingName = signal<string | null>(null)
const formName = signal('')
const formInput = signal('')
const formOutput = signal('')
const formFormat = signal('mp3')
const formBitrate = signal(128)
const formEnabled = signal(true)
const formSampleRate = signal(0)
const formOpusApp = signal('audio')
const formOpusVBR = signal(true)
const formOpusComplexity = signal(0)
const formOpusFrame = signal(20)
const formError = signal('')

function resetForm() {
  formName.value = ''
  formInput.value = ''
  formOutput.value = ''
  formFormat.value = 'mp3'
  formBitrate.value = 128
  formEnabled.value = true
  formSampleRate.value = 0
  formOpusApp.value = 'audio'
  formOpusVBR.value = true
  formOpusComplexity.value = 0
  formOpusFrame.value = 20
  editingName.value = null
  formError.value = ''
}

function openAddForm() {
  resetForm()
  showForm.value = true
}

function openEditForm(t: Transcoder) {
  resetForm()
  editingName.value = t.name
  formName.value = t.name
  formInput.value = t.input
  formOutput.value = t.output
  formFormat.value = t.format || 'mp3'
  formBitrate.value = t.bitrate || 128
  formEnabled.value = t.enabled
  formSampleRate.value = t.sample_rate || 0
  formOpusApp.value = t.opus_application || 'audio'
  formOpusVBR.value = t.opus_vbr ?? true
  formOpusComplexity.value = t.opus_complexity || 0
  formOpusFrame.value = t.opus_frame_size_ms || 20
  showForm.value = true
}

async function load() {
  loading.value = true
  try {
    transcoders.value = await api.get<Transcoder[]>('/api/transcoders')
  } catch (e) {
    reportError(e, 'Failed to load transcoders')
  }
  loading.value = false
}

function currentBody() {
  return {
    name: formName.value,
    input_mount: formInput.value,
    output_mount: formOutput.value,
    format: formFormat.value,
    bitrate: formBitrate.value,
    enabled: formEnabled.value,
    sample_rate: formSampleRate.value || undefined,
    opus_application: formFormat.value === 'opus' ? formOpusApp.value : undefined,
    opus_vbr: formFormat.value === 'opus' ? formOpusVBR.value : undefined,
    opus_complexity: formFormat.value === 'opus' && formOpusComplexity.value > 0 ? formOpusComplexity.value : undefined,
    opus_frame_size_ms: formFormat.value === 'opus' ? formOpusFrame.value : undefined,
  }
}

async function saveTranscoder() {
  formError.value = ''
  try {
    if (editingName.value) {
      await api.put(`/api/transcoders?name=${encodeURIComponent(editingName.value)}`, currentBody())
    } else {
      await api.post('/api/transcoders', currentBody())
    }
    showForm.value = false
    resetForm()
    load()
  } catch (e) {
    formError.value = (e as Error).message || 'Save failed'
  }
}

async function removeTranscoder(name: string) {
  try {
    await api.del(`/api/transcoders?name=${encodeURIComponent(name)}`)
    showToast('success', `Transcoder "${name}" removed`)
  } catch (e) {
    reportError(e, `Failed to remove transcoder "${name}"`)
  }
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
          onClick={openAddForm}
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
            <div key={t.name} class="border border-border rounded-xl bg-surface-raised p-5">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-3 flex-1 min-w-0">
                  {/* Visual flow */}
                  <span class="font-mono text-sm font-bold text-text-primary truncate">{t.input}</span>
                  <span class="text-text-tertiary">
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7" /></svg>
                  </span>
                  <span class="inline-flex items-center gap-1.5">
                    <span class="font-mono text-[10px] tracking-[1px] px-2 py-0.5 rounded bg-accent/10 text-accent uppercase">{t.format} {t.bitrate}k</span>
                  </span>
                  <span class="text-text-tertiary">
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7" /></svg>
                  </span>
                  <span class="font-mono text-sm font-bold text-text-primary truncate">{t.output}</span>
                </div>
                <div class="flex items-center gap-4 ml-4">
                  <div class="flex items-center gap-2">
                    <span class={`inline-block w-2 h-2 rounded-full ${t.active ? 'bg-live' : 'bg-text-tertiary'}`} />
                    <span class="text-xs text-text-tertiary">{t.active ? t.uptime : (t.enabled === false ? 'DISABLED' : 'OFF')}</span>
                  </div>
                  <button
                    onClick={() => openEditForm(t)}
                    title="Edit transcoder"
                    aria-label="Edit transcoder"
                    class="border border-border text-text-secondary font-mono text-xs px-2 py-1.5 rounded-lg hover:border-border-hover"
                  >
                    <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" /><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" /></svg>
                  </button>
                  <button
                    onClick={() => removeTranscoder(t.name)}
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

      {/* Add / Edit Transcoder Modal */}
      {showForm.value && (
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div class="bg-surface-overlay border border-border rounded-xl p-6 max-w-md w-full mx-4 max-h-[90vh] overflow-y-auto">
            <h2 class="text-lg font-bold text-text-primary mb-4">
              {editingName.value ? `Edit Transcoder "${editingName.value}"` : 'Add Transcoder'}
            </h2>
            <div class="flex flex-col gap-3">
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">NAME</label>
                <input
                  type="text"
                  value={formName.value}
                  onInput={(e) => { formName.value = (e.target as HTMLInputElement).value }}
                  placeholder="My Transcoder"
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
              </div>
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
              <div class="grid grid-cols-2 gap-3">
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
              <div>
                <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">SAMPLE RATE (HZ, 0 = AUTO)</label>
                <input
                  type="number"
                  value={formSampleRate.value}
                  onInput={(e) => { formSampleRate.value = parseInt((e.target as HTMLInputElement).value) || 0 }}
                  placeholder="0"
                  class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
                <p class="text-[10px] text-text-tertiary mt-1">Opus always emits at 48000 Hz regardless of this value.</p>
              </div>

              {formFormat.value === 'opus' && (
                <div class="border border-border rounded-lg p-3 flex flex-col gap-3">
                  <div class="font-mono text-[10px] tracking-[2px] text-text-tertiary">OPUS ENCODER</div>
                  <div class="grid grid-cols-2 gap-3">
                    <div>
                      <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">APPLICATION</label>
                      <select
                        value={formOpusApp.value}
                        onChange={(e) => { formOpusApp.value = (e.target as HTMLSelectElement).value }}
                        class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-3 py-2 text-text-primary font-mono text-xs focus:border-accent outline-none"
                      >
                        <option value="audio">Audio (music)</option>
                        <option value="voip">VoIP (speech)</option>
                        <option value="lowdelay">Low-delay</option>
                      </select>
                    </div>
                    <div>
                      <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">FRAME SIZE (MS)</label>
                      <select
                        value={String(formOpusFrame.value)}
                        onChange={(e) => { formOpusFrame.value = parseInt((e.target as HTMLSelectElement).value) || 20 }}
                        class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-3 py-2 text-text-primary font-mono text-xs focus:border-accent outline-none"
                      >
                        <option value="5">5</option>
                        <option value="10">10</option>
                        <option value="20">20</option>
                        <option value="40">40</option>
                        <option value="60">60</option>
                      </select>
                    </div>
                  </div>
                  <div>
                    <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">COMPLEXITY (0 = DEFAULT, 1-10)</label>
                    <input
                      type="number"
                      min={0}
                      max={10}
                      value={formOpusComplexity.value}
                      onInput={(e) => { formOpusComplexity.value = parseInt((e.target as HTMLInputElement).value) || 0 }}
                      class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-3 py-2 text-text-primary font-mono text-xs focus:border-accent outline-none"
                    />
                  </div>
                  <label class="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formOpusVBR.value}
                      onChange={(e) => { formOpusVBR.value = (e.target as HTMLInputElement).checked }}
                      class="accent-accent"
                    />
                    <span class="font-mono text-xs text-text-secondary">VBR (variable bitrate)</span>
                  </label>
                </div>
              )}

              <label class="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formEnabled.value}
                  onChange={(e) => { formEnabled.value = (e.target as HTMLInputElement).checked }}
                  class="accent-accent"
                />
                <span class="font-mono text-xs text-text-secondary">ENABLED (run this transcoder)</span>
              </label>

              {formError.value && (
                <div class="text-danger font-mono text-xs">{formError.value}</div>
              )}
            </div>
            <div class="flex justify-end gap-2 mt-6">
              <button
                onClick={() => { showForm.value = false; resetForm() }}
                class="border border-border text-text-secondary font-mono text-xs px-4 py-2.5 rounded-lg hover:border-border-hover"
              >
                CANCEL
              </button>
              <button
                onClick={saveTranscoder}
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
