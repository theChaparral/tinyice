import { useEffect } from 'preact/hooks'
import { signal, computed } from '@preact/signals'
import { api } from '@/lib/api'
import { showToast, reportError } from '@/lib/toast'

// ---------------------------------------------------------------------------
// Types — kept in sync with config.WebhookConfig and the /api/webhooks/meta
// shape on the server. When the server schema changes, update both ends.
// ---------------------------------------------------------------------------

interface Webhook {
  id: string
  name?: string
  url: string
  method?: string
  events: string[]
  headers?: Record<string, string>
  body_template?: string
  content_type?: string
  enabled: boolean
}

interface EventInfo {
  name: string
  description: string
  sample: Record<string, unknown>
  placeholders: string[]
}

interface Preset {
  id: string
  name: string
  description: string
  url_hint: string
  events: string[]
  method: string
  content_type: string
  headers?: Record<string, string>
  body: string
}

interface FuncDoc {
  name: string
  description: string
  example: string
}

interface WebhookMeta {
  events: EventInfo[]
  presets: Preset[]
  funcs: FuncDoc[]
}

// ---------------------------------------------------------------------------
// Page-level state. Signals are deliberately top-level so the form can be
// shared across the create/edit codepaths without prop-drilling — same
// pattern used by the rest of the admin pages (AutoDJ.tsx, Relays.tsx).
// ---------------------------------------------------------------------------

const webhooks = signal<Webhook[]>([])
const meta = signal<WebhookMeta | null>(null)
const loading = signal(true)
const showForm = signal(false)
const editingId = signal<string | null>(null)
const saveError = signal('')

const formName = signal('')
const formURL = signal('')
const formMethod = signal('POST')
const formContentType = signal('application/json')
const formEvents = signal<string[]>(['now_playing'])
const formHeaders = signal<Array<{ key: string; value: string }>>([])
const formBodyTemplate = signal('')
const formEnabled = signal(true)
const formActiveEvent = signal('now_playing') // which event's placeholders to show in the helper

function resetForm() {
  saveError.value = ''
  editingId.value = null
  formName.value = ''
  formURL.value = ''
  formMethod.value = 'POST'
  formContentType.value = 'application/json'
  formEvents.value = ['now_playing']
  formHeaders.value = []
  formBodyTemplate.value = ''
  formEnabled.value = true
  formActiveEvent.value = 'now_playing'
}

function openEdit(wh: Webhook) {
  editingId.value = wh.id
  formName.value = wh.name || ''
  formURL.value = wh.url
  formMethod.value = wh.method || 'POST'
  formContentType.value = wh.content_type || 'application/json'
  formEvents.value = [...wh.events]
  formHeaders.value = wh.headers
    ? Object.entries(wh.headers).map(([key, value]) => ({ key, value }))
    : []
  formBodyTemplate.value = wh.body_template || ''
  formEnabled.value = wh.enabled
  formActiveEvent.value = wh.events[0] || 'now_playing'
  saveError.value = ''
  showForm.value = true
}

function applyPreset(presetId: string) {
  const preset = meta.value?.presets.find((p) => p.id === presetId)
  if (!preset) return
  // Only fill URL if the user hasn't typed one yet — the URL hint is a
  // template (e.g. "https://discord.com/api/webhooks/<id>/<token>") and
  // overwriting a real URL would lose the operator's credentials.
  if (!formURL.value.trim()) {
    formURL.value = preset.url_hint
  }
  formMethod.value = preset.method || 'POST'
  formContentType.value = preset.content_type || 'application/json'
  formBodyTemplate.value = preset.body
  formHeaders.value = preset.headers
    ? Object.entries(preset.headers).map(([key, value]) => ({ key, value }))
    : []
  // Subscribe to the events this preset is designed for, but only if the
  // user is on a brand-new form. Otherwise keep their event selection.
  if (!editingId.value && preset.events.length > 0) {
    formEvents.value = [...preset.events]
    formActiveEvent.value = preset.events[0]
  }
  showToast('info', `Loaded preset: ${preset.name}`, 2500)
}

function toggleEvent(name: string) {
  const set = new Set(formEvents.value)
  if (set.has(name)) {
    set.delete(name)
  } else {
    set.add(name)
  }
  formEvents.value = Array.from(set)
}

function addHeaderRow() {
  formHeaders.value = [...formHeaders.value, { key: '', value: '' }]
}

function removeHeaderRow(idx: number) {
  formHeaders.value = formHeaders.value.filter((_, i) => i !== idx)
}

function updateHeader(idx: number, field: 'key' | 'value', value: string) {
  formHeaders.value = formHeaders.value.map((h, i) =>
    i === idx ? { ...h, [field]: value } : h
  )
}

function buildBody() {
  const headerObj: Record<string, string> = {}
  for (const { key, value } of formHeaders.value) {
    if (key.trim()) headerObj[key.trim()] = value
  }
  return {
    name: formName.value.trim(),
    url: formURL.value.trim(),
    method: formMethod.value,
    events: formEvents.value,
    headers: headerObj,
    body_template: formBodyTemplate.value,
    content_type: formContentType.value.trim(),
    enabled: formEnabled.value,
  }
}

async function saveWebhook() {
  saveError.value = ''
  const body = buildBody()
  if (!body.url) {
    saveError.value = 'URL is required'
    return
  }
  if (body.events.length === 0) {
    saveError.value = 'Pick at least one event to subscribe to'
    return
  }
  try {
    if (editingId.value) {
      await api.put(`/api/webhooks?id=${encodeURIComponent(editingId.value)}`, body)
      showToast('success', 'Webhook updated')
    } else {
      await api.post('/api/webhooks', body)
      showToast('success', 'Webhook created')
    }
    showForm.value = false
    resetForm()
    loadWebhooks()
  } catch (e) {
    saveError.value = (e as Error).message || 'Save failed'
  }
}

async function deleteWebhook(wh: Webhook) {
  const label = wh.name || wh.url
  if (!confirm(`Delete webhook "${label}"? This cannot be undone.`)) return
  try {
    await api.del(`/api/webhooks?id=${encodeURIComponent(wh.id)}`)
    showToast('success', 'Webhook deleted')
    loadWebhooks()
  } catch (e) {
    reportError(e, 'Failed to delete webhook')
  }
}

async function toggleEnabled(wh: Webhook) {
  try {
    await api.put(`/api/webhooks?id=${encodeURIComponent(wh.id)}`, {
      ...wh,
      enabled: !wh.enabled,
    })
    loadWebhooks()
  } catch (e) {
    reportError(e, 'Failed to toggle webhook')
  }
}

async function testWebhook(wh: Webhook, event?: string) {
  const eventName = event || wh.events[0] || 'now_playing'
  try {
    await api.post(
      `/api/webhooks/test?id=${encodeURIComponent(wh.id)}&event=${encodeURIComponent(eventName)}`,
    )
    showToast('success', `Test "${eventName}" dispatched — check your receiver and the server logs`)
  } catch (e) {
    reportError(e, 'Failed to send test webhook')
  }
}

async function loadWebhooks() {
  loading.value = true
  try {
    const list = await api.get<Webhook[] | null>('/api/webhooks')
    webhooks.value = list || []
  } catch {
    webhooks.value = []
  }
  loading.value = false
}

async function loadMeta() {
  try {
    meta.value = await api.get<WebhookMeta>('/api/webhooks/meta')
  } catch {
    meta.value = null
  }
}

// Computed: placeholders visible in the editor's helper panel for the
// event the user is currently focused on. Recomputes when the active
// event tab changes.
const activePlaceholders = computed<string[]>(() => {
  if (!meta.value) return []
  const ev = meta.value.events.find((e) => e.name === formActiveEvent.value)
  return ev ? ev.placeholders : []
})

const activeSample = computed<Record<string, unknown>>(() => {
  if (!meta.value) return {}
  const ev = meta.value.events.find((e) => e.name === formActiveEvent.value)
  return ev ? ev.sample : {}
})

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

function WebhookCard({ wh }: { wh: Webhook }) {
  const label = wh.name || wh.url
  return (
    <div class="bg-surface-raised border border-border rounded-xl p-5 hover:border-border-hover transition-colors">
      <div class="flex items-start justify-between gap-3 mb-3">
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2 mb-1">
            <span
              class={`w-2 h-2 rounded-full flex-shrink-0 ${
                wh.enabled ? 'bg-live' : 'bg-text-tertiary'
              }`}
              title={wh.enabled ? 'Enabled' : 'Disabled'}
            />
            <h3 class="text-text-primary font-medium truncate">{label}</h3>
            <span class="text-[10px] font-mono text-text-tertiary uppercase tracking-wider px-1.5 py-0.5 border border-border rounded">
              {wh.method || 'POST'}
            </span>
          </div>
          {wh.name && (
            <div class="text-[11px] font-mono text-text-tertiary truncate" title={wh.url}>
              {wh.url}
            </div>
          )}
          <div class="flex flex-wrap gap-1 mt-2">
            {wh.events.map((e) => (
              <span
                key={e}
                class="text-[10px] font-mono px-2 py-0.5 rounded bg-accent/10 text-accent"
              >
                {e}
              </span>
            ))}
          </div>
        </div>
        <div class="flex items-center gap-1 flex-shrink-0">
          <button
            onClick={() => testWebhook(wh)}
            class="h-8 px-3 rounded-lg border border-border text-[11px] font-mono text-text-secondary hover:text-accent hover:border-accent/30 transition-colors"
            title={`Send a sample ${wh.events[0] || 'now_playing'} payload`}
          >
            Test
          </button>
          <button
            onClick={() => toggleEnabled(wh)}
            class="h-8 px-3 rounded-lg border border-border text-[11px] font-mono text-text-secondary hover:text-text-primary hover:border-border-hover transition-colors"
          >
            {wh.enabled ? 'Disable' : 'Enable'}
          </button>
          <button
            onClick={() => openEdit(wh)}
            class="w-8 h-8 rounded-lg border border-border flex items-center justify-center text-text-secondary hover:text-accent hover:border-accent/30 transition-colors"
            aria-label="Edit"
            title="Edit"
          >
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" />
              <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" />
            </svg>
          </button>
          <button
            onClick={() => deleteWebhook(wh)}
            class="w-8 h-8 rounded-lg border border-border flex items-center justify-center text-danger hover:border-danger/30 transition-colors"
            aria-label="Delete"
            title="Delete"
          >
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="3 6 5 6 21 6" />
              <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  )
}

function PlaceholderHelper() {
  if (!meta.value) return null
  const events = meta.value.events
  return (
    <div class="bg-[rgba(255,255,255,0.02)] border border-border rounded-lg p-3">
      <div class="flex items-center justify-between mb-2">
        <span class="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          Placeholders & sample payload
        </span>
        <select
          value={formActiveEvent.value}
          onChange={(e) => { formActiveEvent.value = (e.target as HTMLSelectElement).value }}
          class="bg-[rgba(255,255,255,0.03)] border border-border rounded px-2 py-1 text-[11px] font-mono text-text-secondary"
        >
          {events.map((ev) => (
            <option key={ev.name} value={ev.name}>{ev.name}</option>
          ))}
        </select>
      </div>
      <div class="flex flex-wrap gap-1 mb-2">
        {activePlaceholders.value.map((ph) => (
          <button
            key={ph}
            type="button"
            onClick={() => {
              const insertion = `{{.${ph}}}`
              formBodyTemplate.value = formBodyTemplate.value + insertion
            }}
            class="text-[10px] font-mono px-1.5 py-0.5 rounded border border-border text-text-secondary hover:text-accent hover:border-accent/30 transition-colors"
            title={`Insert {{.${ph}}}`}
          >
            {`{{.${ph}}}`}
          </button>
        ))}
      </div>
      <details>
        <summary class="text-[10px] font-mono uppercase tracking-wider text-text-tertiary cursor-pointer">
          Sample payload
        </summary>
        <pre class="text-[10px] font-mono text-text-secondary mt-2 whitespace-pre-wrap">
{JSON.stringify(activeSample.value, null, 2)}
        </pre>
      </details>
      {meta.value.funcs.length > 0 && (
        <details class="mt-2">
          <summary class="text-[10px] font-mono uppercase tracking-wider text-text-tertiary cursor-pointer">
            Template functions
          </summary>
          <ul class="text-[11px] text-text-secondary mt-2 space-y-1">
            {meta.value.funcs.map((f) => (
              <li key={f.name}>
                <code class="text-accent">{f.name}</code> — {f.description}
                {' '}
                <code class="text-text-tertiary">{f.example}</code>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  )
}

function FormModal() {
  if (!showForm.value) return null
  return (
    <div class="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div class="bg-surface-raised border border-border rounded-xl p-6 w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-lg font-bold text-text-primary">
            {editingId.value ? 'Edit Webhook' : 'New Webhook'}
          </h2>
          <button
            onClick={() => { showForm.value = false; resetForm() }}
            class="text-text-tertiary hover:text-text-primary"
            aria-label="Close"
          >
            <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-3">
            {/* Preset picker */}
            {meta.value && meta.value.presets.length > 0 && (
              <div>
                <label class="text-text-secondary text-xs font-mono tracking-wider uppercase mb-1.5 block">
                  Load preset
                </label>
                <select
                  onChange={(e) => {
                    const v = (e.target as HTMLSelectElement).value
                    if (v) applyPreset(v)
                    ;(e.target as HTMLSelectElement).value = ''
                  }}
                  class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-3 py-2 text-text-primary font-mono text-sm focus:border-accent outline-none w-full"
                >
                  <option value="">— Pick a verified template —</option>
                  {meta.value.presets.map((p) => (
                    <option key={p.id} value={p.id} title={p.description}>{p.name}</option>
                  ))}
                </select>
                <p class="text-[10px] text-text-tertiary mt-1">
                  Fills method, headers and body template. URL is left alone if you've already typed one.
                </p>
              </div>
            )}

            <div>
              <label class="text-text-secondary text-xs font-mono tracking-wider uppercase mb-1.5 block">Name (optional)</label>
              <input
                type="text"
                value={formName.value}
                onInput={(e) => { formName.value = (e.target as HTMLInputElement).value }}
                placeholder="Discord — #now-playing"
                class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none w-full"
              />
            </div>

            <div>
              <label class="text-text-secondary text-xs font-mono tracking-wider uppercase mb-1.5 block">URL</label>
              <input
                type="url"
                value={formURL.value}
                onInput={(e) => { formURL.value = (e.target as HTMLInputElement).value }}
                placeholder="https://example.com/webhook"
                class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none w-full"
              />
            </div>

            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-text-secondary text-xs font-mono tracking-wider uppercase mb-1.5 block">Method</label>
                <select
                  value={formMethod.value}
                  onChange={(e) => { formMethod.value = (e.target as HTMLSelectElement).value }}
                  class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-3 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none w-full"
                >
                  {['POST', 'PUT', 'PATCH', 'GET', 'DELETE'].map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>
              <div>
                <label class="text-text-secondary text-xs font-mono tracking-wider uppercase mb-1.5 block">Content-Type</label>
                <input
                  type="text"
                  value={formContentType.value}
                  onInput={(e) => { formContentType.value = (e.target as HTMLInputElement).value }}
                  placeholder="application/json"
                  class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-3 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none w-full"
                />
              </div>
            </div>

            <div>
              <label class="text-text-secondary text-xs font-mono tracking-wider uppercase mb-1.5 block">Events</label>
              <div class="flex flex-col gap-1">
                {meta.value?.events.map((ev) => {
                  const checked = formEvents.value.includes(ev.name)
                  return (
                    <label key={ev.name} class="flex items-start gap-2 text-sm text-text-secondary cursor-pointer">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleEvent(ev.name)}
                        class="mt-1 accent-accent"
                      />
                      <span class="flex flex-col">
                        <span class="font-mono text-[12px] text-text-primary">{ev.name}</span>
                        <span class="text-[11px] text-text-tertiary">{ev.description}</span>
                      </span>
                    </label>
                  )
                })}
              </div>
            </div>

            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="text-text-secondary text-xs font-mono tracking-wider uppercase">Headers</label>
                <button
                  type="button"
                  onClick={addHeaderRow}
                  class="text-[11px] font-mono text-accent hover:underline"
                >+ Add header</button>
              </div>
              <div class="flex flex-col gap-1.5">
                {formHeaders.value.length === 0 && (
                  <p class="text-[11px] text-text-tertiary">No custom headers. Content-Type and User-Agent are sent automatically.</p>
                )}
                {formHeaders.value.map((h, i) => (
                  <div key={i} class="flex gap-1.5">
                    <input
                      type="text"
                      value={h.key}
                      onInput={(e) => updateHeader(i, 'key', (e.target as HTMLInputElement).value)}
                      placeholder="Authorization"
                      class="flex-1 bg-[rgba(255,255,255,0.03)] border border-border rounded px-2 py-1.5 text-text-primary font-mono text-[12px] focus:border-accent outline-none"
                    />
                    <input
                      type="text"
                      value={h.value}
                      onInput={(e) => updateHeader(i, 'value', (e.target as HTMLInputElement).value)}
                      placeholder="Bearer ..."
                      class="flex-[2] bg-[rgba(255,255,255,0.03)] border border-border rounded px-2 py-1.5 text-text-primary font-mono text-[12px] focus:border-accent outline-none"
                    />
                    <button
                      type="button"
                      onClick={() => removeHeaderRow(i)}
                      class="w-7 h-7 rounded border border-border flex items-center justify-center text-danger hover:border-danger/30"
                      aria-label="Remove header"
                    >
                      <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="6" x2="6" y2="18" />
                        <line x1="6" y1="6" x2="18" y2="18" />
                      </svg>
                    </button>
                  </div>
                ))}
              </div>
              <p class="text-[10px] text-text-tertiary mt-1">
                Header values can use <code>{'{{.Placeholders}}'}</code> too.
              </p>
            </div>

            <label class="flex items-center gap-2 text-sm text-text-secondary cursor-pointer">
              <input
                type="checkbox"
                checked={formEnabled.value}
                onChange={(e) => { formEnabled.value = (e.target as HTMLInputElement).checked }}
                class="accent-accent"
              />
              <span>Enabled</span>
            </label>
          </div>

          <div class="flex flex-col gap-3">
            <div>
              <label class="text-text-secondary text-xs font-mono tracking-wider uppercase mb-1.5 block">Body template</label>
              <textarea
                value={formBodyTemplate.value}
                onInput={(e) => { formBodyTemplate.value = (e.target as HTMLTextAreaElement).value }}
                placeholder={'Leave empty for the default JSON envelope.\n\nExample:\n{\n  "content": "Now playing: {{.Artist}} – {{.Title}}"\n}'}
                rows={14}
                class="bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-3 py-2 text-text-primary font-mono text-[12px] focus:border-accent outline-none w-full resize-y"
              />
              <p class="text-[10px] text-text-tertiary mt-1">
                For GET/HEAD, the rendered body is appended to the URL as a query string.
              </p>
            </div>
            <PlaceholderHelper />
          </div>
        </div>

        {saveError.value && (
          <div class="mt-4 text-danger font-mono text-xs">{saveError.value}</div>
        )}

        <div class="flex justify-end gap-2 mt-6">
          <button
            onClick={() => { showForm.value = false; resetForm() }}
            class="h-9 px-4 rounded-lg border border-border text-sm text-text-secondary hover:text-text-primary hover:border-border-hover transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={saveWebhook}
            class="h-9 px-4 rounded-lg bg-accent text-surface-base text-sm font-medium hover:shadow-[0_0_20px_rgba(255,102,0,0.3)] transition-shadow"
          >
            {editingId.value ? 'Save changes' : 'Create webhook'}
          </button>
        </div>
      </div>
    </div>
  )
}

export function Webhooks() {
  useEffect(() => {
    loadMeta()
    loadWebhooks()
  }, [])

  return (
    <div class="p-6">
      <div class="flex items-center justify-between mb-2">
        <h1 class="text-xl font-bold text-text-primary font-heading">Webhooks</h1>
        <button
          onClick={() => { resetForm(); showForm.value = true }}
          class="h-9 px-4 rounded-lg bg-accent text-surface-base text-sm font-medium flex items-center gap-2 hover:shadow-[0_0_20px_rgba(255,102,0,0.3)] transition-shadow"
        >
          <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
            <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z" />
          </svg>
          New Webhook
        </button>
      </div>
      <p class="text-sm text-text-tertiary mb-6">
        Outbound HTTP notifications for stream and AutoDJ events. Pick a preset or
        write a Go-style template body using the placeholders shown in the editor.
      </p>

      {loading.value && (
        <div class="text-sm text-text-tertiary py-10 text-center">Loading...</div>
      )}

      {!loading.value && webhooks.value.length === 0 && (
        <div class="flex flex-col items-center justify-center py-20 text-text-tertiary">
          <svg class="w-12 h-12 mb-4 opacity-30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92s2.92-1.31 2.92-2.92-1.31-2.92-2.92-2.92z" />
          </svg>
          <p class="text-sm">No webhooks configured.</p>
          <p class="text-xs mt-1">Create one to push now-playing updates, source connect/disconnect events, and more.</p>
        </div>
      )}

      {!loading.value && webhooks.value.length > 0 && (
        <div class="grid gap-3 grid-cols-1">
          {webhooks.value.map((wh) => (
            <WebhookCard key={wh.id} wh={wh} />
          ))}
        </div>
      )}

      <FormModal />
    </div>
  )
}
