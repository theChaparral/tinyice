import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'
import { api } from '../../lib/api'
import { Toggle } from '../../components/Toggle'

interface ServerSettings {
  bindHost: string
  port: number
  https: boolean
  maxListeners: number
  version: string
  uptime: number
}

interface BrandingSettings {
  pageTitle: string
  pageSubtitle: string
  accentColor: string
  landingContent: string
  location: string
  adminEmail: string
}

const activeTab = signal<'server' | 'branding'>('server')
const saving = signal(false)

// Server state
const server = signal<ServerSettings>({
  bindHost: '0.0.0.0',
  port: 8000,
  https: false,
  maxListeners: 0,
  version: '',
  uptime: 0,
})

// Branding state
const branding = signal<BrandingSettings>({
  pageTitle: '',
  pageSubtitle: '',
  accentColor: '#ff6600',
  landingContent: '',
  location: '',
  adminEmail: '',
})

const loading = signal(true)

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

async function load() {
  loading.value = true
  try {
    const [s, b] = await Promise.all([
      api.get<ServerSettings>('/api/settings'),
      api.get<BrandingSettings>('/api/branding'),
    ])
    server.value = s
    branding.value = b
  } catch { /* empty */ }
  loading.value = false
}

async function saveServer() {
  saving.value = true
  try {
    await api.put('/api/settings', {
      bindHost: server.value.bindHost,
      port: server.value.port,
      https: server.value.https,
      maxListeners: server.value.maxListeners,
    })
  } catch { /* empty */ }
  saving.value = false
}

async function saveBranding() {
  saving.value = true
  try {
    await api.put('/api/branding', branding.value)
  } catch { /* empty */ }
  saving.value = false
}

function updateServer<K extends keyof ServerSettings>(key: K, value: ServerSettings[K]) {
  server.value = { ...server.value, [key]: value }
}

function updateBranding<K extends keyof BrandingSettings>(key: K, value: BrandingSettings[K]) {
  branding.value = { ...branding.value, [key]: value }
}

export function Settings() {
  useEffect(() => { load() }, [])

  return (
    <div class="p-7">
      <div class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1">MANAGE</div>
      <h1 class="text-xl font-bold text-text-primary mb-6">Settings</h1>

      {/* Tabs */}
      <div class="flex gap-1 mb-6 border-b border-border">
        {(['server', 'branding'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => { activeTab.value = tab }}
            class={`font-mono text-xs tracking-[1px] uppercase px-4 py-2.5 border-b-2 transition-colors ${
              activeTab.value === tab
                ? 'border-accent text-accent'
                : 'border-transparent text-text-tertiary hover:text-text-secondary'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {loading.value ? (
        <p class="text-text-tertiary text-sm">Loading...</p>
      ) : activeTab.value === 'server' ? (
        <div class="max-w-lg">
          <div class="flex flex-col gap-4">
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">BIND HOST</label>
              <input
                type="text"
                value={server.value.bindHost}
                onInput={(e) => updateServer('bindHost', (e.target as HTMLInputElement).value)}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">PORT</label>
              <input
                type="number"
                value={server.value.port}
                onInput={(e) => updateServer('port', parseInt((e.target as HTMLInputElement).value) || 0)}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>
            <div class="flex items-center justify-between">
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary">HTTPS</label>
              <Toggle checked={server.value.https} onChange={(v) => updateServer('https', v)} label="Enable HTTPS" />
            </div>
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">MAX LISTENERS</label>
              <input
                type="number"
                value={server.value.maxListeners}
                onInput={(e) => updateServer('maxListeners', parseInt((e.target as HTMLInputElement).value) || 0)}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>

            {/* Read-only info */}
            <div class="border-t border-border pt-4 mt-2">
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <span class="font-mono text-[10px] tracking-[2px] text-text-tertiary block mb-1">VERSION</span>
                  <span class="font-mono text-sm text-text-primary">{server.value.version || '—'}</span>
                </div>
                <div>
                  <span class="font-mono text-[10px] tracking-[2px] text-text-tertiary block mb-1">UPTIME</span>
                  <span class="font-mono text-sm text-text-primary">{formatUptime(server.value.uptime)}</span>
                </div>
              </div>
            </div>

            <button
              onClick={saveServer}
              disabled={saving.value}
              class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg mt-2 self-start disabled:opacity-50"
            >
              {saving.value ? 'SAVING...' : 'SAVE'}
            </button>
          </div>
        </div>
      ) : (
        <div class="max-w-lg">
          <div class="flex flex-col gap-4">
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">PAGE TITLE</label>
              <input
                type="text"
                value={branding.value.pageTitle}
                onInput={(e) => updateBranding('pageTitle', (e.target as HTMLInputElement).value)}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">PAGE SUBTITLE</label>
              <input
                type="text"
                value={branding.value.pageSubtitle}
                onInput={(e) => updateBranding('pageSubtitle', (e.target as HTMLInputElement).value)}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">ACCENT COLOR</label>
              <div class="flex items-center gap-3">
                <input
                  type="text"
                  value={branding.value.accentColor}
                  onInput={(e) => updateBranding('accentColor', (e.target as HTMLInputElement).value)}
                  placeholder="#ff6600"
                  class="flex-1 bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
                <div
                  class="w-10 h-10 rounded-lg border border-border flex-shrink-0"
                  style={{ backgroundColor: branding.value.accentColor }}
                />
              </div>
            </div>
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">LANDING CONTENT (MARKDOWN)</label>
              <textarea
                value={branding.value.landingContent}
                onInput={(e) => updateBranding('landingContent', (e.target as HTMLTextAreaElement).value)}
                rows={8}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-code text-sm focus:border-accent outline-none resize-y"
              />
            </div>
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">LOCATION</label>
              <input
                type="text"
                value={branding.value.location}
                onInput={(e) => updateBranding('location', (e.target as HTMLInputElement).value)}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">ADMIN EMAIL</label>
              <input
                type="email"
                value={branding.value.adminEmail}
                onInput={(e) => updateBranding('adminEmail', (e.target as HTMLInputElement).value)}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>

            <button
              onClick={saveBranding}
              disabled={saving.value}
              class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg mt-2 self-start disabled:opacity-50"
            >
              {saving.value ? 'SAVING...' : 'SAVE'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
