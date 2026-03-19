import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'
import { api } from '../../lib/api'
import { Toggle } from '../../components/Toggle'

interface ServerSettings {
  bind_host: string
  port: number
  use_https: boolean
  max_listeners: number
  hostname: string
  base_url: string
  location: string
  admin_email: string
  low_latency_mode: boolean
  directory_listing: boolean
  auto_update: boolean
}

interface BrandingSettings {
  page_title: string
  page_subtitle: string
  accent_color: string
  landing_markdown: string
  logo_path: string
}

const activeTab = signal<'server' | 'branding'>('server')
const saving = signal(false)

// Server state
const server = signal<ServerSettings>({
  bind_host: '0.0.0.0',
  port: 8000,
  use_https: false,
  max_listeners: 0,
  hostname: '',
  base_url: '',
  location: '',
  admin_email: '',
  low_latency_mode: false,
  directory_listing: false,
  auto_update: false,
})

// Branding state
const branding = signal<BrandingSettings>({
  page_title: '',
  page_subtitle: '',
  accent_color: '#ff6600',
  landing_markdown: '',
  logo_path: '',
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
      hostname: server.value.hostname,
      base_url: server.value.base_url,
      location: server.value.location,
      admin_email: server.value.admin_email,
      max_listeners: server.value.max_listeners,
      low_latency_mode: server.value.low_latency_mode,
      directory_listing: server.value.directory_listing,
      auto_update: server.value.auto_update,
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
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">HOSTNAME</label>
              <input
                type="text"
                value={server.value.hostname}
                onInput={(e) => updateServer('hostname', (e.target as HTMLInputElement).value)}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">LOCATION</label>
              <input
                type="text"
                value={server.value.location}
                onInput={(e) => updateServer('location', (e.target as HTMLInputElement).value)}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">ADMIN EMAIL</label>
              <input
                type="email"
                value={server.value.admin_email}
                onInput={(e) => updateServer('admin_email', (e.target as HTMLInputElement).value)}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">MAX LISTENERS</label>
              <input
                type="number"
                value={server.value.max_listeners}
                onInput={(e) => updateServer('max_listeners', parseInt((e.target as HTMLInputElement).value) || 0)}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>
            <div class="flex items-center justify-between">
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary">LOW LATENCY MODE</label>
              <Toggle checked={server.value.low_latency_mode} onChange={(v) => updateServer('low_latency_mode', v)} label="Low latency" />
            </div>
            <div class="flex items-center justify-between">
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary">DIRECTORY LISTING</label>
              <Toggle checked={server.value.directory_listing} onChange={(v) => updateServer('directory_listing', v)} label="Directory listing" />
            </div>
            <div class="flex items-center justify-between">
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary">AUTO UPDATE</label>
              <Toggle checked={server.value.auto_update} onChange={(v) => updateServer('auto_update', v)} label="Auto update" />
            </div>

            {/* Read-only info */}
            <div class="border-t border-border pt-4 mt-2">
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <span class="font-mono text-[10px] tracking-[2px] text-text-tertiary block mb-1">BIND</span>
                  <span class="font-mono text-sm text-text-primary">{server.value.bind_host}:{server.value.port}</span>
                </div>
                <div>
                  <span class="font-mono text-[10px] tracking-[2px] text-text-tertiary block mb-1">HTTPS</span>
                  <span class="font-mono text-sm text-text-primary">{server.value.use_https ? 'Enabled' : 'Disabled'}</span>
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
          <div class="flex flex-col gap-5">
            {/* Logo */}
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-2 block">LOGO</label>
              <div class="flex items-center gap-4">
                {/* Preview */}
                <div class="w-16 h-16 rounded-xl border border-border bg-surface-overlay flex items-center justify-center overflow-hidden flex-shrink-0">
                  {branding.value.logo_path ? (
                    <img src={`/branding/logo?t=${Date.now()}`} alt="Logo" class="w-full h-full object-cover" />
                  ) : (
                    <span class="font-mono text-lg font-bold text-text-tertiary">
                      {(branding.value.page_title || 'Ti').slice(0, 2).toUpperCase()}
                    </span>
                  )}
                </div>
                <div class="flex flex-col gap-2 flex-1">
                  <label class="cursor-pointer">
                    <input
                      type="file"
                      accept="image/*"
                      class="hidden"
                      onChange={async (e) => {
                        const file = (e.target as HTMLInputElement).files?.[0]
                        if (!file) return
                        const form = new FormData()
                        form.append('logo', file)
                        const res = await fetch('/api/branding/logo', {
                          method: 'POST',
                          body: form,
                        })
                        if (res.ok) {
                          const data = await res.json()
                          updateBranding('logo_path', data.path || file.name)
                        }
                      }}
                    />
                    <span class="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-border text-text-secondary font-mono text-xs tracking-wider hover:border-border-hover hover:text-text-primary transition-colors">
                      <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                        <polyline points="17 8 12 3 7 8" />
                        <line x1="12" y1="3" x2="12" y2="15" />
                      </svg>
                      UPLOAD IMAGE
                    </span>
                  </label>
                  {branding.value.logo_path && (
                    <button
                      onClick={() => updateBranding('logo_path', '')}
                      class="text-left text-danger font-mono text-[10px] tracking-wider hover:underline"
                    >
                      REMOVE LOGO
                    </button>
                  )}
                  <span class="text-text-tertiary text-[10px]">PNG, JPG, SVG. Recommended 128x128.</span>
                </div>
              </div>
            </div>

            {/* Page Title */}
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">SITE NAME</label>
              <p class="text-[10px] text-text-tertiary mb-2">Shown in the navigation bar and browser tab.</p>
              <input
                type="text"
                value={branding.value.page_title}
                onInput={(e) => updateBranding('page_title', (e.target as HTMLInputElement).value)}
                placeholder="TinyIce"
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>

            {/* Subtitle */}
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">TAGLINE</label>
              <p class="text-[10px] text-text-tertiary mb-2">Shown above the title on the landing page.</p>
              <input
                type="text"
                value={branding.value.page_subtitle}
                onInput={(e) => updateBranding('page_subtitle', (e.target as HTMLInputElement).value)}
                placeholder="Live Streaming Server powered by Go"
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
              />
            </div>

            {/* Accent Color */}
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">ACCENT COLOR</label>
              <p class="text-[10px] text-text-tertiary mb-2">Primary color for buttons, links, and highlights.</p>
              {/* Preset swatches */}
              <div class="flex items-center gap-1.5 mb-3">
                {['#ff6600', '#e74c3c', '#e91e63', '#9b59b6', '#3498db', '#00bcd4', '#2ecc71', '#f39c12', '#1abc9c', '#6c5ce7'].map((color) => (
                  <button
                    key={color}
                    onClick={() => updateBranding('accent_color', color)}
                    class="w-7 h-7 rounded-lg border-2 transition-all hover:scale-110"
                    style={{
                      backgroundColor: color,
                      borderColor: branding.value.accent_color === color ? 'white' : 'transparent',
                      boxShadow: branding.value.accent_color === color ? `0 0 8px ${color}` : 'none',
                    }}
                    title={color}
                  />
                ))}
              </div>
              {/* Color picker + hex input */}
              <div class="flex items-center gap-3">
                <label
                  class="w-10 h-10 rounded-lg border border-border flex-shrink-0 cursor-pointer overflow-hidden relative"
                  style={{ backgroundColor: branding.value.accent_color }}
                >
                  <input
                    type="color"
                    value={branding.value.accent_color || '#ff6600'}
                    onInput={(e) => updateBranding('accent_color', (e.target as HTMLInputElement).value)}
                    class="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
                  />
                </label>
                <input
                  type="text"
                  value={branding.value.accent_color}
                  onInput={(e) => updateBranding('accent_color', (e.target as HTMLInputElement).value)}
                  placeholder="#ff6600"
                  class="flex-1 bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
                />
              </div>
            </div>

            {/* Landing Content */}
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1 block">LANDING PAGE CONTENT</label>
              <p class="text-[10px] text-text-tertiary mb-2">Supports Markdown: **bold**, *italic*, [links](url), # headings, lists, etc.</p>
              <textarea
                value={branding.value.landing_markdown}
                onInput={(e) => updateBranding('landing_markdown', (e.target as HTMLTextAreaElement).value)}
                rows={10}
                placeholder={"Welcome to our station!\n\n## Schedule\n- **Mon-Fri** 8am-10pm: Live shows\n- **Weekends**: AutoDJ\n\n[Listen now](/explore)"}
                class="w-full bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-code text-sm focus:border-accent outline-none resize-y"
              />
            </div>

            {/* Live preview */}
            <div>
              <label class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-2 block">PREVIEW</label>
              <div class="border border-border rounded-xl bg-surface-raised overflow-hidden">
                {/* Mini nav preview */}
                <div class="flex items-center gap-3 px-4 py-2.5 border-b border-border">
                  <div
                    class="w-6 h-6 rounded flex items-center justify-center flex-shrink-0 overflow-hidden"
                    style={{ backgroundColor: branding.value.accent_color || '#ff6600' }}
                  >
                    {branding.value.logo_path ? (
                      <img src={`/branding/logo?t=${Date.now()}`} alt="" class="w-full h-full object-cover" />
                    ) : (
                      <span class="font-mono text-[8px] font-bold text-white leading-none">
                        {(branding.value.page_title || 'Ti').slice(0, 2).toUpperCase()}
                      </span>
                    )}
                  </div>
                  <span class="font-mono text-[10px] font-bold tracking-widest text-text-primary uppercase">
                    {branding.value.page_title || 'TINYICE'}
                  </span>
                </div>
                {/* Content area */}
                <div class="p-4">
                  <span class="font-mono text-[9px] tracking-widest block mb-1" style={{ color: branding.value.accent_color || '#ff6600' }}>
                    {branding.value.page_subtitle || '— AUDIO STREAMING SERVER'}
                  </span>
                  <h3 class="font-bold text-text-primary text-sm mb-2">{branding.value.page_title || 'TinyIce'}</h3>
                  {branding.value.landing_markdown && (
                    <div class="text-[11px] text-text-tertiary line-clamp-3">
                      {branding.value.landing_markdown.slice(0, 150)}...
                    </div>
                  )}
                </div>
              </div>
            </div>

            <button
              onClick={saveBranding}
              disabled={saving.value}
              class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg mt-2 self-start disabled:opacity-50"
            >
              {saving.value ? 'SAVING...' : 'SAVE BRANDING'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
