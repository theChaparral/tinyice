import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'
import { api } from '../../lib/api'

const bans = signal<string[]>([])
const whitelist = signal<string[]>([])
const loading = signal(true)
const banInput = signal('')
const whitelistInput = signal('')

async function load() {
  loading.value = true
  try {
    const [b, w] = await Promise.all([
      api.get<string[]>('/api/security/bans'),
      api.get<string[]>('/api/security/whitelist'),
    ])
    bans.value = b
    whitelist.value = w
  } catch { /* empty */ }
  loading.value = false
}

async function addBan() {
  if (!banInput.value.trim()) return
  await api.post('/api/security/bans', { ip: banInput.value.trim() })
  banInput.value = ''
  load()
}

async function removeBan(ip: string) {
  await api.del(`/api/security/bans/${encodeURIComponent(ip)}`)
  load()
}

async function addWhitelist() {
  if (!whitelistInput.value.trim()) return
  await api.post('/api/security/whitelist', { ip: whitelistInput.value.trim() })
  whitelistInput.value = ''
  load()
}

async function removeWhitelist(ip: string) {
  await api.del(`/api/security/whitelist/${encodeURIComponent(ip)}`)
  load()
}

function IpSection({
  title,
  description,
  items,
  inputValue,
  onInput,
  onAdd,
  onRemove,
  placeholder,
}: {
  title: string
  description: string
  items: string[]
  inputValue: string
  onInput: (v: string) => void
  onAdd: () => void
  onRemove: (ip: string) => void
  placeholder: string
}) {
  return (
    <div class="mb-8">
      <h2 class="text-base font-bold text-text-primary mb-1">{title}</h2>
      <p class="text-sm text-text-tertiary mb-4">{description}</p>

      {/* Add input */}
      <div class="flex gap-2 mb-4">
        <input
          type="text"
          value={inputValue}
          onInput={(e) => onInput((e.target as HTMLInputElement).value)}
          onKeyDown={(e) => { if (e.key === 'Enter') onAdd() }}
          placeholder={placeholder}
          class="flex-1 bg-[rgba(255,255,255,0.03)] border border-border rounded-lg px-4 py-2.5 text-text-primary font-mono text-sm focus:border-accent outline-none"
        />
        <button
          onClick={onAdd}
          class="bg-accent text-surface-base font-mono font-bold text-xs tracking-[1px] px-4 py-2.5 rounded-lg"
        >
          ADD IP
        </button>
      </div>

      {/* Table */}
      <div class="border border-border rounded-xl overflow-hidden">
        <table class="w-full">
          <thead>
            <tr class="border-b border-border">
              <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-left px-4 py-3">IP / CIDR</th>
              <th class="font-mono text-[9px] tracking-[1px] text-text-tertiary uppercase text-right px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr><td colSpan={2} class="px-4 py-6 text-center text-text-tertiary text-sm">None configured</td></tr>
            ) : (
              items.map((ip) => (
                <tr key={ip} class="border-b border-[rgba(255,255,255,0.03)]">
                  <td class="px-4 py-3.5 font-mono text-sm text-text-primary">{ip}</td>
                  <td class="px-4 py-3.5 text-right">
                    <button
                      onClick={() => onRemove(ip)}
                      class="border border-border text-danger font-mono text-xs px-3 py-1.5 rounded-lg hover:border-danger/30"
                    >
                      REMOVE
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export function Security() {
  useEffect(() => { load() }, [])

  return (
    <div class="p-7">
      <div class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1">MANAGE</div>
      <h1 class="text-xl font-bold text-text-primary mb-6">Security</h1>

      {loading.value ? (
        <p class="text-text-tertiary text-sm">Loading...</p>
      ) : (
        <>
          <IpSection
            title="Banned IPs"
            description="Connections from these IPs will be rejected."
            items={bans.value}
            inputValue={banInput.value}
            onInput={(v) => { banInput.value = v }}
            onAdd={addBan}
            onRemove={removeBan}
            placeholder="192.168.1.0/24"
          />
          <IpSection
            title="Whitelisted IPs"
            description="Only these IPs will be allowed to connect. Leave empty to allow all."
            items={whitelist.value}
            inputValue={whitelistInput.value}
            onInput={(v) => { whitelistInput.value = v }}
            onAdd={addWhitelist}
            onRemove={removeWhitelist}
            placeholder="10.0.0.0/8"
          />
        </>
      )}
    </div>
  )
}
