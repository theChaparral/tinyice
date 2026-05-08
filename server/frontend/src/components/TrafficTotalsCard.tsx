import { useEffect } from 'preact/hooks'
import { signal } from '@preact/signals'
import { api } from '../lib/api'

// TrafficTotalsCard — compact horizontal table of cumulative traffic
// across day / week / month / quarter / year / lifetime windows.
// Each row shows the window label, an "in" arrow (↓ from sources),
// and an "out" arrow (↑ to listeners). Single-line dense layout
// reads at a glance and scales linearly to more windows without
// breaking the dashboard grid.

type Window = 'day' | 'week' | 'month' | 'quarter' | 'year' | 'lifetime'

type Totals = {
  bytes_in: number
  bytes_out: number
  mounts: number
}

type TrafficResp = Record<Window, Totals> & { all?: Totals }

const data = signal<TrafficResp | null>(null)
const loading = signal(false)
const error = signal<string | null>(null)

const WINDOWS: { key: Window; label: string }[] = [
  { key: 'day',      label: '24 h'  },
  { key: 'week',     label: '7 d'   },
  { key: 'month',    label: '30 d'  },
  { key: 'quarter',  label: '90 d'  },
  { key: 'year',     label: '365 d' },
  { key: 'lifetime', label: 'all'   },
]

// formatBytes — base-1024 with concise decimals so totals fit in a
// single column ("4.2 GB" / "12 MB" / "850 KB").
function formatBytes(b: number): string {
  if (b < 0 || !Number.isFinite(b)) return '—'
  if (b === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let i = 0
  let v = b
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  const decimals = i <= 1 ? 0 : v >= 100 ? 0 : v >= 10 ? 1 : 2
  return `${v.toFixed(decimals)} ${units[i]}`
}

function fetchTotals() {
  if (loading.value) return
  loading.value = true
  error.value = null
  api
    .get<TrafficResp>('/admin/traffic')
    .then((d) => (data.value = d))
    .catch((err) => (error.value = err?.message || 'Failed to load traffic totals'))
    .finally(() => (loading.value = false))
}

export function TrafficTotalsCard() {
  useEffect(() => {
    fetchTotals()
    // Refresh every two minutes — RecordStats samples each minute,
    // anything tighter is wasted polling.
    const id = window.setInterval(fetchTotals, 120_000)
    return () => window.clearInterval(id)
  }, [])

  return (
    <div class="rounded-lg border border-border bg-surface-raised p-4">
      <div class="flex items-center justify-between mb-3">
        <span class="font-mono text-[10px] tracking-widest uppercase text-text-tertiary">
          Total traffic
        </span>
        <span class="font-mono text-[10px] text-text-tertiary">
          ↓ inbound (sources) · ↑ outbound (listeners)
        </span>
      </div>

      {error.value && !data.value && (
        <div class="text-danger text-xs font-mono">{error.value}</div>
      )}

      <div class="overflow-x-auto">
        <table class="w-full font-mono text-xs tabular-nums">
          <thead>
            <tr class="text-text-tertiary border-b border-border">
              <th class="text-left py-1.5 px-2 text-[10px] tracking-widest uppercase font-normal">
                Window
              </th>
              <th class="text-right py-1.5 px-2 text-[10px] tracking-widest uppercase font-normal">
                ↓ in
              </th>
              <th class="text-right py-1.5 px-2 text-[10px] tracking-widest uppercase font-normal">
                ↑ out
              </th>
              <th class="text-right py-1.5 px-2 text-[10px] tracking-widest uppercase font-normal">
                Mounts
              </th>
            </tr>
          </thead>
          <tbody>
            {WINDOWS.map(({ key, label }) => {
              const t = data.value?.[key]
              return (
                <tr key={key} class="border-b border-border last:border-b-0 hover:bg-surface-hover transition-colors">
                  <td class="py-1.5 px-2 text-text-secondary">{label}</td>
                  <td class="py-1.5 px-2 text-right text-text-primary">
                    {t ? formatBytes(t.bytes_in) : '…'}
                  </td>
                  <td class="py-1.5 px-2 text-right text-text-primary">
                    {t ? formatBytes(t.bytes_out) : '…'}
                  </td>
                  <td class="py-1.5 px-2 text-right text-text-tertiary">
                    {t && t.mounts > 0 ? t.mounts : '—'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
