import { useEffect } from 'preact/hooks'
import { signal } from '@preact/signals'
import { api } from '../lib/api'

type Window = 'day' | 'week' | 'month' | 'all'

type Totals = {
  bytes_in: number
  bytes_out: number
  mounts: number
}

type TrafficResp = Record<Window, Totals>

const data = signal<TrafficResp | null>(null)
const loading = signal(false)
const error = signal<string | null>(null)

const WINDOW_LABEL: Record<Window, string> = {
  day: 'last 24h',
  week: 'last 7d',
  month: 'last 30d',
  all: 'all time',
}

// formatBytes converts an int64 byte total into a compact human-readable
// string. Uses 1024-based units (KiB-style sizes) but renders without
// the "i" — what "GB" colloquially means in dashboard contexts. Picks
// the unit that lands a value between 0.5 and 1000 so the eye can read
// it without doing math.
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
  // Fewer decimals for big numbers.
  const decimals = i <= 1 ? 0 : v >= 100 ? 0 : v >= 10 ? 1 : 2
  return `${v.toFixed(decimals)} ${units[i]}`
}

function fetchTotals() {
  if (loading.value) return
  loading.value = true
  error.value = null
  api
    .get<TrafficResp>('/admin/traffic')
    .then((d) => {
      data.value = d
    })
    .catch((err) => {
      error.value = err?.message || 'Failed to load traffic totals'
    })
    .finally(() => {
      loading.value = false
    })
}

export function TrafficTotalsCard() {
  useEffect(() => {
    fetchTotals()
    // Refresh every two minutes — the underlying samples update at the
    // RecordStats cadence (~1 min), faster polling is wasted bytes.
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
          inbound (sources) · outbound (listeners)
        </span>
      </div>

      {error.value && !data.value && (
        <div class="text-danger text-xs font-mono">{error.value}</div>
      )}

      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {(['day', 'week', 'month', 'all'] as const).map((w) => {
          const t = data.value?.[w]
          return (
            <div
              key={w}
              class="rounded-md border border-border/70 bg-surface-base p-3 flex flex-col gap-1"
            >
              <span class="font-mono text-[9px] tracking-widest uppercase text-text-tertiary">
                {WINDOW_LABEL[w]}
              </span>
              <div class="flex items-baseline justify-between gap-2">
                <span
                  class="font-mono text-[9px] text-text-tertiary uppercase tracking-wider"
                  title="bytes received from sources"
                >
                  in
                </span>
                <span class="font-mono text-sm text-text-primary tabular-nums">
                  {t ? formatBytes(t.bytes_in) : '…'}
                </span>
              </div>
              <div class="flex items-baseline justify-between gap-2">
                <span
                  class="font-mono text-[9px] text-text-tertiary uppercase tracking-wider"
                  title="bytes served to listeners"
                >
                  out
                </span>
                <span class="font-mono text-sm text-text-primary tabular-nums">
                  {t ? formatBytes(t.bytes_out) : '…'}
                </span>
              </div>
              {t && t.mounts > 0 && (
                <span class="font-mono text-[9px] text-text-tertiary mt-0.5">
                  {t.mounts} {t.mounts === 1 ? 'mount' : 'mounts'}
                </span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
