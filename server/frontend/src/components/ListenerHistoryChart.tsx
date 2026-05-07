import { useEffect, useMemo } from 'preact/hooks'
import { signal } from '@preact/signals'
import { api } from '../lib/api'

type HistoricalStat = {
  timestamp: string
  listeners: number
  bytes_in: number
  bytes_out: number
}

// API returns map[mount] -> series. Empty when history is disabled or
// no data has been recorded yet for the chosen window.
type InsightsResp = Record<string, HistoricalStat[]>

type Range = '1H' | '24H' | '7D'

const HOURS: Record<Range, number> = { '1H': 1, '24H': 24, '7D': 168 }

// Module-level cache so flipping range tabs doesn't refetch on every
// remount (Dashboard re-renders frequently from SSE updates).
const cache = signal<Record<Range, InsightsResp | null>>({
  '1H': null,
  '24H': null,
  '7D': null,
})
const loading = signal<Range | null>(null)
const error = signal<string | null>(null)

// Eight-color palette cycled by mount index. Picked to stay legible
// against the dark surface-raised background and to read distinct
// even with two mounts overlapping.
const PALETTE = [
  '#ff8a3d', // accent-warm
  '#7dd3fc', // sky
  '#a78bfa', // violet
  '#34d399', // emerald
  '#f472b6', // pink
  '#fbbf24', // amber
  '#60a5fa', // blue
  '#f87171', // red
]

function fetchRange(range: Range) {
  if (loading.value === range) return
  loading.value = range
  error.value = null
  api
    .get<InsightsResp>(`/admin/insights?hours=${HOURS[range]}`)
    .then((data) => {
      cache.value = { ...cache.value, [range]: data ?? {} }
    })
    .catch((err) => {
      error.value = err?.message || 'Failed to load history'
    })
    .finally(() => {
      if (loading.value === range) loading.value = null
    })
}

interface Props {
  range: Range
}

export function ListenerHistoryChart({ range }: Props) {
  useEffect(() => {
    if (cache.value[range] === null) fetchRange(range)
  }, [range])

  const data = cache.value[range]

  // Series sorted by current peak listeners DESC so the busiest mount
  // legend entry comes first. Auto-MP3 transcoder mounts are filtered
  // out of the legend by default — they're always identical to their
  // source's listener curve and add visual noise — but kept in the
  // payload so a future "show all" toggle can surface them.
  const series = useMemo(() => {
    if (!data) return [] as { mount: string; series: HistoricalStat[]; peak: number }[]
    const all = Object.entries(data)
      .map(([mount, s]) => ({
        mount,
        series: s,
        peak: s.reduce((m, p) => (p.listeners > m ? p.listeners : m), 0),
      }))
      .filter((entry) => !/-mp3-\d+$|-128$|-256$/.test(entry.mount))
    all.sort((a, b) => b.peak - a.peak)
    return all
  }, [data])

  const peak = series.reduce((m, s) => (s.peak > m ? s.peak : m), 0)
  const yMax = Math.max(1, peak)

  // Chart geometry: full width SVG, fixed 192px height (h-48), small
  // padding so axis numbers don't clip. ViewBox uses logical coords —
  // CSS scales it to whatever container width.
  const W = 1000
  const H = 240
  const PAD_L = 36
  const PAD_R = 12
  const PAD_T = 12
  const PAD_B = 24
  const innerW = W - PAD_L - PAD_R
  const innerH = H - PAD_T - PAD_B

  const windowStart = useMemo(() => {
    const ms = Date.now() - HOURS[range] * 3600_000
    return ms
  }, [range])

  function pointsFor(s: HistoricalStat[]) {
    if (s.length === 0) return ''
    return s
      .map((p) => {
        const t = new Date(p.timestamp).getTime()
        const x = PAD_L + ((t - windowStart) / (HOURS[range] * 3600_000)) * innerW
        const y = PAD_T + innerH - (p.listeners / yMax) * innerH
        return `${x.toFixed(1)},${y.toFixed(1)}`
      })
      .join(' ')
  }

  const isLoading = loading.value === range && !data
  const isEmpty = data !== null && series.length === 0

  return (
    <div class="rounded-lg border border-border bg-surface-raised p-4">
      <div class="flex items-center justify-between mb-3">
        <span class="font-mono text-[10px] tracking-widest uppercase text-text-tertiary">
          Listeners over time
        </span>
        <span class="font-mono text-[10px] text-text-tertiary tabular-nums">
          peak {peak} · {HOURS[range]}h window
        </span>
      </div>

      <div class="relative">
        <svg viewBox={`0 0 ${W} ${H}`} class="w-full h-48 block" preserveAspectRatio="none">
          {/* Y-axis grid: 4 horizontal lines at 0/25/50/75/100 % of yMax */}
          {[0, 0.25, 0.5, 0.75, 1].map((f) => {
            const y = PAD_T + innerH - f * innerH
            return (
              <g key={f}>
                <line
                  x1={PAD_L}
                  x2={W - PAD_R}
                  y1={y}
                  y2={y}
                  stroke="var(--color-border)"
                  stroke-width="1"
                  opacity={f === 0 ? 0.6 : 0.25}
                />
                <text
                  x={PAD_L - 6}
                  y={y + 4}
                  text-anchor="end"
                  font-family="ui-monospace,monospace"
                  font-size="10"
                  fill="var(--color-text-tertiary)"
                >
                  {Math.round(f * yMax)}
                </text>
              </g>
            )
          })}

          {/* Per-mount polylines */}
          {series.slice(0, PALETTE.length).map((s, i) => (
            <polyline
              key={s.mount}
              points={pointsFor(s.series)}
              fill="none"
              stroke={PALETTE[i % PALETTE.length]}
              stroke-width="1.5"
              stroke-linejoin="round"
              stroke-linecap="round"
              opacity="0.9"
            />
          ))}

          {/* X-axis tick labels — start, mid, now */}
          {[0, 0.5, 1].map((f) => {
            const x = PAD_L + f * innerW
            const ms = windowStart + f * HOURS[range] * 3600_000
            const lbl =
              f === 1
                ? 'now'
                : range === '1H'
                  ? `${Math.round((1 - f) * 60)}m ago`
                  : range === '24H'
                    ? `${Math.round((1 - f) * 24)}h ago`
                    : `${Math.round((1 - f) * 7)}d ago`
            return (
              <text
                key={f}
                x={x}
                y={H - 6}
                text-anchor={f === 0 ? 'start' : f === 1 ? 'end' : 'middle'}
                font-family="ui-monospace,monospace"
                font-size="10"
                fill="var(--color-text-tertiary)"
              >
                {lbl}
              </text>
            )
          })}
        </svg>

        {isLoading && (
          <div class="absolute inset-0 flex items-center justify-center text-text-tertiary text-xs font-mono">
            Loading…
          </div>
        )}
        {!isLoading && error.value && (
          <div class="absolute inset-0 flex items-center justify-center text-danger text-xs font-mono">
            {error.value}
          </div>
        )}
        {isEmpty && (
          <div class="absolute inset-0 flex items-center justify-center text-text-tertiary text-xs font-mono">
            No listener data yet for this window
          </div>
        )}
      </div>

      {/* Legend */}
      {series.length > 0 && (
        <div class="flex flex-wrap gap-x-4 gap-y-1 mt-3">
          {series.slice(0, PALETTE.length).map((s, i) => (
            <div key={s.mount} class="flex items-center gap-1.5">
              <span
                class="w-2 h-2 rounded-sm inline-block"
                style={{ backgroundColor: PALETTE[i % PALETTE.length] }}
              />
              <span class="font-mono text-[10px] text-text-secondary">{s.mount}</span>
              <span class="font-mono text-[10px] text-text-tertiary tabular-nums">
                peak {s.peak}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
