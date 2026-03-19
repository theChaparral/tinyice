import { signal } from '@preact/signals'
import { useEffect } from 'preact/hooks'
import { createSSE } from '../../lib/sse'
import { StatCard } from '../../components/StatCard'
import type { StatsEvent, StreamEvent } from '../../types'

// Reactive state
const stats = signal<StatsEvent>({
  listeners: 0,
  streams: 0,
  bandwidth: 0,
  bandwidth_in: 0,
  bandwidth_out: 0,
  uptime: 0,
  goroutines: 0,
  memory: 0,
  gc: 0,
})

const streams = signal<StreamEvent[]>([])
const connected = signal(false)
const timeRange = signal<'1H' | '24H' | '7D'>('1H')

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) {
    const h = Math.floor(seconds / 3600)
    const m = Math.floor((seconds % 3600) / 60)
    return `${h}h ${m}m`
  }
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  return `${d}d ${h}h`
}

function formatBandwidth(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec} B/s`
  if (bytesPerSec < 1048576) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`
  return `${(bytesPerSec / 1048576).toFixed(1)} MB/s`
}

export function Dashboard() {
  useEffect(() => {
    const sse = createSSE('/admin/events')

    const offStats = sse.on('stats', (data: StatsEvent) => {
      stats.value = data
      connected.value = true
    })

    const offStream = sse.on('stream', (data: StreamEvent) => {
      streams.value = [
        ...streams.value.filter((s) => s.mount !== data.mount),
        data,
      ].sort((a, b) => a.mount.localeCompare(b.mount))
    })

    return () => {
      offStats()
      offStream()
      sse.close()
    }
  }, [])

  const totalStreams = streams.value.length
  const activeStreams = streams.value.filter((s) => s.listeners > 0).length

  return (
    <div class="p-7 max-w-[1400px]">
      {/* Header */}
      <div class="flex items-center justify-between mb-6">
        <div>
          <div class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1">
            DASHBOARD
          </div>
          <h1 class="text-xl font-bold text-text-primary">System Overview</h1>
        </div>
        <div class="flex items-center gap-2">
          <span
            class="w-2 h-2 rounded-full"
            style={{
              backgroundColor: connected.value ? 'var(--color-live)' : 'var(--color-danger)',
              animation: connected.value ? 'pulse-glow 2s ease-in-out infinite' : 'none',
            }}
          />
          <span class="font-mono text-[10px] tracking-widest text-text-tertiary uppercase">
            {connected.value ? 'ALL SYSTEMS OK' : 'CONNECTING...'}
          </span>
        </div>
      </div>

      {/* Stats row */}
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
        <StatCard
          label="Listeners"
          value={stats.value.listeners}
          subtitle="connected now"
          gauge={Math.min(100, stats.value.listeners)}
        />
        <StatCard
          label="Streams"
          value={`${activeStreams} / ${totalStreams}`}
          subtitle="active / total"
        />
        <StatCard
          label="Inbound"
          value={formatBandwidth(stats.value.bandwidth_in || 0)}
          subtitle="from sources"
        />
        <StatCard
          label="Outbound"
          value={formatBandwidth(stats.value.bandwidth_out || stats.value.bandwidth || 0)}
          subtitle="to listeners"
        />
        <StatCard
          label="Uptime"
          value={formatUptime(stats.value.uptime)}
          subtitle="since last restart"
        />
      </div>

      {/* Traffic chart placeholder */}
      <div class="rounded-lg border border-border bg-surface-raised p-4 mb-6">
        <div class="flex items-center justify-between mb-4">
          <span class="font-mono text-[10px] tracking-widest uppercase text-text-tertiary">
            Listener Traffic
          </span>
          <div class="flex gap-1">
            {(['1H', '24H', '7D'] as const).map((range) => (
              <button
                key={range}
                onClick={() => (timeRange.value = range)}
                class={`
                  px-2 py-1 rounded font-mono text-[10px] tracking-wider transition-colors
                  ${
                    timeRange.value === range
                      ? 'bg-accent/15 text-accent'
                      : 'text-text-tertiary hover:text-text-secondary hover:bg-surface-hover'
                  }
                `}
              >
                {range}
              </button>
            ))}
          </div>
        </div>
        {/* Listener traffic chart */}
        <div class="h-32 flex items-end gap-px">
          {stats.value.listeners > 0 ? Array.from({ length: 48 }, (_, i) => (
            <div
              key={i}
              class="flex-1 rounded-t bg-accent/20 transition-all duration-300"
              style={{ height: `${Math.max(4, (i === 47 ? stats.value.listeners : 0) * 10)}%` }}
            />
          )) : (
            <div class="flex-1 flex items-center justify-center text-text-tertiary text-xs font-mono">
              No listener data yet
            </div>
          )}
        </div>
        <div class="flex justify-between mt-2">
          <span class="font-mono text-[9px] text-text-tertiary">
            {timeRange.value === '1H' ? '60m ago' : timeRange.value === '24H' ? '24h ago' : '7d ago'}
          </span>
          <span class="font-mono text-[9px] text-text-tertiary">now</span>
        </div>
      </div>

      {/* Streams table */}
      <div class="rounded-lg border border-border bg-surface-raised overflow-hidden">
        <div class="px-4 py-3 border-b border-border">
          <span class="font-mono text-[10px] tracking-widest uppercase text-text-tertiary">
            Active Streams
          </span>
        </div>
        {streams.value.length === 0 ? (
          <div class="px-4 py-8 text-center text-text-tertiary text-sm">
            No streams connected
          </div>
        ) : (
          <table class="w-full">
            <thead>
              <tr class="text-left text-text-tertiary font-mono text-[10px] tracking-wider uppercase border-b border-border">
                <th class="px-4 py-2 font-normal">Status</th>
                <th class="px-4 py-2 font-normal">Mount</th>
                <th class="px-4 py-2 font-normal">Format</th>
                <th class="px-4 py-2 font-normal">Listeners</th>
                <th class="px-4 py-2 font-normal">Health</th>
              </tr>
            </thead>
            <tbody>
              {streams.value.map((stream) => (
                <tr
                  key={stream.mount}
                  class="border-b border-border last:border-b-0 hover:bg-surface-hover transition-colors"
                >
                  {/* Status dot */}
                  <td class="px-4 py-3">
                    <span
                      class="w-2 h-2 rounded-full inline-block"
                      style={{
                        backgroundColor:
                          stream.listeners > 0
                            ? 'var(--color-live)'
                            : 'var(--color-text-tertiary)',
                      }}
                    />
                  </td>
                  {/* Mount */}
                  <td class="px-4 py-3">
                    <span class="font-mono font-bold text-sm text-text-primary">
                      {stream.mount}
                    </span>
                    {stream.title && (
                      <div class="text-xs text-text-secondary mt-0.5">
                        {stream.artist ? `${stream.artist} - ${stream.title}` : stream.title}
                      </div>
                    )}
                  </td>
                  {/* Format */}
                  <td class="px-4 py-3">
                    <span class="font-mono text-xs text-text-secondary uppercase">
                      {stream.format}
                    </span>
                    {stream.bitrate > 0 && (
                      <span class="text-text-tertiary text-xs ml-1">
                        {stream.bitrate}k
                      </span>
                    )}
                  </td>
                  {/* Listeners */}
                  <td class="px-4 py-3">
                    <span class="font-mono text-sm text-text-primary">
                      {stream.listeners}
                    </span>
                  </td>
                  {/* Health bar */}
                  <td class="px-4 py-3">
                    <div class="flex items-center gap-2">
                      <div class="h-1 w-16 rounded-full bg-surface-overlay overflow-hidden">
                        <div
                          class="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${Math.min(100, Math.max(0, stream.health))}%`,
                            backgroundColor:
                              stream.health >= 80
                                ? 'var(--color-live)'
                                : stream.health >= 50
                                  ? 'var(--color-accent)'
                                  : 'var(--color-danger)',
                          }}
                        />
                      </div>
                      <span class="font-mono text-[10px] text-text-tertiary">
                        {stream.health}%
                      </span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* System info footer */}
      <div class="flex gap-6 mt-4 text-text-tertiary font-mono text-[10px] tracking-wider">
        <span>MEM {(stats.value.memory / 1048576).toFixed(1)} MB</span>
        <span>GR {stats.value.goroutines}</span>
        <span>GC {stats.value.gc}</span>
      </div>
    </div>
  )
}
