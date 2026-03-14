import { useEffect } from 'preact/hooks'
import { signal } from '@preact/signals'
import { api } from '@/lib/api'
import { createSSE } from '@/lib/sse'
import { EqBars } from '@/components/EqBars'
import type { AutoDJEvent } from '@/types'

interface AutoDJInstance {
  mount: string
  format: string
  bitrate: number
  state: 'playing' | 'paused' | 'stopped'
  currentTrack: { title: string; artist: string; file: string }
  position: number
  duration: number
  listeners: number
  queue: string[]
  trackCount: number
}

const instances = signal<AutoDJInstance[]>([])
const loading = signal(true)

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = Math.floor(seconds % 60)
  return `${m}:${s.toString().padStart(2, '0')}`
}

function InstanceCard({ inst }: { inst: AutoDJInstance }) {
  const isPlaying = inst.state === 'playing'
  const isPaused = inst.state === 'paused'
  const isStopped = inst.state === 'stopped'
  const progress = inst.duration > 0 ? (inst.position / inst.duration) * 100 : 0

  const handleTransport = (action: string) => {
    api.post(`/api/autodj/${encodeURIComponent(inst.mount)}/${action}`)
  }

  return (
    <div class="bg-surface-raised border border-border rounded-xl p-5 hover:border-border-hover transition-colors">
      {/* Header: status + mount + format */}
      <div class="flex items-center gap-3 mb-4">
        <span
          class={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${
            isPlaying ? 'bg-live' : 'bg-text-tertiary'
          }`}
          style={isPlaying ? { animation: 'pulse-glow 2s ease-in-out infinite' } : undefined}
        />
        <span class="font-mono font-bold text-text-primary text-sm">
          {inst.mount}
        </span>
        <span class="font-mono text-[10px] text-text-tertiary tracking-wider uppercase">
          {inst.format} {inst.bitrate}kbps
        </span>
        <div class="ml-auto flex items-center gap-1.5">
          <span class="text-2xl font-bold text-text-primary leading-none">{inst.listeners}</span>
          <span class="text-[9px] font-mono text-text-tertiary uppercase tracking-wider">
            {inst.listeners === 1 ? 'listener' : 'listeners'}
          </span>
        </div>
      </div>

      {/* Now Playing or Stopped */}
      {isStopped ? (
        <div class="flex items-center justify-between py-4">
          <span class="text-sm text-text-tertiary">
            Stopped &mdash; {inst.trackCount} tracks
          </span>
          <button
            onClick={() => handleTransport('play')}
            class="w-10 h-10 rounded-full border border-border flex items-center justify-center text-text-tertiary hover:text-accent hover:border-accent transition-colors"
            aria-label="Play"
          >
            <svg class="w-4 h-4 ml-0.5" viewBox="0 0 24 24" fill="currentColor">
              <path d="M8 5v14l11-7z" />
            </svg>
          </button>
        </div>
      ) : (
        <>
          {/* Track info */}
          <div class="mb-3">
            <div class="text-sm font-medium text-text-primary truncate">
              {inst.currentTrack.title || inst.currentTrack.file || 'Unknown'}
            </div>
            <div class="text-xs text-text-tertiary truncate">
              {inst.currentTrack.artist || 'Unknown Artist'}
            </div>
          </div>

          {/* Progress bar */}
          <div class="mb-4">
            <div class="w-full h-1 bg-surface-overlay rounded-full overflow-hidden">
              <div
                class="h-full bg-accent rounded-full transition-[width] duration-1000 ease-linear"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div class="flex justify-between mt-1">
              <span class="font-mono text-[10px] text-text-tertiary">{formatTime(inst.position)}</span>
              <span class="font-mono text-[10px] text-text-tertiary">{formatTime(inst.duration)}</span>
            </div>
          </div>

          {/* Transport controls */}
          <div class="flex items-center gap-2">
            <button
              onClick={() => handleTransport('prev')}
              class="w-8 h-8 rounded-full flex items-center justify-center text-text-secondary hover:text-text-primary transition-colors"
              aria-label="Previous"
            >
              <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M6 6h2v12H6zm3.5 6l8.5 6V6z" />
              </svg>
            </button>
            <button
              onClick={() => handleTransport(isPlaying ? 'pause' : 'play')}
              class="w-10 h-10 rounded-full bg-accent flex items-center justify-center shadow-[0_0_16px_rgba(255,102,0,0.25)] hover:shadow-[0_0_24px_rgba(255,102,0,0.4)] transition-shadow"
              aria-label={isPlaying ? 'Pause' : 'Play'}
            >
              {isPlaying ? (
                <svg class="w-4 h-4 text-surface-base" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
                </svg>
              ) : (
                <svg class="w-4 h-4 text-surface-base ml-0.5" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M8 5v14l11-7z" />
                </svg>
              )}
            </button>
            <button
              onClick={() => handleTransport('next')}
              class="w-8 h-8 rounded-full flex items-center justify-center text-text-secondary hover:text-text-primary transition-colors"
              aria-label="Next"
            >
              <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M6 18l8.5-6L6 6v12zm2-8.14L11.03 12 8 14.14V9.86zM16 6h2v12h-2z" />
              </svg>
            </button>

            <div class="w-px h-6 bg-border mx-1" />

            <a
              href={`/admin/studio?mount=${encodeURIComponent(inst.mount)}`}
              class="h-8 px-3 rounded-lg border border-border flex items-center gap-1.5 text-[11px] font-mono text-text-secondary hover:text-text-primary hover:border-border-hover transition-colors"
            >
              <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z" />
              </svg>
              Studio
            </a>

            <button
              class="w-8 h-8 rounded-lg border border-border flex items-center justify-center text-text-tertiary hover:text-text-secondary hover:border-border-hover transition-colors"
              aria-label="Settings"
            >
              <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1115.6 12 3.6 3.6 0 0112 15.6z" />
              </svg>
            </button>
          </div>
        </>
      )}

      {/* Queue preview strip */}
      {!isStopped && inst.queue.length > 0 && (
        <div class="mt-4 pt-3 border-t border-border">
          <div class="flex items-center gap-2">
            <span class="font-mono text-[9px] tracking-widest text-text-tertiary uppercase flex-shrink-0">
              UP NEXT
            </span>
            <div class="flex items-center gap-1 min-w-0 overflow-hidden">
              {inst.queue.slice(0, 3).map((track, i) => (
                <div key={i} class="flex items-center gap-1 min-w-0">
                  {i > 0 && (
                    <svg class="w-3 h-3 text-text-tertiary flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z" />
                    </svg>
                  )}
                  <span class="text-[11px] text-text-tertiary truncate">{track}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export function AutoDJ() {
  useEffect(() => {
    loading.value = true
    api.get<AutoDJInstance[]>('/api/autodj')
      .then((data) => { instances.value = data })
      .catch(() => { instances.value = [] })
      .finally(() => { loading.value = false })

    const sse = createSSE('/events')
    sse.on('autodj', (evt: AutoDJEvent) => {
      instances.value = instances.value.map((inst) =>
        inst.mount === evt.mount
          ? {
              ...inst,
              state: evt.state,
              currentTrack: evt.currentTrack,
              position: evt.position,
              duration: evt.duration,
              queue: evt.queue,
            }
          : inst
      )
    })

    sse.on('stream', (evt) => {
      instances.value = instances.value.map((inst) =>
        inst.mount === evt.mount ? { ...inst, listeners: evt.listeners } : inst
      )
    })

    return () => sse.close()
  }, [])

  return (
    <div class="p-6">
      {/* Header */}
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-xl font-bold text-text-primary font-heading">AutoDJ</h1>
        <button class="h-9 px-4 rounded-lg bg-accent text-surface-base text-sm font-medium flex items-center gap-2 hover:shadow-[0_0_20px_rgba(255,102,0,0.3)] transition-shadow">
          <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
            <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z" />
          </svg>
          New AutoDJ
        </button>
      </div>

      {/* Loading */}
      {loading.value && (
        <div class="flex items-center justify-center py-20">
          <div class="flex items-center gap-3 text-text-tertiary">
            <EqBars bars={3} />
            <span class="text-sm">Loading...</span>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!loading.value && instances.value.length === 0 && (
        <div class="flex flex-col items-center justify-center py-20 text-text-tertiary">
          <svg class="w-12 h-12 mb-4 opacity-30" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z" />
          </svg>
          <p class="text-sm">No AutoDJ instances configured</p>
        </div>
      )}

      {/* Instance cards */}
      {!loading.value && instances.value.length > 0 && (
        <div class="grid gap-4 grid-cols-1 lg:grid-cols-2">
          {instances.value.map((inst) => (
            <InstanceCard key={inst.mount} inst={inst} />
          ))}
        </div>
      )}
    </div>
  )
}
