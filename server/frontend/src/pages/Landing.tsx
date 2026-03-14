import { useEffect } from 'preact/hooks'
import { signal } from '@preact/signals'
import { Nav } from '@/components/Nav'
import { StreamCard } from '@/components/StreamCard'
import { createSSE } from '@/lib/sse'
import type { LandingData, StreamInfo } from '@/types'

const data = (window.__TINYICE__ ?? {}) as Partial<LandingData>
const streams = signal<StreamInfo[]>(data.streams ?? [])

export function Landing() {
  useEffect(() => {
    const sse = createSSE('/events')

    sse.on('streams', (updated) => {
      streams.value = updated
    })

    sse.on('stream', (evt) => {
      streams.value = streams.value.map((s) =>
        s.mount === evt.mount
          ? { ...s, title: evt.title, artist: evt.artist, listeners: evt.listeners, live: true }
          : s
      )
    })

    sse.on('metadata', (evt) => {
      streams.value = streams.value.map((s) =>
        s.mount === evt.mount ? { ...s, title: evt.title, artist: evt.artist } : s
      )
    })

    return () => sse.close()
  }, [])

  const liveStreams = streams.value.filter((s) => s.live)
  const hasLive = liveStreams.length > 0

  return (
    <div class="min-h-screen bg-surface-base relative overflow-hidden">
      {/* Dot grid texture */}
      <div
        class="fixed inset-0 pointer-events-none z-0"
        style={{
          backgroundImage: 'radial-gradient(rgba(255,255,255,0.03) 1px, transparent 1px)',
          backgroundSize: '20px 20px',
        }}
      />

      {/* Ambient orange glow */}
      <div
        class="fixed top-0 right-0 w-[800px] h-[800px] pointer-events-none z-0"
        style={{
          background: 'radial-gradient(ellipse at 80% 20%, rgba(255,102,0,0.06) 0%, transparent 70%)',
        }}
      />

      {/* Nav */}
      <Nav branding={data.branding ?? { logoUrl: null, accentColor: '#ff6600', landingMarkdown: '' }} />

      {/* Hero */}
      <main class="relative z-10 pt-14">
        <div class="mx-auto max-w-7xl px-4 py-20 lg:py-32">
          <div class="flex flex-col lg:flex-row gap-12 lg:gap-20 items-start">
            {/* Left column */}
            <div class="flex flex-col gap-8 min-w-0 flex-1">
              {/* Category label */}
              <span class="font-mono text-xs tracking-widest text-accent">
                — AUDIO STREAMING SERVER
              </span>

              {/* Headline */}
              <h1 class="font-heading text-5xl font-bold tracking-tight leading-tight">
                One binary.
                <br />
                <span class="bg-gradient-to-r from-white to-accent bg-clip-text text-transparent">
                  Pure audio.
                </span>
              </h1>

              {/* Description */}
              <p class="text-text-tertiary text-base leading-relaxed max-w-md">
                A lightweight, high-performance audio streaming server written in pure Go.
                Deploy anywhere with a single binary — no dependencies, no containers, no complexity.
              </p>

              {/* CTA buttons */}
              <div class="flex items-center gap-4">
                <a
                  href="/admin"
                  class="font-mono text-xs tracking-widest font-bold px-6 py-3 rounded bg-accent text-surface-base hover:bg-accent/90 transition-colors"
                  style={{ boxShadow: '0 0 20px rgba(255,102,0,0.25)' }}
                >
                  GET STARTED
                </a>
                <a
                  href="/developers"
                  class="font-mono text-xs tracking-widest font-bold px-6 py-3 rounded border border-border hover:border-border-hover text-text-secondary hover:text-text-primary transition-colors"
                >
                  VIEW DOCS
                </a>
              </div>

              {/* Stats strip */}
              <div class="border-t border-border pt-6 mt-4 flex items-center gap-10">
                <div class="flex flex-col gap-1">
                  <span class="font-mono text-2xl font-bold text-text-primary">100K+</span>
                  <span class="font-mono text-[10px] tracking-wider text-text-tertiary uppercase">
                    Concurrent
                  </span>
                </div>
                <div class="flex flex-col gap-1">
                  <span class="font-mono text-2xl font-bold text-text-primary">&lt;1ms</span>
                  <span class="font-mono text-[10px] tracking-wider text-text-tertiary uppercase">
                    Latency
                  </span>
                </div>
                <div class="flex flex-col gap-1">
                  <span class="font-mono text-2xl font-bold text-text-primary">~8MB</span>
                  <span class="font-mono text-[10px] tracking-wider text-text-tertiary uppercase">
                    Binary
                  </span>
                </div>
              </div>
            </div>

            {/* Right column */}
            <div class="flex flex-col gap-4 w-full lg:w-[360px] lg:shrink-0">
              {/* Live streams header */}
              <div class="flex items-center gap-2 mb-2">
                {hasLive && (
                  <span
                    class="w-2 h-2 rounded-full bg-live"
                    style={{ animation: 'pulse-glow 2s ease-in-out infinite' }}
                  />
                )}
                <span class="font-mono text-xs tracking-widest text-text-secondary">
                  LIVE STREAMS
                </span>
              </div>

              {/* Stream cards */}
              {streams.value.length > 0 ? (
                <div class="flex flex-col gap-3">
                  {streams.value.map((stream) => (
                    <StreamCard
                      key={stream.mount}
                      stream={stream}
                      onPlay={() => {
                        window.location.href = `/player/${stream.mount}`
                      }}
                    />
                  ))}
                </div>
              ) : (
                <div class="rounded-lg border border-border bg-surface-raised p-8 text-center">
                  <p class="font-mono text-xs text-text-tertiary tracking-wider">
                    NO ACTIVE STREAMS
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer class="relative z-10 border-t border-border">
        <div class="mx-auto max-w-7xl px-4 py-6 flex items-center justify-between">
          <span class="font-mono text-[9px] tracking-widest text-text-tertiary/50 uppercase">
            TINYICE // PURE GO
          </span>
          <span class="font-mono text-[9px] tracking-widest text-text-tertiary/50">
            {data.version || 'dev'}
          </span>
        </div>
      </footer>
    </div>
  )
}
