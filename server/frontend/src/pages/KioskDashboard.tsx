import { useEffect, useRef } from 'preact/hooks'
import { signal } from '@preact/signals'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { createSSE } from '../lib/sse'

// KioskDashboard — full-screen status wall for studio / NOC display.
// Designed for a TV mounted in the control room: no nav, no chrome,
// big numbers, live LTC clock, live map, per-mount status cards
// stacked down the right side.
//
// Authenticated via the same admin session as /admin. Bounce to
// /login on 401 like the rest of the dashboard.
//
// Refresh strategy: 100% SSE-driven. The /admin/events stream
// already pushes stats / per-stream / geo every ~500 ms; we just
// re-render whenever data arrives. Wall clock + LTC tick locally
// at 25 fps (40 ms) on a separate animation timer.

// Pulled from window.__TINYICE__ — set by the Go shell renderer.
type PageData = {
  title?: string
  subtitle?: string
  branding?: { accentColor?: string; logoUrl?: string | null }
  user?: { username?: string; role?: string }
}
const data = (window.__TINYICE__ ?? {}) as Partial<PageData>

// SSE shapes — lightly typed; we accept whatever the server sends.
type StatsEv = {
  listeners?: number
  bandwidth_in?: number
  bandwidth_out?: number
  bytes_in?: number
  bytes_out?: number
  uptime?: number
}
type StreamEv = {
  mount: string
  title?: string
  artist?: string
  format?: string
  bitrate?: number | string
  listeners?: number
  health?: number
  is_transcoded?: boolean
  source_type?: string
  source_bitrate?: string
}
type GeoCity = {
  iso: string
  country?: string
  city?: string
  lat: number
  lon: number
  listeners: number
}

const stats = signal<StatsEv>({})
const streams = signal<Record<string, StreamEv>>({})
const geo = signal<GeoCity[]>([])
const sseUp = signal(false)
const tick = signal(0) // bumped every 40 ms by the local wall-clock timer

// ── helpers ───────────────────────────────────────────────────────────────

function formatBandwidth(bps: number): string {
  if (!bps || !Number.isFinite(bps)) return '0 B/s'
  if (bps < 1024) return `${bps} B/s`
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`
  return `${(bps / (1024 * 1024)).toFixed(1)} MB/s`
}

function formatUptime(s: number): string {
  if (!s) return '—'
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

function fmt2(n: number): string {
  return n < 10 ? `0${n}` : `${n}`
}

// LTC clock — 25 fps wall-clock time-of-day display, format
// HH:MM:SS:FF where FF is the frame count (0–24). Same as a
// broadcast LTC generator running in free-run mode locked to
// system time. Updates from the local `tick` signal so a missing
// SSE update doesn't freeze the clock.
function useLtcDisplay() {
  const now = new Date()
  void tick.value // subscribe to the tick signal so we re-render
  const ms = now.getMilliseconds()
  const frame = Math.floor(ms / 40) // 25 fps -> 40 ms per frame
  return {
    hms: `${fmt2(now.getHours())}:${fmt2(now.getMinutes())}:${fmt2(now.getSeconds())}`,
    ff: fmt2(frame),
    utc:
      `${fmt2(now.getUTCHours())}:${fmt2(now.getUTCMinutes())}:${fmt2(now.getUTCSeconds())}`,
    date: now.toLocaleDateString(undefined, {
      weekday: 'short',
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    }),
  }
}

// Marker radius in pixels: sqrt scaling so a 100-listener city
// isn't 100x the area of a 1-listener city.
function radiusFor(n: number): number {
  if (n <= 0) return 0
  return Math.max(4, Math.round(4 + Math.sqrt(n) * 3))
}

// ── component ────────────────────────────────────────────────────────────

export function KioskDashboard() {
  const mapEl = useRef<HTMLDivElement>(null)
  const mapRef = useRef<L.Map | null>(null)
  const layerRef = useRef<L.LayerGroup | null>(null)

  // SSE wiring — single source of truth for everything live on the page.
  useEffect(() => {
    const sse = createSSE('/admin/events')
    const offStats = sse.on('stats', (d: StatsEv) => {
      stats.value = d
      sseUp.value = true
    })
    const offStream = sse.on('stream', (d: StreamEv) => {
      streams.value = { ...streams.value, [d.mount]: d }
    })
    const offGeo = sse.on('geo', (d: GeoCity[]) => {
      geo.value = Array.isArray(d) ? d : []
    })
    return () => {
      offStats()
      offStream()
      offGeo()
      sse.close()
    }
  }, [])

  // Local wall-clock tick (LTC frame counter). Animates at 25 fps so
  // the FF digits look continuous; cheap because we only signal a
  // counter, not full state.
  useEffect(() => {
    const id = window.setInterval(() => {
      tick.value = tick.value + 1
    }, 40)
    return () => window.clearInterval(id)
  }, [])

  // Map init + live geo.
  useEffect(() => {
    if (!mapEl.current || mapRef.current) return
    const m = L.map(mapEl.current, {
      attributionControl: true,
      zoomControl: false,
      worldCopyJump: true,
      minZoom: 1,
      maxZoom: 8,
    }).setView([20, 0], 2)
    L.tileLayer(
      'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
      {
        subdomains: 'abcd',
        maxZoom: 19,
        attribution:
          '&copy; OSM · CARTO · GeoIP db-ip.com CC-BY-4.0',
      },
    ).addTo(m)
    layerRef.current = L.layerGroup().addTo(m)
    mapRef.current = m
    return () => {
      m.remove()
      mapRef.current = null
      layerRef.current = null
    }
  }, [])

  // Map markers + autozoom on every geo refresh.
  useEffect(() => {
    const map = mapRef.current
    const layer = layerRef.current
    if (!map || !layer) return
    layer.clearLayers()
    const d = geo.value
    const points: L.LatLngExpression[] = []
    for (const c of d) {
      if (!c.lat && !c.lon) continue
      const marker = L.circleMarker([c.lat, c.lon], {
        radius: radiusFor(c.listeners),
        color: '#ff8a3d',
        weight: 1.5,
        fillColor: '#ff8a3d',
        fillOpacity: 0.6,
      })
      const label = c.city
        ? `${c.city}${c.country ? ' · ' + c.country : ''}`
        : c.country || c.iso
      marker.bindTooltip(
        `<strong>${label}</strong><br/>${c.listeners} listener${c.listeners === 1 ? '' : 's'}`,
        { direction: 'top' },
      )
      marker.addTo(layer)
      points.push([c.lat, c.lon])
    }
    if (points.length === 0) {
      map.flyTo([20, 0], 2, { animate: true, duration: 1.0 })
      return
    }
    if (points.length === 1) {
      map.flyTo(points[0], 5, { animate: true, duration: 1.0 })
      return
    }
    map.flyToBounds(L.latLngBounds(points), {
      padding: [60, 60],
      maxZoom: 6,
      animate: true,
      duration: 1.0,
    })
  }, [geo.value])

  const ltc = useLtcDisplay()
  const streamList = Object.values(streams.value).sort((a, b) => a.mount.localeCompare(b.mount))
  const totalListeners = streamList.reduce((acc, s) => acc + (s.listeners ?? 0), 0)
  const liveMounts = streamList.filter((s) => (s.listeners ?? 0) > 0 || (s.health ?? 0) > 0).length

  return (
    <div class="min-h-screen bg-surface-base text-text-primary flex flex-col">
      {/* Top bar — station name, big LTC clock, KPIs */}
      <div class="flex items-center gap-6 px-6 py-3 border-b border-border bg-surface-raised">
        <div class="flex flex-col">
          <span class="font-mono text-[10px] tracking-[3px] uppercase text-text-tertiary">
            On Air
          </span>
          <span class="text-xl font-bold leading-tight">
            {data.title || 'TinyIce'}
          </span>
        </div>

        <div class="flex-1 flex items-center justify-center gap-6 font-mono tabular-nums">
          <div class="flex flex-col items-center">
            <span class="text-[9px] tracking-[3px] uppercase text-text-tertiary">LTC · 25 fps</span>
            <span class="text-5xl font-bold tracking-wider text-accent">
              {ltc.hms}
              <span class="text-3xl text-text-secondary ml-1">:{ltc.ff}</span>
            </span>
          </div>
          <div class="flex flex-col items-center">
            <span class="text-[9px] tracking-[3px] uppercase text-text-tertiary">UTC</span>
            <span class="text-2xl text-text-secondary">{ltc.utc}</span>
          </div>
        </div>

        <div class="flex gap-6 font-mono">
          <div class="flex flex-col items-end">
            <span class="text-[9px] tracking-[3px] uppercase text-text-tertiary">Listeners</span>
            <span class="text-3xl font-bold text-accent tabular-nums">{totalListeners}</span>
          </div>
          <div class="flex flex-col items-end">
            <span class="text-[9px] tracking-[3px] uppercase text-text-tertiary">Mounts live</span>
            <span class="text-3xl font-bold tabular-nums">{liveMounts}</span>
          </div>
          <div class="flex flex-col items-end">
            <span class="text-[9px] tracking-[3px] uppercase text-text-tertiary">Out</span>
            <span class="text-xl text-text-secondary tabular-nums">
              {formatBandwidth(stats.value.bandwidth_out ?? stats.value.bytes_out ?? 0)}
            </span>
          </div>
          <div class="flex flex-col items-end">
            <span class="text-[9px] tracking-[3px] uppercase text-text-tertiary">Uptime</span>
            <span class="text-xl text-text-secondary tabular-nums">
              {formatUptime(stats.value.uptime ?? 0)}
            </span>
          </div>
          <div class="flex flex-col items-end justify-center">
            <span class="text-[9px] tracking-[3px] uppercase text-text-tertiary">SSE</span>
            <span
              class="w-2.5 h-2.5 rounded-full mt-1"
              style={{
                backgroundColor: sseUp.value ? 'var(--color-live)' : 'var(--color-danger)',
                animation: sseUp.value ? 'pulse-glow 2s ease-in-out infinite' : 'none',
              }}
            />
          </div>
        </div>
      </div>

      {/* Main grid — left: map, right: per-mount stream cards */}
      <div class="flex-1 grid grid-cols-1 lg:grid-cols-[2fr_1fr] gap-4 p-4 min-h-0">
        <div class="rounded-lg border border-border bg-surface-raised overflow-hidden flex flex-col min-h-0">
          <div class="flex items-center justify-between px-4 py-2 border-b border-border">
            <span class="font-mono text-[10px] tracking-widest uppercase text-text-tertiary">
              Listeners worldwide
            </span>
            <span class="font-mono text-[10px] text-text-tertiary tabular-nums">
              {geo.value.length} {geo.value.length === 1 ? 'city' : 'cities'} · {totalListeners} {totalListeners === 1 ? 'listener' : 'listeners'}
            </span>
          </div>
          <div ref={mapEl} class="flex-1 min-h-0" />
        </div>

        <div class="flex flex-col gap-3 min-h-0 overflow-y-auto">
          {streamList.length === 0 && (
            <div class="rounded-lg border border-border bg-surface-raised p-6 text-center text-text-tertiary font-mono text-sm">
              waiting for streams…
            </div>
          )}
          {streamList.map((s) => (
            <StreamCard key={s.mount} s={s} />
          ))}
        </div>
      </div>

      {/* Bottom bar — branding + attribution */}
      <div class="flex items-center justify-between px-6 py-2 border-t border-border bg-surface-raised text-text-tertiary font-mono text-[10px]">
        <span>{data.subtitle || ''}</span>
        <span>kiosk · live data via /admin/events SSE · GeoIP db-ip.com CC BY 4.0</span>
      </div>
    </div>
  )
}

function StreamCard({ s }: { s: StreamEv }) {
  const live = (s.listeners ?? 0) > 0
  const health = s.health ?? 0
  return (
    <div class="rounded-lg border border-border bg-surface-raised p-4 flex flex-col gap-2">
      <div class="flex items-baseline justify-between gap-2">
        <span class="font-mono font-bold text-base text-text-primary">{s.mount}</span>
        <span
          class="w-2 h-2 rounded-full"
          style={{
            backgroundColor: live ? 'var(--color-live)' : 'var(--color-text-tertiary)',
            animation: live ? 'pulse-glow 2s ease-in-out infinite' : 'none',
          }}
        />
      </div>
      {s.title && (
        <div class="text-sm text-text-secondary leading-tight">
          <span class="text-text-tertiary text-[9px] tracking-widest uppercase block">Now playing</span>
          {s.artist ? `${s.artist} — ${s.title}` : s.title}
        </div>
      )}
      <div class="flex items-center justify-between mt-1">
        <div class="flex items-center gap-1.5 font-mono text-[11px]">
          {s.is_transcoded && s.source_type ? (
            <>
              <span class="text-text-tertiary uppercase">{formatChip(s.source_type)}</span>
              {s.source_bitrate && <span class="text-text-tertiary">{s.source_bitrate}k</span>}
              <span class="text-text-tertiary">→</span>
              <span class="text-text-secondary uppercase">{formatChip(s.format ?? '')}</span>
              {Number(s.bitrate) > 0 && <span class="text-text-tertiary">{s.bitrate}k</span>}
            </>
          ) : (
            <>
              <span class="text-text-secondary uppercase">{formatChip(s.format ?? '')}</span>
              {Number(s.bitrate) > 0 && <span class="text-text-tertiary">{s.bitrate}k</span>}
            </>
          )}
        </div>
        <span class="font-mono text-2xl font-bold text-accent tabular-nums">
          {s.listeners ?? 0}
        </span>
      </div>
      {/* Health bar */}
      <div class="flex items-center gap-2">
        <div class="flex-1 h-1 rounded-full bg-surface-overlay overflow-hidden">
          <div
            class="h-full rounded-full transition-all duration-500"
            style={{
              width: `${Math.min(100, Math.max(0, health))}%`,
              backgroundColor:
                health >= 80
                  ? 'var(--color-live)'
                  : health >= 50
                    ? 'var(--color-accent)'
                    : 'var(--color-danger)',
            }}
          />
        </div>
        <span class="font-mono text-[10px] text-text-tertiary tabular-nums">
          {Math.round(health)}%
        </span>
      </div>
    </div>
  )
}

function formatChip(ct: string): string {
  const lower = (ct || '').toLowerCase()
  if (lower.includes('mpeg') || lower.includes('mp3')) return 'MP3'
  if (lower.includes('opus')) return 'OPUS'
  if (lower.includes('ogg')) return 'OGG'
  if (lower.includes('aac')) return 'AAC'
  if (lower.includes('flac')) return 'FLAC'
  if (lower.includes('vorbis')) return 'VORBIS'
  if (lower.startsWith('audio/')) return lower.slice(6).toUpperCase()
  return lower.toUpperCase() || '—'
}
