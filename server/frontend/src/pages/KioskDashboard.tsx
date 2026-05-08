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

  // Map init + live geo. Leaflet computes lat/lon → pixel from the
  // container size at render time; if the container resizes (kiosk
  // mounts, container starts at 0×0 before flexbox layout settles,
  // viewport rotates, etc.) the projection goes stale and
  // flyToBounds picks a target against the wrong viewport — markers
  // land in the wrong place and the fly zoom is off. Hooking a
  // ResizeObserver fires invalidateSize() on every container size
  // change, which keeps the projection honest.
  useEffect(() => {
    const container = mapEl.current
    if (!container || mapRef.current) return
    const m = L.map(container, {
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

    // Initial nudge: in case the container started at 0×0 (flexbox
    // hadn't laid out yet) re-validate after one paint.
    requestAnimationFrame(() => m.invalidateSize())

    const ro = new ResizeObserver(() => {
      m.invalidateSize()
    })
    ro.observe(container)

    return () => {
      ro.disconnect()
      m.remove()
      mapRef.current = null
      layerRef.current = null
    }
  }, [])

  // Map markers + autozoom. Smart-fit:
  //   - 0 listeners: world view centred at (20, 0), zoom 2.
  //   - 1 city: fly to that point at zoom 5 (city-wide).
  //   - many cities, all within ~one continent (bounds < ~60° in
  //     either lat or lon): fly to bounds with maxZoom 5.
  //   - many cities spread worldwide: world view at zoom 2 — no
  //     wandering camera centred on mid-ocean.
  useEffect(() => {
    const map = mapRef.current
    const layer = layerRef.current
    if (!map || !layer) return
    // Re-validate the projection before computing fly targets — if a
    // resize raced with this update the bounds math would otherwise
    // be against a stale viewport.
    map.invalidateSize()
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
    const bounds = L.latLngBounds(points)
    const sw = bounds.getSouthWest()
    const ne = bounds.getNorthEast()
    const latSpan = Math.abs(ne.lat - sw.lat)
    const lonSpan = Math.abs(ne.lng - sw.lng)
    if (latSpan > 60 || lonSpan > 100) {
      // Worldwide spread — fitBounds would centre on a meaningless
      // mid-ocean point. Show the world instead.
      map.flyTo([20, 0], 2, { animate: true, duration: 1.0 })
      return
    }
    map.flyToBounds(bounds, {
      padding: [60, 60],
      maxZoom: 5,
      animate: true,
      duration: 1.0,
    })
  }, [geo.value])

  const ltc = useLtcDisplay()
  const streamList = Object.values(streams.value).sort((a, b) => a.mount.localeCompare(b.mount))
  const totalListeners = streamList.reduce((acc, s) => acc + (s.listeners ?? 0), 0)
  const liveMounts = streamList.filter((s) => (s.listeners ?? 0) > 0 || (s.health ?? 0) > 0).length

  return (
    <div class="h-screen w-screen overflow-hidden bg-surface-base text-text-primary flex flex-col">
      {/* Top bar — station name, big LTC clock, KPIs. Fixed height,
          single row, content tightened so it fits a 720p TV without
          wrapping. */}
      <div class="flex items-center gap-4 px-5 py-2 border-b border-border bg-surface-raised shrink-0">
        <div class="flex items-baseline gap-2 min-w-0">
          <span class="font-mono text-[9px] tracking-[3px] uppercase text-text-tertiary">
            On Air
          </span>
          <span class="text-lg font-bold leading-none truncate">
            {data.title || 'TinyIce'}
          </span>
        </div>

        <div class="flex-1 flex items-baseline justify-center gap-4 font-mono tabular-nums">
          <span class="text-4xl font-bold tracking-wider text-accent leading-none">
            {ltc.hms}
            <span class="text-2xl text-text-secondary ml-1">:{ltc.ff}</span>
          </span>
          <div class="flex flex-col leading-none">
            <span class="text-[8px] tracking-[3px] uppercase text-text-tertiary">UTC</span>
            <span class="text-base text-text-secondary mt-0.5">{ltc.utc}</span>
          </div>
        </div>

        <div class="flex gap-4 font-mono items-baseline">
          <Kpi label="Listeners" value={String(totalListeners)} accent />
          <Kpi label="Mounts" value={String(liveMounts)} />
          <Kpi
            label="Out"
            value={formatBandwidth(stats.value.bandwidth_out ?? stats.value.bytes_out ?? 0)}
            small
          />
          <Kpi label="Uptime" value={formatUptime(stats.value.uptime ?? 0)} small />
          <span
            class="w-2 h-2 rounded-full self-center"
            title={sseUp.value ? 'SSE live' : 'SSE down'}
            style={{
              backgroundColor: sseUp.value ? 'var(--color-live)' : 'var(--color-danger)',
              animation: sseUp.value ? 'pulse-glow 2s ease-in-out infinite' : 'none',
            }}
          />
        </div>
      </div>

      {/* Main grid — flex-1 fills the rest; min-h-0 lets the children
          (map, scrollable stream column) actually constrain to the
          available height instead of overflowing. */}
      <div class="flex-1 grid grid-cols-1 lg:grid-cols-[2fr_1fr] gap-3 p-3 min-h-0 min-w-0">
        <div class="rounded-lg border border-border bg-surface-raised overflow-hidden flex flex-col min-h-0">
          <div class="flex items-center justify-between px-3 py-1.5 border-b border-border shrink-0">
            <span class="font-mono text-[10px] tracking-widest uppercase text-text-tertiary">
              Listeners worldwide
            </span>
            <span class="font-mono text-[10px] text-text-tertiary tabular-nums">
              {geo.value.length} {geo.value.length === 1 ? 'city' : 'cities'} · {totalListeners} {totalListeners === 1 ? 'listener' : 'listeners'}
            </span>
          </div>
          <div ref={mapEl} class="flex-1 min-h-0" />
        </div>

        <div class="flex flex-col gap-2 min-h-0 overflow-y-auto pr-1">
          {streamList.length === 0 && (
            <div class="rounded-lg border border-border bg-surface-raised p-4 text-center text-text-tertiary font-mono text-sm">
              waiting for streams…
            </div>
          )}
          {streamList.map((s) => (
            <StreamCard key={s.mount} s={s} />
          ))}
        </div>
      </div>

      {/* Bottom bar — branding + attribution. shrink-0 so it never
          steals space from the main grid. */}
      <div class="flex items-center justify-between px-5 py-1.5 border-t border-border bg-surface-raised text-text-tertiary font-mono text-[9px] shrink-0">
        <span class="truncate">{data.subtitle || ''}</span>
        <span class="truncate">kiosk · /admin/events SSE · GeoIP db-ip.com CC BY 4.0</span>
      </div>
    </div>
  )
}

// Kpi — compact top-bar tile. accent=true paints the value in the
// brand orange; small=true makes the value smaller (used for less-
// important metrics like bandwidth and uptime).
function Kpi({
  label, value, accent = false, small = false,
}: { label: string; value: string; accent?: boolean; small?: boolean }) {
  return (
    <div class="flex flex-col items-end leading-none">
      <span class="text-[8px] tracking-[3px] uppercase text-text-tertiary">{label}</span>
      <span
        class={`mt-0.5 font-bold tabular-nums ${
          small ? 'text-base' : 'text-2xl'
        } ${accent ? 'text-accent' : 'text-text-primary'}`}
      >
        {value}
      </span>
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
