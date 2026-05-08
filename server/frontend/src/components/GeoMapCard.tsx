import { useEffect, useRef } from 'preact/hooks'
import { signal } from '@preact/signals'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { api } from '../lib/api'

// GeoMapCard — live listener map.
//
// Tiles come from CartoDB's free "Dark Matter" basemap: no API key,
// no signup, OpenStreetMap data, free for non-commercial use with
// attribution. Tracks subdomains a-d for browser-side request
// parallelism.
//
// Listener data comes from /admin/geo, refreshed every 15 s. Each
// country with at least one listener is rendered as a circle marker
// at its centroid; radius scales with sqrt(listeners) so 100
// listeners isn't 100x the size of one.

type GeoCountry = {
  iso: string
  name: string
  lat: number
  lon: number
  listeners: number
  mounts?: Record<string, number>
}

type GeoResp = {
  countries: GeoCountry[]
  total: number
  attribution: string
}

const data = signal<GeoResp | null>(null)
const loading = signal(false)
const error = signal<string | null>(null)

function fetchGeo() {
  if (loading.value) return
  loading.value = true
  error.value = null
  api
    .get<GeoResp>('/admin/geo')
    .then((d) => (data.value = d))
    .catch((err) => (error.value = err?.message || 'Failed to load geo'))
    .finally(() => (loading.value = false))
}

// Marker radius in pixels: sqrt scaling so a 100-listener country
// isn't 100x the area of a 1-listener country, but still
// proportional. Floor at 4 px so single-listener bubbles are
// clickable.
function radiusFor(n: number): number {
  if (n <= 0) return 0
  return Math.max(4, Math.round(4 + Math.sqrt(n) * 3))
}

export function GeoMapCard() {
  const containerRef = useRef<HTMLDivElement>(null)
  const mapRef = useRef<L.Map | null>(null)
  const layerRef = useRef<L.LayerGroup | null>(null)

  // Init map once on mount.
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return
    const m = L.map(containerRef.current, {
      attributionControl: true,
      zoomControl: true,
      worldCopyJump: true,
      minZoom: 1,
      maxZoom: 6,
    }).setView([20, 0], 2)

    L.tileLayer(
      'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
      {
        subdomains: 'abcd',
        maxZoom: 19,
        attribution:
          '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> · &copy; <a href="https://carto.com/attributions">CARTO</a> · GeoIP: <a href="https://db-ip.com/">DB-IP</a> CC-BY-4.0',
      },
    ).addTo(m)

    layerRef.current = L.layerGroup().addTo(m)
    mapRef.current = m
    fetchGeo()
    const id = window.setInterval(fetchGeo, 15_000)
    return () => {
      window.clearInterval(id)
      m.remove()
      mapRef.current = null
      layerRef.current = null
    }
  }, [])

  // Re-render markers whenever data changes.
  useEffect(() => {
    if (!layerRef.current) return
    layerRef.current.clearLayers()
    const d = data.value
    if (!d || !d.countries.length) return
    for (const c of d.countries) {
      if (!c.lat && !c.lon) continue // unknown centroid
      const marker = L.circleMarker([c.lat, c.lon], {
        radius: radiusFor(c.listeners),
        color: '#ff8a3d',
        weight: 1.5,
        fillColor: '#ff8a3d',
        fillOpacity: 0.55,
      })
      const mountsLine = c.mounts
        ? Object.entries(c.mounts)
            .map(([m, n]) => `${m}: ${n}`)
            .join('<br/>')
        : ''
      marker.bindTooltip(
        `<strong>${c.name}</strong><br/>${c.listeners} listener${c.listeners === 1 ? '' : 's'}` +
          (mountsLine ? `<br/><span style="opacity:.7">${mountsLine}</span>` : ''),
        { direction: 'top' },
      )
      marker.addTo(layerRef.current!)
    }
  }, [data.value])

  return (
    <div class="rounded-lg border border-border bg-surface-raised p-4">
      <div class="flex items-center justify-between mb-3">
        <span class="font-mono text-[10px] tracking-widest uppercase text-text-tertiary">
          Listeners worldwide
        </span>
        <span class="font-mono text-[10px] text-text-tertiary tabular-nums">
          {data.value
            ? `${data.value.total} listener${data.value.total === 1 ? '' : 's'} · ${data.value.countries.length} ${data.value.countries.length === 1 ? 'country' : 'countries'}`
            : '…'}
        </span>
      </div>
      {error.value && (
        <div class="text-danger text-xs font-mono mb-2">{error.value}</div>
      )}
      <div
        ref={containerRef}
        class="h-72 w-full rounded-md border border-border/70 bg-surface-base overflow-hidden"
      />
      <div class="mt-2 font-mono text-[9px] text-text-tertiary">
        Tiles: CARTO / OpenStreetMap. GeoIP data: db-ip.com / CC BY 4.0.
      </div>
    </div>
  )
}
