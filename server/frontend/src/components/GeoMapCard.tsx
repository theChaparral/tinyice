import { useEffect, useRef } from 'preact/hooks'
import { signal } from '@preact/signals'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { createSSE } from '../lib/sse'

// GeoMapCard — live listener map at city granularity.
//
// Tiles: CartoDB Dark Matter (no API key, OpenStreetMap data).
// Geo data: city + lat/lon from DB-IP city-lite (CC BY 4.0, no key,
// no signup). Resolved per listener at connect time, aggregated on
// the server by (country, city) so co-located listeners collapse
// into one bigger bubble.
//
// Updates: piggyback on the dashboard's `/admin/events` SSE stream
// instead of polling /admin/geo. Each connect / disconnect pushes a
// fresh `geo` event so the map ticks live with the rest of the
// dashboard counters.

type GeoCity = {
  iso: string
  country?: string
  city?: string
  lat: number
  lon: number
  listeners: number
  mounts?: Record<string, number>
}

const data = signal<GeoCity[]>([])

// Marker radius in pixels: sqrt scaling so a 100-listener city
// isn't 100x the area of a 1-listener city, but still proportional.
// Floor at 4 px so single-listener bubbles stay clickable.
function radiusFor(n: number): number {
  if (n <= 0) return 0
  return Math.max(4, Math.round(4 + Math.sqrt(n) * 3))
}

function totalListeners(d: GeoCity[]): number {
  return d.reduce((acc, c) => acc + c.listeners, 0)
}

function cityCount(d: GeoCity[]): number {
  return d.filter((c) => c.lat !== 0 || c.lon !== 0).length
}

export function GeoMapCard() {
  const containerRef = useRef<HTMLDivElement>(null)
  const mapRef = useRef<L.Map | null>(null)
  const layerRef = useRef<L.LayerGroup | null>(null)

  // Init map once on mount; subscribe to SSE for live updates.
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return
    const m = L.map(containerRef.current, {
      attributionControl: true,
      zoomControl: true,
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
          '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> · &copy; <a href="https://carto.com/attributions">CARTO</a> · GeoIP: <a href="https://db-ip.com/">DB-IP</a> CC-BY-4.0',
      },
    ).addTo(m)

    layerRef.current = L.layerGroup().addTo(m)
    mapRef.current = m

    const sse = createSSE('/admin/events')
    const off = sse.on('geo', (payload: GeoCity[]) => {
      data.value = Array.isArray(payload) ? payload : []
    })

    return () => {
      off()
      sse.close()
      m.remove()
      mapRef.current = null
      layerRef.current = null
    }
  }, [])

  // Re-render markers + auto-fit whenever data changes. Auto-fits
  // the camera to the bounding box of all currently active cities;
  // a single city pans to it at zoom 5 (city-wide), no listeners
  // returns to the world view.
  useEffect(() => {
    const map = mapRef.current
    const layer = layerRef.current
    if (!map || !layer) return
    layer.clearLayers()
    const d = data.value
    if (!d.length) {
      map.flyTo([20, 0], 2, { animate: true, duration: 0.8 })
      return
    }
    const points: L.LatLngExpression[] = []
    for (const c of d) {
      if (!c.lat && !c.lon) continue // unknown / unresolved
      const marker = L.circleMarker([c.lat, c.lon], {
        radius: radiusFor(c.listeners),
        color: '#ff8a3d',
        weight: 1.5,
        fillColor: '#ff8a3d',
        fillOpacity: 0.55,
      })
      const cityLine = c.city
        ? `<strong>${c.city}</strong>${c.country ? ` · ${c.country}` : ''}`
        : `<strong>${c.country || c.iso}</strong>`
      const mountsLine = c.mounts
        ? Object.entries(c.mounts)
            .map(([m, n]) => `${m}: ${n}`)
            .join('<br/>')
        : ''
      marker.bindTooltip(
        `${cityLine}<br/>${c.listeners} listener${c.listeners === 1 ? '' : 's'}` +
          (mountsLine ? `<br/><span style="opacity:.7">${mountsLine}</span>` : ''),
        { direction: 'top' },
      )
      marker.addTo(layer)
      points.push([c.lat, c.lon])
    }
    if (points.length === 0) {
      map.flyTo([20, 0], 2, { animate: true, duration: 0.8 })
      return
    }
    if (points.length === 1) {
      map.flyTo(points[0], 5, { animate: true, duration: 0.8 })
      return
    }
    const bounds = L.latLngBounds(points)
    map.flyToBounds(bounds, {
      padding: [40, 40],
      maxZoom: 6,
      animate: true,
      duration: 0.8,
    })
  }, [data.value])

  return (
    <div class="rounded-lg border border-border bg-surface-raised p-4">
      <div class="flex items-center justify-between mb-3">
        <span class="font-mono text-[10px] tracking-widest uppercase text-text-tertiary">
          Listeners worldwide
        </span>
        <span class="font-mono text-[10px] text-text-tertiary tabular-nums">
          {data.value.length
            ? `${totalListeners(data.value)} listener${totalListeners(data.value) === 1 ? '' : 's'} · ${cityCount(data.value)} ${cityCount(data.value) === 1 ? 'city' : 'cities'}`
            : 'no listeners yet'}
        </span>
      </div>
      <div
        ref={containerRef}
        class="h-72 w-full rounded-md border border-border/70 bg-surface-base overflow-hidden"
      />
      <div class="mt-2 font-mono text-[9px] text-text-tertiary">
        Tiles: CARTO / OpenStreetMap. GeoIP: db-ip.com / CC BY 4.0.
      </div>
    </div>
  )
}
