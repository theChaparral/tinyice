import { useEffect, useRef } from 'preact/hooks'
import maplibregl from 'maplibre-gl'
import 'maplibre-gl/dist/maplibre-gl.css'

// LiveGeoMap — MapLibre GL view of listener cities, fed by a parent
// component's geo data via props.
//
// Tiles: openfreemap.org / positron style. Open and free, no signup,
// no API key, no usage caps that affect a self-hosted dashboard. The
// previous Leaflet + CARTO setup had two unrelated problems we fix
// here:
//
//   1. CARTO's basemap policy is murky for production scale; OFM is
//      explicitly free for any use.
//
//   2. The auto-fit / marker-render logic ran on every SSE tick
//      (~500 ms), so when listeners came and went the camera
//      animated continuously. Each fitBounds is a 1 s animation;
//      ticks at 0.5 s stack on each other → the map never settles.
//      Markers were also clear-and-readded on every tick, causing
//      visible flicker.
//
// This component:
//
//   - Refits the camera ONLY when the SET of cities (signature of
//     iso/city/lat/lon tuples) changes. Listener-count changes
//     update marker sizes in place without touching the camera.
//
//   - Diffs markers — keeps an internal Map keyed by city signature.
//     Existing markers update their radius/tooltip; new ones get
//     created; removed ones get torn down. No clearLayers churn.
//
//   - Smart fit: zoom logic depends on city count and the spread of
//     points (one point → city-zoom; far-spread points → world view
//     instead of mid-ocean centre).

export type GeoCity = {
  iso: string
  country?: string
  city?: string
  lat: number
  lon: number
  listeners: number
  mounts?: Record<string, number>
}

type Props = {
  data: GeoCity[]
  // Tailwind classes for the outer container. Defaults to a fixed
  // 18 rem so cards look right inside a card grid; pass `flex-1` etc.
  // for kiosk-style fill-the-row layouts.
  className?: string
  // Optional override of the camera spread heuristic. Pass `false`
  // to force fitBounds even when cities are far-spread (kiosk wants
  // to see what's there; dashboard prefers a steady world view).
  worldFallback?: boolean
}

const OPENFREEMAP_STYLE = 'https://tiles.openfreemap.org/styles/positron'

// Marker radius (px). sqrt scaling so 100-listener cities aren't 100×
// the area of 1-listener cities. Floor at 6 px so a single listener
// stays clickable. Cap at 36 px so a viral spike doesn't paint half
// the screen.
function radiusFor(n: number): number {
  if (n <= 0) return 0
  return Math.max(6, Math.min(36, Math.round(6 + Math.sqrt(n) * 3)))
}

function citySignature(d: GeoCity[]): string {
  return d
    .filter((c) => c.lat !== 0 || c.lon !== 0)
    .map((c) => `${c.iso}|${c.city ?? ''}|${c.lat.toFixed(3)}|${c.lon.toFixed(3)}`)
    .sort()
    .join(';')
}

function cityKey(c: GeoCity): string {
  return `${c.iso}|${c.city ?? ''}|${c.lat.toFixed(3)}|${c.lon.toFixed(3)}`
}

type MarkerEntry = {
  marker: maplibregl.Marker
  popup: maplibregl.Popup
  el: HTMLDivElement
  lastListeners: number
}

function buildMarkerEl(listeners: number): HTMLDivElement {
  const el = document.createElement('div')
  el.className = 'tinyice-geo-marker'
  applyMarkerStyle(el, listeners)
  return el
}

function applyMarkerStyle(el: HTMLDivElement, listeners: number) {
  const r = radiusFor(listeners)
  const size = r * 2
  el.style.width = `${size}px`
  el.style.height = `${size}px`
  el.style.borderRadius = '50%'
  el.style.background = 'rgba(255, 138, 61, 0.55)'
  el.style.border = '1.5px solid #ff8a3d'
  el.style.boxShadow = '0 0 8px rgba(255, 138, 61, 0.4)'
  el.style.cursor = 'pointer'
  el.style.transition = 'width 200ms ease, height 200ms ease'
}

function popupHTML(c: GeoCity): string {
  const cityLine = c.city
    ? `<strong>${escapeHTML(c.city)}</strong>${c.country ? ` · ${escapeHTML(c.country)}` : ''}`
    : `<strong>${escapeHTML(c.country || c.iso)}</strong>`
  const mountsLine = c.mounts
    ? Object.entries(c.mounts)
        .map(([m, n]) => `${escapeHTML(m)}: ${n}`)
        .join('<br/>')
    : ''
  return (
    `${cityLine}<br/>${c.listeners} listener${c.listeners === 1 ? '' : 's'}` +
    (mountsLine ? `<br/><span style="opacity:.7">${mountsLine}</span>` : '')
  )
}

function escapeHTML(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => {
    switch (ch) {
      case '&':
        return '&amp;'
      case '<':
        return '&lt;'
      case '>':
        return '&gt;'
      case '"':
        return '&quot;'
      case "'":
        return '&#39;'
      default:
        return ch
    }
  })
}

export function LiveGeoMap({ data, className, worldFallback = true }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const mapRef = useRef<maplibregl.Map | null>(null)
  const markersRef = useRef<Map<string, MarkerEntry>>(new Map())
  const lastSignatureRef = useRef<string>('')

  // Init map once. Tear down on unmount.
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return

    const m = new maplibregl.Map({
      container: containerRef.current,
      style: OPENFREEMAP_STYLE,
      center: [0, 20],
      zoom: 1.5,
      minZoom: 1,
      maxZoom: 8,
      // Keep zoom controls minimal and out of the way of the
      // dashboard's own UI. Attribution is required by the data
      // licence; MapLibre adds the right one for OFM/OSM
      // automatically.
      attributionControl: { compact: true },
      // World-wraparound: smoother panning past the antimeridian.
      renderWorldCopies: true,
    })

    m.addControl(new maplibregl.NavigationControl({ showCompass: false }), 'top-right')

    // First-load resize: container may start at 0×0 if flexbox hasn't
    // settled. resize() once on next paint, then rely on
    // ResizeObserver for any later layout shifts (cards growing
    // around us, viewport rotation, kiosk reflows).
    requestAnimationFrame(() => m.resize())
    const ro = new ResizeObserver(() => m.resize())
    ro.observe(containerRef.current)

    mapRef.current = m
    return () => {
      ro.disconnect()
      // Each marker has a popup that holds DOM; remove them all so
      // we don't leak when the dashboard re-mounts the card.
      for (const e of markersRef.current.values()) {
        e.marker.remove()
      }
      markersRef.current.clear()
      m.remove()
      mapRef.current = null
    }
  }, [])

  // Marker diff + smart auto-fit. Runs every time `data` changes by
  // reference. The signature check below ensures we only re-camera
  // when the SET of cities changed; listener-count flips update
  // marker sizes in place without flying anywhere.
  useEffect(() => {
    const m = mapRef.current
    if (!m) return

    // Wait until the style has finished loading before we try to
    // place markers. MapLibre buffers addControl etc. but Marker
    // attachment expects the map's projection to be initialised.
    if (!m.isStyleLoaded()) {
      const onLoad = () => {
        m.off('load', onLoad)
        // re-trigger by writing to a local ref-tracked sentinel;
        // simplest: just call ourselves via a microtask. The effect
        // runs again when `data` changes anyway, but we also want
        // it to run once after the initial style load even if data
        // is already populated.
        renderMarkersAndFit(m, data, markersRef, lastSignatureRef, worldFallback)
      }
      m.on('load', onLoad)
      return
    }

    renderMarkersAndFit(m, data, markersRef, lastSignatureRef, worldFallback)
  }, [data, worldFallback])

  return (
    <div
      ref={containerRef}
      class={className ?? 'h-72 w-full rounded-md border border-border/70 bg-surface-base overflow-hidden'}
    />
  )
}

function renderMarkersAndFit(
  m: maplibregl.Map,
  data: GeoCity[],
  markersRef: { current: Map<string, MarkerEntry> },
  lastSignatureRef: { current: string },
  worldFallback: boolean,
) {
  // 1. Diff markers. Build a fresh keyed view of the incoming data
  //    (we pick the highest listener-count entry if duplicates show
  //    up — server should have aggregated already).
  const incoming = new Map<string, GeoCity>()
  for (const c of data) {
    if (c.lat === 0 && c.lon === 0) continue
    if (c.listeners <= 0) continue
    const k = cityKey(c)
    const prev = incoming.get(k)
    if (!prev || c.listeners > prev.listeners) incoming.set(k, c)
  }

  // 2. Remove markers for cities no longer present.
  for (const [k, e] of markersRef.current) {
    if (!incoming.has(k)) {
      e.marker.remove()
      markersRef.current.delete(k)
    }
  }

  // 3. Update existing or create new.
  for (const [k, c] of incoming) {
    const existing = markersRef.current.get(k)
    if (existing) {
      if (existing.lastListeners !== c.listeners) {
        applyMarkerStyle(existing.el, c.listeners)
        existing.lastListeners = c.listeners
      }
      existing.popup.setHTML(popupHTML(c))
      continue
    }
    const el = buildMarkerEl(c.listeners)
    const popup = new maplibregl.Popup({ offset: 12, closeButton: false }).setHTML(
      popupHTML(c),
    )
    const marker = new maplibregl.Marker({ element: el, anchor: 'center' })
      .setLngLat([c.lon, c.lat])
      .setPopup(popup)
      .addTo(m)
    el.addEventListener('mouseenter', () => marker.togglePopup())
    el.addEventListener('mouseleave', () => marker.togglePopup())
    markersRef.current.set(k, {
      marker,
      popup,
      el,
      lastListeners: c.listeners,
    })
  }

  // 4. Camera. Only refit when the SET of cities changed. Listener
  //    counts flipping doesn't justify another 1-second animation.
  const sig = citySignature(data)
  if (sig === lastSignatureRef.current) return
  lastSignatureRef.current = sig

  const points: [number, number][] = []
  for (const c of incoming.values()) points.push([c.lon, c.lat])

  if (points.length === 0) {
    m.flyTo({ center: [0, 20], zoom: 1.5, duration: 800 })
    return
  }
  if (points.length === 1) {
    m.flyTo({ center: points[0], zoom: 5, duration: 800 })
    return
  }

  // fitBounds against an LngLatBounds. MapLibre wants
  // [[minLng, minLat], [maxLng, maxLat]] for the bounds value.
  let minLng = Infinity,
    minLat = Infinity,
    maxLng = -Infinity,
    maxLat = -Infinity
  for (const [lng, lat] of points) {
    if (lng < minLng) minLng = lng
    if (lng > maxLng) maxLng = lng
    if (lat < minLat) minLat = lat
    if (lat > maxLat) maxLat = lat
  }
  const lngSpan = maxLng - minLng
  const latSpan = maxLat - minLat
  if (worldFallback && (lngSpan > 100 || latSpan > 60)) {
    // Worldwide spread — fitBounds would centre on a meaningless
    // mid-ocean point. Show the world instead.
    m.flyTo({ center: [0, 20], zoom: 1.5, duration: 800 })
    return
  }
  m.fitBounds(
    [
      [minLng, minLat],
      [maxLng, maxLat],
    ],
    {
      padding: 50,
      maxZoom: 6,
      duration: 800,
    },
  )
}
