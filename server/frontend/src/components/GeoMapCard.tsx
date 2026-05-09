import { useEffect } from 'preact/hooks'
import { signal } from '@preact/signals'
import { createSSE } from '../lib/sse'
import { LiveGeoMap, type GeoCity } from './LiveGeoMap'

// GeoMapCard — live listener map for the admin dashboard.
//
// Geo data: city + lat/lon from DB-IP city-lite (CC BY 4.0, no key,
// no signup). Resolved per listener at connect time, aggregated on
// the server by (country, city) so co-located listeners collapse
// into one bigger bubble. Updates piggyback on the dashboard's
// `/admin/events` SSE stream so the map ticks live without a
// separate poll loop.
//
// Rendering lives in <LiveGeoMap> — a MapLibre GL component
// pointing at openfreemap.org tiles. The previous Leaflet + CARTO
// implementation re-flew the camera and clear-and-readded markers
// on every SSE tick, producing a constantly-animating, flickering
// view. The new component diffs markers in place and only refits
// when the SET of cities changes.

const data = signal<GeoCity[]>([])

function totalListeners(d: GeoCity[]): number {
  return d.reduce((acc, c) => acc + c.listeners, 0)
}

function cityCount(d: GeoCity[]): number {
  return d.filter((c) => c.lat !== 0 || c.lon !== 0).length
}

export function GeoMapCard() {
  // Subscribe to the dashboard SSE stream once. Unsubscribe on
  // unmount. The SSE connection is shared with other dashboard cards
  // via the createSSE singleton; we just listen for the geo event.
  useEffect(() => {
    const sse = createSSE('/admin/events')
    const off = sse.on('geo', (payload: GeoCity[]) => {
      data.value = Array.isArray(payload) ? payload : []
    })
    return () => {
      off()
      sse.close()
    }
  }, [])

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
      <LiveGeoMap data={data.value} />
      <div class="mt-2 font-mono text-[9px] text-text-tertiary">
        Tiles: <a href="https://openfreemap.org/" class="underline">OpenFreeMap</a> · ©{' '}
        <a href="https://www.openstreetmap.org/copyright" class="underline">OpenStreetMap</a>{' '}
        contributors. GeoIP: <a href="https://db-ip.com/" class="underline">DB-IP</a> CC-BY-4.0.
      </div>
    </div>
  )
}
