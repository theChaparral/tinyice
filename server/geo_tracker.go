package server

import (
	"sort"
	"sync"

	"github.com/DatanoiseTV/tinyice/relay"
)

// GeoTracker keeps a live count of listeners per (country, mount).
// handleListener calls Add when a listener subscribes and Remove
// when the handler returns. /admin/geo reads Snapshot.
//
// We track by country only (not by city / lat-lon) because the
// free DB-IP country-lite database returns only ISO-3166 codes.
// Centroids in relay/geoip_centroids.go give the dashboard one
// dot per country at a fixed location, which is the right tradeoff
// for a free + key-less + no-tracking deployment.
type GeoTracker struct {
	mu     sync.Mutex
	geo    *relay.GeoLookup
	counts map[geoKey]int // (country, mount) -> count
}

type geoKey struct {
	Country string
	Mount   string
}

func NewGeoTracker(g *relay.GeoLookup) *GeoTracker {
	return &GeoTracker{
		geo:    g,
		counts: make(map[geoKey]int),
	}
}

// Add looks up `ip`'s country and increments its count for `mount`.
// Returns the country code so the handler can log it. Empty country
// (private / loopback / unresolved IP) is silently ignored.
func (t *GeoTracker) Add(ip, mount string) string {
	if t == nil || t.geo == nil {
		return ""
	}
	cc := t.geo.Lookup(ip)
	if cc == "" {
		return ""
	}
	t.mu.Lock()
	t.counts[geoKey{cc, mount}]++
	t.mu.Unlock()
	return cc
}

// Remove decrements the count for the listener that previously
// resolved to `country` on `mount`. country == "" is a no-op so
// callers can pass through whatever Add returned without branching.
func (t *GeoTracker) Remove(country, mount string) {
	if t == nil || country == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k := geoKey{country, mount}
	if t.counts[k] <= 1 {
		delete(t.counts, k)
		return
	}
	t.counts[k]--
}

// GeoCountry is one row of the /admin/geo response.
type GeoCountry struct {
	ISO       string  `json:"iso"`        // ISO-3166-1 alpha-2
	Name      string  `json:"name"`
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	Listeners int     `json:"listeners"`        // total across all mounts
	Mounts    map[string]int `json:"mounts,omitempty"` // per-mount split
}

// Snapshot returns a per-country aggregated view, sorted by total
// listeners DESC. mountFilter == "" includes all mounts; otherwise
// counts are restricted to the named mount.
func (t *GeoTracker) Snapshot(mountFilter string) []GeoCountry {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	// Aggregate to (country) -> totals + per-mount split. The
	// underlying counts map is small (one row per active country
	// per mount) so a copy is cheap.
	type acc struct {
		total  int
		mounts map[string]int
	}
	byCountry := make(map[string]*acc)
	for k, v := range t.counts {
		if mountFilter != "" && k.Mount != mountFilter {
			continue
		}
		a, ok := byCountry[k.Country]
		if !ok {
			a = &acc{mounts: map[string]int{}}
			byCountry[k.Country] = a
		}
		a.total += v
		a.mounts[k.Mount] += v
	}
	t.mu.Unlock()

	out := make([]GeoCountry, 0, len(byCountry))
	for cc, a := range byCountry {
		meta := relay.CountryCentroids()[cc]
		out = append(out, GeoCountry{
			ISO:       cc,
			Name:      meta.Name,
			Lat:       meta.Lat,
			Lon:       meta.Lon,
			Listeners: a.total,
			Mounts:    a.mounts,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Listeners != out[j].Listeners {
			return out[i].Listeners > out[j].Listeners
		}
		return out[i].ISO < out[j].ISO
	})
	return out
}
