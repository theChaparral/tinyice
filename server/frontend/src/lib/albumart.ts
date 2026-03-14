// Cache to avoid repeated lookups
const cache = new Map<string, string | null>()

/**
 * Fetch album art URL for a given artist + title.
 * Uses MusicBrainz search API (no key needed) -> Cover Art Archive.
 * Returns a URL string or null if not found.
 */
export async function fetchAlbumArt(artist: string, title: string): Promise<string | null> {
  if (!artist || !title) return null

  const key = `${artist}::${title}`.toLowerCase()
  if (cache.has(key)) return cache.get(key) ?? null

  try {
    // Search MusicBrainz for the recording
    const query = encodeURIComponent(`recording:"${title}" AND artist:"${artist}"`)
    const res = await fetch(
      `https://musicbrainz.org/ws/2/recording?query=${query}&limit=1&fmt=json`,
      { headers: { 'User-Agent': 'TinyIce/2.0 (https://github.com/DatanoiseTV/tinyice)' } }
    )

    if (!res.ok) { cache.set(key, null); return null }

    const data = await res.json()
    const recording = data.recordings?.[0]
    if (!recording?.releases?.[0]?.id) { cache.set(key, null); return null }

    const releaseId = recording.releases[0].id

    // Get cover art from Cover Art Archive
    const coverRes = await fetch(`https://coverartarchive.org/release/${releaseId}`)
    if (!coverRes.ok) { cache.set(key, null); return null }

    const coverData = await coverRes.json()
    const front = coverData.images?.find((img: any) => img.front)
    const url = front?.thumbnails?.small || front?.thumbnails?.['250'] || front?.image || null

    cache.set(key, url)
    return url
  } catch {
    cache.set(key, null)
    return null
  }
}
