import { useState, useEffect } from 'preact/hooks'
import { fetchAlbumArt } from '../lib/albumart'

export function useAlbumArt(artist: string, title: string): string | null {
  const [url, setUrl] = useState<string | null>(null)

  useEffect(() => {
    setUrl(null)
    if (!artist || !title) return

    let cancelled = false
    fetchAlbumArt(artist, title).then(result => {
      if (!cancelled) setUrl(result)
    })

    return () => { cancelled = true }
  }, [artist, title])

  return url
}
