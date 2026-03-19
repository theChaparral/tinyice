import type { StreamInfo } from '@/types'
import { useAlbumArt } from '@/hooks/useAlbumArt'
import { EqBars } from './EqBars'

interface StreamCardProps {
  stream: StreamInfo
  onPlay?: () => void
}

export function StreamCard({ stream, onPlay }: StreamCardProps) {
  const albumArt = useAlbumArt(stream.artist, stream.title)

  return (
    <div class="group relative rounded-lg border border-border bg-surface-raised hover:border-accent/40 transition-colors overflow-hidden">
      {/* Top accent gradient when live */}
      {stream.live && (
        <div class="absolute top-0 inset-x-0 h-[2px] bg-gradient-to-r from-accent via-accent/60 to-transparent" />
      )}

      <div class="p-4 flex gap-3">
        {/* Album art thumbnail */}
        <div class="w-10 h-10 rounded bg-surface-base border border-border flex-shrink-0 flex items-center justify-center overflow-hidden">
          {albumArt ? (
            <img
              src={albumArt}
              alt="Album art"
              loading="lazy"
              class="w-full h-full object-cover"
            />
          ) : (
            <svg class="w-4 h-4 text-text-tertiary" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 3v10.55A4 4 0 1 0 14 17V7h4V3h-6z" />
            </svg>
          )}
        </div>

        <div class="flex flex-col gap-3 min-w-0 flex-1">
          {/* Header: mount + format badge */}
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              {stream.live && <EqBars bars={3} />}
              <span class="font-mono text-xs font-bold tracking-wider text-text-primary uppercase">
                {stream.mount}
              </span>
            </div>
            <span class="font-mono text-[10px] tracking-wider text-text-tertiary uppercase">
              {stream.format} {stream.bitrate}k
            </span>
          </div>

          {/* Now playing */}
          <div class="min-h-[2.5rem]">
            <p class="text-sm text-text-primary truncate">
              {stream.title || 'No track info'}
            </p>
            <p class="text-xs text-text-secondary truncate">
              {stream.artist || '\u00A0'}
            </p>
          </div>

          {/* Footer: listeners + play */}
          <div class="flex items-center justify-between">
            <span class="font-mono text-xs text-text-tertiary">
              {stream.listeners} {stream.listeners === 1 ? 'listener' : 'listeners'}
            </span>
            <button
              onClick={onPlay}
              class="h-8 w-8 rounded-full bg-accent flex items-center justify-center hover:bg-accent/90 transition-colors"
              aria-label={`Play ${stream.mount}`}
            >
              <svg class="w-3.5 h-3.5 text-surface-base ml-0.5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M8 5v14l11-7z" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
