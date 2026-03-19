interface TransportControlsProps {
  playing: boolean
  shuffleActive?: boolean
  repeatActive?: boolean
  onPlay?: () => void
  onPause?: () => void
  onNext?: () => void
  onPrev?: () => void
  onShuffle?: () => void
  onRepeat?: () => void
}

export function TransportControls({
  playing,
  shuffleActive = false,
  repeatActive = false,
  onPlay,
  onPause,
  onNext,
  onPrev,
  onShuffle,
  onRepeat,
}: TransportControlsProps) {
  return (
    <div class="flex items-center gap-4">
      {/* Shuffle */}
      <button
        onClick={onShuffle}
        class={`w-9 h-9 rounded-full flex items-center justify-center transition-colors ${
          shuffleActive ? 'text-accent' : 'text-text-tertiary hover:text-text-secondary'
        }`}
        aria-label="Shuffle"
      >
        <svg class="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="currentColor">
          <path d="M10.59 9.17L5.41 4 4 5.41l5.17 5.17 1.42-1.41zM14.5 4l2.04 2.04L4 18.59 5.41 20 17.96 7.46 20 9.5V4h-5.5zm.33 9.41l-1.41 1.41 3.13 3.13L14.5 20H20v-5.5l-2.04 2.04-3.13-3.13z" />
        </svg>
      </button>

      {/* Prev */}
      <button
        onClick={onPrev}
        class="w-9 h-9 rounded-full flex items-center justify-center text-text-secondary hover:text-text-primary transition-colors"
        aria-label="Previous"
      >
        <svg class="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="currentColor">
          <path d="M6 6h2v12H6zm3.5 6l8.5 6V6z" />
        </svg>
      </button>

      {/* Play / Pause — large orange */}
      <button
        onClick={playing ? onPause : onPlay}
        class="w-14 h-14 rounded-full bg-accent flex items-center justify-center shadow-[0_0_20px_rgba(255,102,0,0.3)] hover:shadow-[0_0_28px_rgba(255,102,0,0.45)] transition-shadow"
        aria-label={playing ? 'Pause' : 'Play'}
      >
        {playing ? (
          <svg class="w-6 h-6 text-surface-base" viewBox="0 0 24 24" fill="currentColor">
            <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
          </svg>
        ) : (
          <svg class="w-6 h-6 text-surface-base ml-0.5" viewBox="0 0 24 24" fill="currentColor">
            <path d="M8 5v14l11-7z" />
          </svg>
        )}
      </button>

      {/* Next */}
      <button
        onClick={onNext}
        class="w-9 h-9 rounded-full flex items-center justify-center text-text-secondary hover:text-text-primary transition-colors"
        aria-label="Next"
      >
        <svg class="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="currentColor">
          <path d="M6 18l8.5-6L6 6v12zm2-8.14L11.03 12 8 14.14V9.86zM16 6h2v12h-2z" />
        </svg>
      </button>

      {/* Repeat */}
      <button
        onClick={onRepeat}
        class={`w-9 h-9 rounded-full flex items-center justify-center transition-colors ${
          repeatActive ? 'text-accent' : 'text-text-tertiary hover:text-text-secondary'
        }`}
        aria-label="Repeat"
      >
        <svg class="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="currentColor">
          <path d="M7 7h10v3l4-4-4-4v3H5v6h2V7zm10 10H7v-3l-4 4 4 4v-3h12v-6h-2v4z" />
        </svg>
      </button>
    </div>
  )
}
