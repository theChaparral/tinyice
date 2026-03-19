import { useRef, useCallback } from 'preact/hooks'

interface VolumeKnobProps {
  value: number // 0-100
  onChange: (value: number) => void
}

export function VolumeKnob({ value, onChange }: VolumeKnobProps) {
  const trackRef = useRef<HTMLDivElement>(null)

  const clamp = (v: number) => Math.min(100, Math.max(0, v))

  const handleClick = useCallback((e: MouseEvent) => {
    const track = trackRef.current
    if (!track) return
    const rect = track.getBoundingClientRect()
    const pct = ((e.clientX - rect.left) / rect.width) * 100
    onChange(clamp(pct))
  }, [onChange])

  const handleDrag = useCallback((e: MouseEvent) => {
    e.preventDefault()
    const track = trackRef.current
    if (!track) return

    const move = (ev: MouseEvent) => {
      const rect = track.getBoundingClientRect()
      const pct = ((ev.clientX - rect.left) / rect.width) * 100
      onChange(clamp(pct))
    }
    const up = () => {
      document.removeEventListener('mousemove', move)
      document.removeEventListener('mouseup', up)
    }
    document.addEventListener('mousemove', move)
    document.addEventListener('mouseup', up)
  }, [onChange])

  return (
    <div class="flex items-center gap-3 w-full max-w-[180px]">
      {/* Volume low icon */}
      <svg class="w-4 h-4 text-text-tertiary flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="11 5 6 9 2 9 2 15 6 15 11 19" />
      </svg>

      {/* Slider track */}
      <div
        ref={trackRef}
        onClick={handleClick}
        onMouseDown={handleDrag}
        class="relative flex-1 h-8 flex items-center cursor-pointer group"
        role="slider"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={value}
        aria-label="Volume"
        tabIndex={0}
      >
        {/* Track background */}
        <div class="absolute inset-x-0 h-1 rounded-full bg-[rgba(255,255,255,0.08)]">
          {/* Fill */}
          <div
            class="h-full rounded-full bg-accent transition-[width] duration-75"
            style={{ width: `${value}%` }}
          />
        </div>
        {/* Thumb */}
        <div
          class="absolute w-3.5 h-3.5 rounded-full bg-white shadow-[0_0_6px_rgba(0,0,0,0.4)] transition-[left] duration-75 group-hover:scale-110"
          style={{ left: `calc(${value}% - 7px)` }}
        />
      </div>

      {/* Volume high icon */}
      <svg class="w-4 h-4 text-text-tertiary flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="11 5 6 9 2 9 2 15 6 15 11 19" />
        <path d="M15.54 8.46a5 5 0 0 1 0 7.07" />
        <path d="M19.07 4.93a10 10 0 0 1 0 14.14" />
      </svg>
    </div>
  )
}
