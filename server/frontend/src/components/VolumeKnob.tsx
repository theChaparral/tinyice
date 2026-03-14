import { useRef, useCallback } from 'preact/hooks'

interface VolumeKnobProps {
  value: number // 0-100
  onChange: (value: number) => void
}

export function VolumeKnob({ value, onChange }: VolumeKnobProps) {
  const knobRef = useRef<HTMLDivElement>(null)
  const dragRef = useRef<{ startY: number; startValue: number } | null>(null)

  const clamp = (v: number) => Math.min(100, Math.max(0, v))

  // Rotation: -135deg (0%) to +135deg (100%)
  const rotation = -135 + (value / 100) * 270

  const handleMouseDown = useCallback((e: MouseEvent) => {
    e.preventDefault()
    dragRef.current = { startY: e.clientY, startValue: value }

    const handleMouseMove = (ev: MouseEvent) => {
      if (!dragRef.current) return
      const delta = dragRef.current.startY - ev.clientY
      const newValue = clamp(dragRef.current.startValue + delta * 0.5)
      onChange(newValue)
    }

    const handleMouseUp = () => {
      dragRef.current = null
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleMouseUp)
    }

    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleMouseUp)
  }, [value, onChange])

  const handleWheel = useCallback((e: WheelEvent) => {
    e.preventDefault()
    onChange(clamp(value + (e.deltaY < 0 ? 2 : -2)))
  }, [value, onChange])

  return (
    <div class="flex items-center gap-3">
      {/* Volume low icon */}
      <svg class="w-4 h-4 text-text-tertiary flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
        <path d="M18.5 12A4.5 4.5 0 0016 7.97v8.05c1.48-.73 2.5-2.25 2.5-3.02zM5 9v6h4l5 5V4L9 9H5z" />
      </svg>

      {/* Knob */}
      <div
        ref={knobRef}
        onMouseDown={handleMouseDown}
        onWheel={handleWheel}
        class="relative w-12 h-12 rounded-full cursor-grab active:cursor-grabbing select-none"
        role="slider"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={value}
        aria-label="Volume"
        tabIndex={0}
        style={{
          background: 'linear-gradient(145deg, oklch(0.25 0 0), oklch(0.12 0 0))',
          boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.06), 0 2px 8px rgba(0,0,0,0.4)',
        }}
      >
        {/* Indicator line */}
        <div
          class="absolute inset-0 flex justify-center"
          style={{ transform: `rotate(${rotation}deg)` }}
        >
          <div class="w-[2px] h-3 mt-1.5 rounded-full bg-accent" />
        </div>

        {/* Center dot */}
        <div class="absolute inset-0 flex items-center justify-center">
          <div class="w-1.5 h-1.5 rounded-full bg-surface-overlay" />
        </div>
      </div>

      {/* Volume high icon */}
      <svg class="w-4 h-4 text-text-tertiary flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
        <path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3A4.5 4.5 0 0014 7.97v8.05c1.48-.73 2.5-2.25 2.5-3.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z" />
      </svg>
    </div>
  )
}
