import { useRef, useEffect } from 'preact/hooks'
import { createVisualizer } from '@/lib/visualizer'

export function Visualizer({ size = 260, getFreqData }: { size?: number; getFreqData: () => Uint8Array | null }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const viz = createVisualizer(canvas, getFreqData)
    viz.setSize(size, size)
    return () => viz.destroy()
  }, [size])

  return (
    <div class="relative" style={{ width: size, height: size }}>
      <canvas ref={canvasRef} style={{ width: size, height: size }} />
      {/* Vinyl center */}
      <div
        class="absolute rounded-full bg-surface-raised border border-border flex flex-col items-center justify-center"
        style={{ inset: `${size * 0.22}px` }}
      >
        {/* Groove lines */}
        <div class="absolute rounded-full border border-[rgba(255,255,255,0.02)]" style={{ inset: '8px' }} />
        <div class="absolute rounded-full border border-[rgba(255,255,255,0.015)]" style={{ inset: '16px' }} />
        <div class="absolute rounded-full border border-[rgba(255,255,255,0.02)]" style={{ inset: '24px' }} />
        {/* Center dot + label */}
        <div class="w-2 h-2 rounded-full bg-[rgba(255,255,255,0.06)] mb-1.5" />
        <span class="font-mono text-[7px] text-text-tertiary tracking-[1px]">TINYICE</span>
      </div>
    </div>
  )
}
