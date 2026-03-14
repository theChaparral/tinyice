import { useEffect, useRef, useCallback } from 'preact/hooks'
import { signal } from '@preact/signals'
import { Visualizer } from '@/components/Visualizer'
import { TransportControls } from '@/components/TransportControls'
import { ModeToggle } from '@/components/ModeToggle'
import { VolumeKnob } from '@/components/VolumeKnob'
import { createSSE } from '@/lib/sse'
import { connectAudio, getFrequencyData, resumeAudio } from '@/lib/audio'
import type { PlayerData } from '@/types'

const data = (window.__TINYICE__ ?? {}) as Partial<PlayerData>

const playing = signal(false)
const title = signal(data.title || 'Untitled')
const artist = signal(data.artist || 'Unknown Artist')
const mode = signal<'http' | 'webrtc'>('http')
const volume = signal(80)
const listeners = signal(data.listeners || 0)

export function Player() {
  const audioRef = useRef<HTMLAudioElement>(null)
  const analyserRef = useRef<AnalyserNode | null>(null)

  const getFreqData = useCallback(() => {
    if (!analyserRef.current) return null
    return getFrequencyData(analyserRef.current)
  }, [])

  useEffect(() => {
    const sse = createSSE('/events')

    sse.on('metadata', (evt) => {
      if (evt.mount === data.mount) {
        title.value = evt.title
        artist.value = evt.artist
      }
    })

    sse.on('stream', (evt) => {
      if (evt.mount === data.mount) {
        listeners.value = evt.listeners
      }
    })

    return () => sse.close()
  }, [])

  useEffect(() => {
    const el = audioRef.current
    if (!el) return
    el.volume = volume.value / 100
  }, [volume.value])

  const handlePlay = useCallback(() => {
    const el = audioRef.current
    if (!el) return
    resumeAudio()
    if (!analyserRef.current) {
      analyserRef.current = connectAudio(el)
    }
    el.src = `/${data.mount}`
    el.play()
    playing.value = true
  }, [])

  const handlePause = useCallback(() => {
    const el = audioRef.current
    if (!el) return
    el.pause()
    el.src = ''
    playing.value = false
  }, [])

  const handleModeChange = useCallback((m: 'http' | 'webrtc') => {
    mode.value = m
  }, [])

  const handleVolumeChange = useCallback((v: number) => {
    volume.value = v
  }, [])

  return (
    <div class="min-h-screen bg-surface-base relative overflow-hidden flex flex-col items-center justify-center">
      {/* Dot grid texture */}
      <div
        class="fixed inset-0 pointer-events-none z-0"
        style={{
          backgroundImage: 'radial-gradient(rgba(255,255,255,0.03) 1px, transparent 1px)',
          backgroundSize: '20px 20px',
        }}
      />

      {/* Ambient orange glow behind visualizer */}
      <div
        class="fixed pointer-events-none z-0"
        style={{
          width: '600px',
          height: '600px',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -60%)',
          background: 'radial-gradient(ellipse, rgba(255,102,0,0.08) 0%, transparent 70%)',
        }}
      />

      {/* Hidden audio element */}
      <audio ref={audioRef} crossOrigin="anonymous" preload="none" />

      {/* Mini nav top-left */}
      <div class="fixed top-0 left-0 z-20 flex items-center gap-3 px-5 py-4">
        <a href="/" class="font-heading text-sm font-bold text-text-primary tracking-tight">
          Ti
        </a>
        <div class="flex items-center gap-1.5">
          <span
            class="w-1.5 h-1.5 rounded-full bg-live"
            style={{ animation: 'pulse-glow 2s ease-in-out infinite' }}
          />
          <span class="font-mono text-[9px] tracking-widest text-live uppercase">LIVE</span>
        </div>
      </div>

      {/* Main content */}
      <main class="relative z-10 flex flex-col items-center gap-8">
        {/* Visualizer */}
        <Visualizer size={260} getFreqData={getFreqData} />

        {/* Track info */}
        <div class="flex flex-col items-center gap-1.5 max-w-xs text-center">
          <h1 class="text-[22px] font-bold text-text-primary leading-tight truncate w-full">
            {title}
          </h1>
          <p class="font-mono text-xs text-text-tertiary truncate w-full">
            {artist}
          </p>
        </div>

        {/* Transport controls */}
        <TransportControls
          playing={playing.value}
          onPlay={handlePlay}
          onPause={handlePause}
        />

        {/* Mode toggle */}
        {data.hasWebRTC && (
          <ModeToggle mode={mode.value} onChange={handleModeChange} />
        )}

        {/* Volume */}
        <VolumeKnob value={volume.value} onChange={handleVolumeChange} />
      </main>

      {/* Bottom strip */}
      <div class="fixed bottom-0 inset-x-0 z-20 border-t border-border">
        <div class="mx-auto max-w-7xl px-4 py-3 flex items-center justify-center gap-8">
          <span class="font-mono text-[9px] tracking-widest text-text-tertiary/50 uppercase">
            /{data.mount}
          </span>
          <span class="font-mono text-[9px] tracking-widest text-text-tertiary/50 uppercase">
            {data.bitrate}kbps {data.format}
          </span>
          <span class="font-mono text-[9px] tracking-widest text-text-tertiary/50 uppercase">
            {listeners} {listeners.value === 1 ? 'listener' : 'listeners'}
          </span>
        </div>
      </div>
    </div>
  )
}
