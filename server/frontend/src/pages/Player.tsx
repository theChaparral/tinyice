import { useEffect, useRef, useCallback } from 'preact/hooks'
import { signal } from '@preact/signals'
import { Visualizer } from '@/components/Visualizer'
import { ModeToggle } from '@/components/ModeToggle'
import { VolumeKnob } from '@/components/VolumeKnob'
import { createSSE } from '@/lib/sse'
import { connectAudio, getFrequencyData, resumeAudio } from '@/lib/audio'
import { useAlbumArt } from '@/hooks/useAlbumArt'
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
  const albumArt = useAlbumArt(artist.value, title.value)

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
    // When the mount advertises a video track we play the HLS playlist —
    // the segments muxed by the server interleave audio and video, so a
    // single <video> element covers both. Browsers that don't play HLS
    // natively (non-Safari) will need hls.js, but Safari + many TVs
    // handle it out of the box. Audio-only mounts keep using the raw
    // Icecast stream URL.
    const mountPath = data.mount.startsWith('/') ? data.mount : `/${data.mount}`
    if (data.hasVideo) {
      el.src = `${mountPath}/playlist.m3u8`
    } else {
      el.src = mountPath
    }
    el.play()
    playing.value = true
  }, [])

  const handlePause = useCallback(() => {
    const el = audioRef.current
    if (!el) return
    el.pause()
    // Previously we cleared src to ''; some browsers warn on that. Leave
    // the src in place so resume is instant and no console noise fires.
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

      {/* Audio / video element — hidden for audio-only mounts, shown for
          A/V mounts so the viewer sees the stream. The underlying element
          is a <video> either way because HTMLVideoElement is a
          superset of HTMLAudioElement; playAudio analyser attaches fine
          to it. */}
      {data.hasVideo ? (
        <video
          ref={audioRef as any}
          crossOrigin="anonymous"
          preload="none"
          playsInline
          controls
          class="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-10 max-w-[80vw] max-h-[70vh] rounded-xl bg-black shadow-2xl"
        />
      ) : (
        <audio ref={audioRef} crossOrigin="anonymous" preload="none" />
      )}

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
        <Visualizer size={260} getFreqData={getFreqData} albumArt={albumArt} />

        {/* Track info */}
        <div class="flex flex-col items-center gap-1.5 max-w-xs text-center">
          <h1 class="text-[22px] font-bold text-text-primary leading-tight truncate w-full">
            {title}
          </h1>
          <p class="font-mono text-xs text-text-tertiary truncate w-full">
            {artist}
          </p>
        </div>

        {/* Play / Pause — radio only needs this */}
        <button
          onClick={playing.value ? handlePause : handlePlay}
          class="w-14 h-14 rounded-full bg-accent flex items-center justify-center shadow-[0_0_20px_rgba(255,102,0,0.3)] hover:shadow-[0_0_28px_rgba(255,102,0,0.45)] transition-shadow"
          aria-label={playing.value ? 'Pause' : 'Play'}
        >
          {playing.value ? (
            <svg class="w-6 h-6 text-surface-base" viewBox="0 0 24 24" fill="currentColor">
              <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
            </svg>
          ) : (
            <svg class="w-6 h-6 text-surface-base ml-0.5" viewBox="0 0 24 24" fill="currentColor">
              <path d="M8 5v14l11-7z" />
            </svg>
          )}
        </button>

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
            {data.mount}
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
