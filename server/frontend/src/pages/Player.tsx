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

// hlsRef holds the live hls.js instance so handlePause and unmount can tear
// it down. Import is dynamic (see attachHLS) so audio-only pages don't
// download the hls.js bundle at all.
type HlsLike = {
  loadSource(url: string): void
  attachMedia(el: HTMLMediaElement): void
  destroy(): void
}

async function attachHLS(url: string, el: HTMLMediaElement): Promise<HlsLike | null> {
  // Safari / iOS / tvOS / Android Chrome handle HLS natively — feed the
  // playlist URL straight into the element and skip the 120 KB bundle.
  if (el.canPlayType('application/vnd.apple.mpegurl')) {
    el.src = url
    return null
  }
  const { default: Hls } = await import('hls.js')
  if (!Hls.isSupported()) {
    // Nothing we can do — neither native HLS nor MSE support.
    el.src = url
    return null
  }
  const hls = new Hls({ enableWorker: true, lowLatencyMode: true })
  hls.loadSource(url)
  hls.attachMedia(el)
  return hls as unknown as HlsLike
}

export function Player() {
  const audioRef = useRef<HTMLAudioElement>(null)
  const analyserRef = useRef<AnalyserNode | null>(null)
  const hlsRef = useRef<HlsLike | null>(null)
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

  const handlePlay = useCallback(async () => {
    const el = audioRef.current
    if (!el) return
    resumeAudio()
    if (!analyserRef.current) {
      analyserRef.current = connectAudio(el)
    }
    // When the mount advertises a video track we play the HLS playlist —
    // the segments muxed by the server interleave audio and video, so a
    // single <video> element covers both. Safari/iOS play HLS natively;
    // on Firefox/Chromium attachHLS dynamically loads hls.js and drives
    // the element via Media Source Extensions. Audio-only mounts keep
    // using the raw Icecast stream URL.
    const mountPath = data.mount!.startsWith('/') ? data.mount! : `/${data.mount}`
    if (data.hasVideo) {
      hlsRef.current = await attachHLS(`${mountPath}/playlist.m3u8`, el)
    } else {
      el.src = mountPath
    }
    try {
      await el.play()
    } catch (err) {
      // Autoplay / gesture failure is expected on first click in some
      // environments; leave the user to press again. Propagate anything
      // unexpected to the console for debugging.
      // eslint-disable-next-line no-console
      console.warn('play() failed:', err)
    }
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

  // Tear down the hls.js instance on unmount so we don't leak MediaSource
  // workers or keep fetching segments for a closed page.
  useEffect(() => {
    return () => {
      if (hlsRef.current) {
        hlsRef.current.destroy()
        hlsRef.current = null
      }
    }
  }, [])

  const handleModeChange = useCallback((m: 'http' | 'webrtc') => {
    mode.value = m
  }, [])

  const handleVolumeChange = useCallback((v: number) => {
    volume.value = v
  }, [])

  // Video-first layout: the stream's video element is the hero. The audio
  // vinyl visualizer + mode toggle are hidden because the video already
  // carries the audio track. Keeps just the essentials: title / artist,
  // play+pause overlay, volume, and the standard bottom-strip metadata.
  if (data.hasVideo) {
    return (
      <div class="min-h-screen bg-surface-base relative overflow-hidden flex flex-col">
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

        {/* Video surface, 16:9 locked, centred */}
        <main class="flex-1 flex items-center justify-center px-4 pt-16 pb-24">
          <div class="relative w-full max-w-[min(92vw,calc(82vh*16/9))] aspect-video">
            <video
              ref={audioRef as any}
              crossOrigin="anonymous"
              preload="none"
              playsInline
              controls
              class="absolute inset-0 w-full h-full rounded-xl bg-black shadow-2xl"
            />
            {!playing.value && (
              <button
                onClick={handlePlay}
                class="absolute inset-0 flex items-center justify-center group"
                aria-label="Play"
              >
                <span class="w-20 h-20 rounded-full bg-accent/90 flex items-center justify-center shadow-[0_0_32px_rgba(255,102,0,0.45)] group-hover:scale-105 transition-transform">
                  <svg class="w-10 h-10 text-surface-base ml-1" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M8 5v14l11-7z" />
                  </svg>
                </span>
              </button>
            )}
          </div>
        </main>

        {/* Title + volume tray */}
        <div class="fixed bottom-0 inset-x-0 z-20 border-t border-border bg-surface-base/90 backdrop-blur">
          <div class="mx-auto max-w-7xl px-4 py-3 flex flex-wrap items-center gap-x-6 gap-y-2">
            <div class="min-w-0 flex-1">
              <div class="text-sm font-bold text-text-primary truncate">{title}</div>
              <div class="font-mono text-[11px] text-text-tertiary truncate">{artist}</div>
            </div>
            <div class="flex items-center gap-4">
              <span class="font-mono text-[9px] tracking-widest text-text-tertiary/60 uppercase hidden sm:inline">
                {data.mount}
              </span>
              <span class="font-mono text-[9px] tracking-widest text-text-tertiary/60 uppercase">
                {listeners} {listeners.value === 1 ? 'listener' : 'listeners'}
              </span>
              <VolumeKnob value={volume.value} onChange={handleVolumeChange} />
            </div>
          </div>
        </div>
      </div>
    )
  }

  // Audio-only layout — unchanged vinyl visualizer design.
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
