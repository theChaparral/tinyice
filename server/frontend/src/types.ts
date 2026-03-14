// Data injected by Go server into window.__TINYICE__
export interface TinyIceBase {
  csrfToken: string
  version: string
  pageTitle: string
  pageSubtitle: string
  branding: {
    logoUrl: string | null
    accentColor: string
    landingMarkdown: string
  }
}

export interface PlayerData extends TinyIceBase {
  mount: string
  title: string
  artist: string
  format: 'mp3' | 'opus'
  bitrate: number
  listeners: number
  hasWebRTC: boolean
}

export interface AdminData extends TinyIceBase {
  user: { username: string; role: 'superadmin' | 'admin' }
  mounts: string[]
}

export interface LandingData extends TinyIceBase {
  streams: StreamInfo[]
}

export interface StreamInfo {
  mount: string
  title: string
  artist: string
  format: string
  bitrate: number
  listeners: number
  live: boolean
}

// SSE Events
export interface StatsEvent {
  listeners: number
  streams: number
  bandwidth: number
  uptime: number
  goroutines: number
  memory: number
  gc: number
}

export interface StreamEvent {
  mount: string
  title: string
  artist: string
  format: string
  bitrate: number
  listeners: number
  health: number
}

export interface AutoDJEvent {
  mount: string
  state: 'playing' | 'paused' | 'stopped'
  currentTrack: { title: string; artist: string; file: string }
  position: number
  duration: number
  queue: string[]
}

// API types
export interface PlaylistItem {
  id: string
  file: string
  title: string
  artist: string
  duration: number
}

export interface FileInfo {
  name: string
  path: string
  isDir: boolean
  title?: string
  artist?: string
  duration?: number
  bitrate?: number
}

declare global {
  interface Window {
    __TINYICE__: TinyIceBase | PlayerData | AdminData | LandingData
  }
}
