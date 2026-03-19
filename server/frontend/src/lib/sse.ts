import type { StatsEvent, StreamEvent, AutoDJEvent, StreamInfo } from '../types'

type SSEEventMap = {
  stats: StatsEvent
  stream: StreamEvent
  autodj: AutoDJEvent
  streams: StreamInfo[]
  metadata: { mount: string; title: string; artist: string }
}

type SSECallback<K extends keyof SSEEventMap> = (data: SSEEventMap[K]) => void

export function createSSE(url: string) {
  let source: EventSource | null = null
  const listeners = new Map<string, Set<Function>>()
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let reconnectDelay = 1000

  function connect() {
    source = new EventSource(url)
    source.onopen = () => { reconnectDelay = 1000 }
    source.onerror = () => {
      source?.close()
      reconnectTimer = setTimeout(connect, reconnectDelay)
      reconnectDelay = Math.min(reconnectDelay * 2, 30000)
    }
    // Legacy untyped messages
    source.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        listeners.get('message')?.forEach(cb => cb(data))
      } catch {}
    }
    // Register typed listeners on new source
    for (const [type, cbs] of listeners) {
      if (type === 'message') continue
      source.addEventListener(type, (e: Event) => {
        try {
          const data = JSON.parse((e as MessageEvent).data)
          cbs.forEach(cb => cb(data))
        } catch {}
      })
    }
  }

  function on<K extends keyof SSEEventMap>(event: K, callback: SSECallback<K>): () => void
  function on(event: 'message', callback: (data: unknown) => void): () => void
  function on(event: string, callback: Function): () => void {
    if (!listeners.has(event)) listeners.set(event, new Set())
    listeners.get(event)!.add(callback)
    if (source && event !== 'message') {
      source.addEventListener(event, (e: Event) => {
        try { callback(JSON.parse((e as MessageEvent).data)) } catch {}
      })
    }
    return () => { listeners.get(event)?.delete(callback) }
  }

  function close() {
    source?.close()
    if (reconnectTimer) clearTimeout(reconnectTimer)
  }

  connect()
  return { on, close }
}
