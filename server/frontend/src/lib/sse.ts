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
  // attached tracks which SSE event types we've already called
  // addEventListener for on the CURRENT EventSource. Reset on reconnect so
  // we re-attach exactly one dispatcher per event type on the new source.
  // Without this, on(...) would add a listener directly every call while
  // connect() also re-attached on every reconnect, making each subsequent
  // reconnect multiply callback invocations.
  let attached = new Set<string>()
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let reconnectDelay = 1000
  let closed = false

  function dispatch(event: string, data: unknown) {
    listeners.get(event)?.forEach((cb) => {
      try { (cb as (d: unknown) => void)(data) } catch (e) { /* swallow per-listener errors */ void e }
    })
  }

  function attachDispatcher(s: EventSource, event: string) {
    if (attached.has(event)) return
    s.addEventListener(event, (e: Event) => {
      try { dispatch(event, JSON.parse((e as MessageEvent).data)) } catch {}
    })
    attached.add(event)
  }

  function connect() {
    if (closed) return
    source = new EventSource(url)
    attached = new Set()
    source.onopen = () => { reconnectDelay = 1000 }
    source.onerror = () => {
      source?.close()
      source = null
      attached = new Set()
      if (closed) return
      reconnectTimer = setTimeout(connect, reconnectDelay)
      reconnectDelay = Math.min(reconnectDelay * 2, 30000)
    }
    // Legacy untyped messages
    source.onmessage = (e) => {
      try { dispatch('message', JSON.parse(e.data)) } catch {}
    }
    // Register exactly one dispatcher per currently-known event type.
    for (const type of listeners.keys()) {
      if (type === 'message') continue
      attachDispatcher(source, type)
    }
  }

  function on<K extends keyof SSEEventMap>(event: K, callback: SSECallback<K>): () => void
  function on(event: 'message', callback: (data: unknown) => void): () => void
  function on(event: string, callback: Function): () => void {
    if (!listeners.has(event)) listeners.set(event, new Set())
    listeners.get(event)!.add(callback)
    if (source && event !== 'message') {
      attachDispatcher(source, event)
    }
    return () => { listeners.get(event)?.delete(callback) }
  }

  function close() {
    closed = true
    source?.close()
    source = null
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
  }

  connect()
  return { on, close }
}
