import { useState, useEffect } from 'preact/hooks'
import { Nav } from '@/components/Nav'
import { CodeBlock } from '@/components/CodeBlock'
import type { TinyIceBase } from '@/types'

const data = window.__TINYICE__ as TinyIceBase

const sections = [
  { id: 'getting-started', label: 'Getting Started', children: [
    { id: 'quick-start', label: 'Quick Start' },
    { id: 'installation', label: 'Installation' },
  ]},
  { id: 'streaming', label: 'Streaming', children: [
    { id: 'webrtc-source', label: 'WebRTC Source' },
    { id: 'http-listening', label: 'HTTP Listening' },
    { id: 'webrtc-playback', label: 'WebRTC Playback' },
    { id: 'metadata-sse', label: 'Metadata SSE' },
  ]},
  { id: 'reference', label: 'Reference', children: [
    { id: 'rest-api', label: 'REST API' },
    { id: 'embed-widget', label: 'Embed Widget' },
    { id: 'icecast-compat', label: 'Icecast Compat' },
  ]},
]

const endpoints = [
  { method: 'POST', path: '/webrtc/source-offer', desc: 'Start WebRTC source stream' },
  { method: 'GET', path: '/{mount}', desc: 'Listen to audio stream (HTTP)' },
  { method: 'GET', path: '/events', desc: 'Real-time metadata (SSE)' },
  { method: 'GET', path: '/api/stats', desc: 'Server statistics' },
  { method: 'GET', path: '/explore', desc: 'Stream discovery page' },
]

function methodColor(m: string) {
  return m === 'POST' ? 'bg-green-500/15 text-green-400 border-green-500/20' : 'bg-blue-500/15 text-blue-400 border-blue-500/20'
}

export function Developers() {
  const [activeSection, setActiveSection] = useState('quick-start')

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id)
          }
        }
      },
      { rootMargin: '-80px 0px -60% 0px', threshold: 0 }
    )

    const allIds = sections.flatMap(s => [s.id, ...s.children.map(c => c.id)])
    for (const id of allIds) {
      const el = document.getElementById(id)
      if (el) observer.observe(el)
    }

    return () => observer.disconnect()
  }, [])

  const scrollTo = (id: string) => {
    const el = document.getElementById(id)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }

  return (
    <div class="min-h-screen bg-surface-base">
      <Nav branding={data.branding} />

      <div class="flex pt-14">
        {/* Sidebar */}
        <aside class="fixed top-14 left-0 bottom-0 w-[210px] border-r border-border overflow-y-auto px-5 py-6">
          <div class="flex items-center gap-2 mb-6">
            <svg class="w-4 h-4 text-accent" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="16 18 22 12 16 6" />
              <polyline points="8 6 2 12 8 18" />
            </svg>
            <span class="font-mono text-[11px] tracking-widest text-accent font-bold">DEVELOPERS</span>
          </div>

          {sections.map((section) => (
            <div key={section.id} class="mb-5">
              <div class="font-mono text-[9px] tracking-widest text-text-tertiary uppercase mb-2 px-3">
                {section.label}
              </div>
              {section.children.map((child) => (
                <button
                  key={child.id}
                  onClick={() => scrollTo(child.id)}
                  class={`w-full text-left px-3 py-1.5 font-mono text-[11px] tracking-wide transition-colors rounded-r-md border-l-2 ${
                    activeSection === child.id
                      ? 'border-accent text-text-primary bg-accent-subtle'
                      : 'border-transparent text-text-tertiary hover:text-text-secondary hover:border-border-hover'
                  }`}
                >
                  {child.label}
                </button>
              ))}
            </div>
          ))}
        </aside>

        {/* Content */}
        <main class="flex-1 ml-[210px] min-w-0">
          <div class="max-w-3xl mx-auto px-8 py-10 space-y-16">

            {/* Quick Start */}
            <section id="quick-start">
              <h1 class="font-heading text-2xl font-bold text-text-primary mb-2">Quick Start</h1>
              <p class="text-text-secondary text-sm leading-relaxed mb-6">
                Get streaming audio in under a minute. TinyIce uses WebRTC for ultra-low-latency source connections
                and standard HTTP for listener playback.
              </p>

              <CodeBlock tabs={[{
                label: 'TypeScript',
                language: 'typescript',
                code: `// Capture microphone audio
const stream = await navigator.mediaDevices
  .getUserMedia({ audio: true })

// Create WebRTC peer connection
const pc = new RTCPeerConnection()
stream.getTracks().forEach(t => pc.addTrack(t, stream))

// Signal to TinyIce server
const offer = await pc.createOffer()
await pc.setLocalDescription(offer)

const res = await fetch('/webrtc/source-offer?mount=/live', {
  method: 'POST',
  body: JSON.stringify(offer),
})
const answer = await res.json()
await pc.setRemoteDescription(answer)
// You're now streaming!`,
              }]} />

              {/* Flow cards */}
              <div class="flex items-center justify-center gap-3 mt-8">
                {[
                  { num: '01', label: 'Connect' },
                  { num: '02', label: 'Stream' },
                  { num: '03', label: 'Listen' },
                ].map((step, i) => (
                  <>
                    <div key={step.num} class="flex-1 rounded-lg border border-border bg-surface-raised p-4 text-center">
                      <div class="font-mono text-[10px] tracking-widest text-accent mb-1">{step.num}</div>
                      <div class="font-heading text-sm font-semibold text-text-primary">{step.label}</div>
                    </div>
                    {i < 2 && (
                      <svg class="w-4 h-4 text-text-tertiary flex-none" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M5 12h14M12 5l7 7-7 7" />
                      </svg>
                    )}
                  </>
                ))}
              </div>
            </section>

            {/* Installation */}
            <section id="installation">
              <h2 class="font-heading text-xl font-bold text-text-primary mb-2">Installation</h2>
              <p class="text-text-secondary text-sm leading-relaxed mb-6">
                TinyIce is a single binary with zero dependencies. Download the latest release or build from source.
              </p>

              <CodeBlock tabs={[
                {
                  label: 'Binary',
                  language: 'bash',
                  code: `# Download latest release
curl -L https://github.com/your-org/tinyice/releases/latest/download/tinyice-$(uname -s)-$(uname -m) -o tinyice
chmod +x tinyice

# Run the server
./tinyice --port 8080`,
                },
                {
                  label: 'From Source',
                  language: 'bash',
                  code: `# Clone and build
git clone https://github.com/your-org/tinyice.git
cd tinyice
go build -o tinyice .

# Run the server
./tinyice --port 8080`,
                },
              ]} />
            </section>

            {/* WebRTC Source */}
            <section id="webrtc-source">
              <h2 class="font-heading text-xl font-bold text-text-primary mb-2">WebRTC Source</h2>
              <p class="text-text-secondary text-sm leading-relaxed mb-6">
                Source connections use WebRTC for real-time audio ingest. Create a peer connection,
                add your audio tracks, and exchange SDP with the server.
              </p>

              <CodeBlock tabs={[{
                label: 'TypeScript',
                language: 'typescript',
                code: `// Capture microphone audio
const stream = await navigator.mediaDevices
  .getUserMedia({ audio: true })

// Create WebRTC peer connection
const pc = new RTCPeerConnection()
stream.getTracks().forEach(t => pc.addTrack(t, stream))

// Signal to TinyIce server
const offer = await pc.createOffer()
await pc.setLocalDescription(offer)

const res = await fetch('/webrtc/source-offer?mount=/live', {
  method: 'POST',
  body: JSON.stringify(offer),
})
const answer = await res.json()
await pc.setRemoteDescription(answer)`,
              }]} />
            </section>

            {/* HTTP Listening */}
            <section id="http-listening">
              <h2 class="font-heading text-xl font-bold text-text-primary mb-2">HTTP Listening</h2>
              <p class="text-text-secondary text-sm leading-relaxed mb-6">
                Listeners connect via standard HTTP. Simply point an audio element or player at the mount URL.
              </p>

              <CodeBlock tabs={[
                {
                  label: 'TypeScript',
                  language: 'typescript',
                  code: `// Play a stream with the Audio API
const audio = new Audio('https://your-server.com/live')
audio.play()

// Or with an HTML element
// <audio src="https://your-server.com/live" controls />`,
                },
              ]} />
            </section>

            {/* WebRTC Playback */}
            <section id="webrtc-playback">
              <h2 class="font-heading text-xl font-bold text-text-primary mb-2">WebRTC Playback</h2>
              <p class="text-text-secondary text-sm leading-relaxed mb-6">
                For ultra-low-latency listening, use WebRTC playback. The server pushes audio tracks
                directly to the client peer connection.
              </p>

              <CodeBlock tabs={[{
                label: 'TypeScript',
                language: 'typescript',
                code: `const pc = new RTCPeerConnection()
pc.ontrack = (e) => {
  const audio = document.createElement('audio')
  audio.srcObject = e.streams[0]
  audio.play()
}

const offer = await pc.createOffer()
await pc.setLocalDescription(offer)

const res = await fetch('/webrtc/offer?mount=/live', {
  method: 'POST',
  body: JSON.stringify(offer),
})
const answer = await res.json()
await pc.setRemoteDescription(answer)`,
              }]} />
            </section>

            {/* Metadata SSE */}
            <section id="metadata-sse">
              <h2 class="font-heading text-xl font-bold text-text-primary mb-2">Metadata (SSE)</h2>
              <p class="text-text-secondary text-sm leading-relaxed mb-6">
                Subscribe to real-time metadata updates via Server-Sent Events. Get notified when
                track information changes on any mount.
              </p>

              <CodeBlock tabs={[{
                label: 'TypeScript',
                language: 'typescript',
                code: `const source = new EventSource('/events')
source.addEventListener('metadata', (e) => {
  const { mount, title, artist } = JSON.parse(e.data)
  console.log(\`Now playing on \${mount}: \${title} \u2014 \${artist}\`)
})`,
              }]} />
            </section>

            {/* REST API */}
            <section id="rest-api">
              <h2 class="font-heading text-xl font-bold text-text-primary mb-2">REST API</h2>
              <p class="text-text-secondary text-sm leading-relaxed mb-6">
                Core endpoints for interacting with TinyIce programmatically.
              </p>

              <div class="space-y-2">
                {endpoints.map((ep) => (
                  <div
                    key={ep.path}
                    class="group flex items-center gap-4 rounded-lg border border-border hover:border-accent/30 bg-surface-raised p-4 transition-colors cursor-pointer"
                  >
                    <span class={`inline-flex items-center justify-center px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider border ${methodColor(ep.method)}`}>
                      {ep.method}
                    </span>
                    <code class="font-code text-[13px] text-text-primary flex-1">{ep.path}</code>
                    <span class="text-text-tertiary text-xs hidden sm:block">{ep.desc}</span>
                    <svg class="w-4 h-4 text-text-tertiary group-hover:text-accent transition-colors flex-none" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <path d="M9 18l6-6-6-6" />
                    </svg>
                  </div>
                ))}
              </div>
            </section>

            {/* Embed Widget */}
            <section id="embed-widget">
              <h2 class="font-heading text-xl font-bold text-text-primary mb-2">Embed Widget</h2>
              <p class="text-text-secondary text-sm leading-relaxed mb-6">
                Embed a minimal player widget on any website with a single iframe tag.
              </p>

              <CodeBlock tabs={[{
                label: 'HTML',
                language: 'bash',
                code: `<iframe
  src="https://your-server.com/embed/live"
  width="100%"
  height="80"
  frameborder="0"
  allow="autoplay"
/>`,
              }]} />
            </section>

            {/* Icecast Compat */}
            <section id="icecast-compat">
              <h2 class="font-heading text-xl font-bold text-text-primary mb-2">Icecast Compatibility</h2>
              <p class="text-text-secondary text-sm leading-relaxed mb-6">
                TinyIce implements the Icecast source protocol, so existing broadcasting software
                (like BUTT, Mixxx, or OBS) can connect without changes. Point your source client
                at the server address and mount path.
              </p>

              <CodeBlock tabs={[{
                label: 'Config',
                language: 'json',
                code: `{
  "host": "your-server.com",
  "port": 8080,
  "mount": "/live",
  "username": "source",
  "password": "your-password"
}`,
              }]} />
            </section>

          </div>

          {/* Footer */}
          <footer class="border-t border-border">
            <div class="max-w-3xl mx-auto px-8 py-6 flex items-center justify-between">
              <span class="font-mono text-[9px] tracking-widest text-text-tertiary/50 uppercase">
                TINYICE // PURE GO
              </span>
              <span class="font-mono text-[9px] tracking-widest text-text-tertiary/50">
                {data.version || 'dev'}
              </span>
            </div>
          </footer>
        </main>
      </div>
    </div>
  )
}
