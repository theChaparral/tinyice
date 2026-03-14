interface ModeToggleProps {
  mode: 'http' | 'webrtc'
  onChange: (mode: 'http' | 'webrtc') => void
}

export function ModeToggle({ mode, onChange }: ModeToggleProps) {
  return (
    <div class="inline-flex rounded-lg bg-surface-raised border border-border p-0.5">
      <button
        onClick={() => onChange('http')}
        class={`
          font-mono text-[10px] tracking-wider uppercase px-3 py-1.5 rounded-md
          transition-all duration-200
          ${mode === 'http'
            ? 'bg-accent text-surface-base font-bold'
            : 'text-text-tertiary hover:text-text-secondary'}
        `}
      >
        HTTP
      </button>
      <button
        onClick={() => onChange('webrtc')}
        class={`
          font-mono text-[10px] tracking-wider uppercase px-3 py-1.5 rounded-md
          transition-all duration-200
          ${mode === 'webrtc'
            ? 'bg-accent text-surface-base font-bold'
            : 'text-text-tertiary hover:text-text-secondary'}
        `}
      >
        WebRTC
      </button>
    </div>
  )
}
