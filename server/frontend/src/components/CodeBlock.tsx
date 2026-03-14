import { useState, useRef, useEffect } from 'preact/hooks'
import hljs from 'highlight.js/lib/core'
import typescript from 'highlight.js/lib/languages/typescript'
import javascript from 'highlight.js/lib/languages/javascript'
import bash from 'highlight.js/lib/languages/bash'
import json from 'highlight.js/lib/languages/json'

hljs.registerLanguage('typescript', typescript)
hljs.registerLanguage('javascript', javascript)
hljs.registerLanguage('bash', bash)
hljs.registerLanguage('json', json)

interface CodeTab {
  label: string
  language: string
  code: string
}

interface CodeBlockProps {
  tabs: CodeTab[]
  activeTab?: number
}

export function CodeBlock({ tabs, activeTab = 0 }: CodeBlockProps) {
  const [active, setActive] = useState(activeTab)
  const [copied, setCopied] = useState(false)
  const codeRef = useRef<HTMLElement>(null)

  const current = tabs[active]
  const lines = current.code.split('\n')

  useEffect(() => {
    if (codeRef.current) {
      codeRef.current.removeAttribute('data-highlighted')
      hljs.highlightElement(codeRef.current)
    }
  }, [active])

  const handleCopy = () => {
    navigator.clipboard.writeText(current.code).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div class="rounded-xl border border-border bg-[#050505] overflow-hidden">
      {/* Top bar */}
      <div class="flex items-center justify-between border-b border-border px-4 h-10">
        <div class="flex items-center gap-0">
          {tabs.map((tab, i) => (
            <button
              key={tab.label}
              onClick={() => setActive(i)}
              class={`font-mono text-[11px] tracking-wider px-3 h-10 transition-colors relative ${
                i === active
                  ? 'text-text-primary'
                  : 'text-text-tertiary hover:text-text-secondary'
              }`}
            >
              {tab.label}
              {i === active && (
                <span class="absolute bottom-0 inset-x-3 h-[2px] bg-accent rounded-full" />
              )}
            </button>
          ))}
        </div>
        <button
          onClick={handleCopy}
          class="font-mono text-[10px] tracking-widest text-text-tertiary hover:text-text-secondary transition-colors px-2 py-1"
        >
          {copied ? 'COPIED' : 'COPY'}
        </button>
      </div>

      {/* Code area */}
      <div class="overflow-x-auto">
        <div class="flex min-w-0">
          {/* Line numbers */}
          <div class="flex-none select-none pr-4 pl-4 py-4 text-right">
            {lines.map((_, i) => (
              <div
                key={i}
                class="font-code text-[12.5px] leading-[1.9] text-white/10"
              >
                {i + 1}
              </div>
            ))}
          </div>

          {/* Code */}
          <div class="flex-1 min-w-0 py-4 pr-4 overflow-x-auto">
            <pre class="m-0"><code
              ref={codeRef}
              class={`hljs language-${current.language} font-code !bg-transparent !p-0`}
              style={{ fontSize: '12.5px', lineHeight: '1.9' }}
            >{current.code}</code></pre>
          </div>
        </div>
      </div>

      {/* Custom highlight.js theme */}
      <style>{`
        .hljs { color: rgba(255,255,255,0.7); }
        .hljs-keyword, .hljs-built_in, .hljs-type { color: #c084fc; }
        .hljs-title.class_, .hljs-title.function_ { color: #ff6600; }
        .hljs-string, .hljs-template-variable { color: #60a5fa; }
        .hljs-number { color: #f59e0b; }
        .hljs-comment { color: rgba(255,255,255,0.2); font-style: italic; }
        .hljs-attr, .hljs-attribute { color: #60a5fa; }
        .hljs-property { color: rgba(255,255,255,0.6); }
        .hljs-literal { color: #f59e0b; }
        .hljs-regexp { color: #f87171; }
        .hljs-meta { color: rgba(255,255,255,0.4); }
        .hljs-variable { color: rgba(255,255,255,0.7); }
        .hljs-params { color: rgba(255,255,255,0.6); }
        .hljs-punctuation { color: rgba(255,255,255,0.35); }
      `}</style>
    </div>
  )
}
