import { useState } from 'preact/hooks'

interface SidebarItem {
  id: string
  label: string
  href: string
  icon: string // SVG path d attribute
}

const NAV_ITEMS: SidebarItem[] = [
  { id: 'dashboard', label: 'Dashboard', href: '/admin', icon: 'M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z' },
  { id: 'streams', label: 'Streams', href: '/admin/streams', icon: 'M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zM4 6h16v12H4V6zm6 5.5l-3 3h2v2h2v-2h2l-3-3z' },
  { id: 'autodj', label: 'AutoDJ', href: '/admin/autodj', icon: 'M12 3v10.55A4 4 0 1014 17V7h4V3h-6zM10 19a2 2 0 110-4 2 2 0 010 4z' },
  { id: 'golive', label: 'Go Live', href: '/admin/golive', icon: 'M17 10.5V7c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4z' },
  { id: 'relays', label: 'Relays', href: '/admin/relays', icon: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z' },
  { id: 'transcoders', label: 'Transcoders', href: '/admin/transcoders', icon: 'M7 5h10v2h2V3c0-1.1-.9-2-2-2H7c-1.1 0-2 .9-2 2v4h2V5zm8 12H9v-2H7v4c0 1.1.9 2 2 2h6c1.1 0 2-.9 2-2v-4h-2v2zm5-7H4c-1.1 0-2 .9-2 2v2c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2v-2c0-1.1-.9-2-2-2z' },
  { id: 'studio', label: 'Studio', href: '/admin/studio', icon: 'M12 3l.01 10.55c-.59-.34-1.27-.55-2.01-.55C7.79 13 6 14.79 6 17s1.79 4 4.01 4S14 19.21 14 17V7h4V3h-6zm-2 16c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z' },
]

const BOTTOM_ITEMS: SidebarItem[] = [
  { id: 'users', label: 'Users', href: '/admin/users', icon: 'M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z' },
  { id: 'security', label: 'Security', href: '/admin/security', icon: 'M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z' },
  { id: 'settings', label: 'Settings', href: '/admin/settings', icon: 'M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.48.48 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.49.49 0 00-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1115.6 12 3.6 3.6 0 0112 15.6z' },
]

interface SidebarProps {
  activePath?: string
  /** @deprecated Use activePath instead */
  active?: string
  onNavigate?: (id: string) => void
}

export function Sidebar({ activePath, active, onNavigate }: SidebarProps) {
  const [tooltip, setTooltip] = useState<string | null>(null)

  const resolveActive = (item: SidebarItem): boolean => {
    if (activePath) {
      // Exact match for dashboard (/admin), prefix match for sub-pages
      if (item.href === '/admin') return activePath === '/admin' || activePath === '/admin/'
      return activePath.startsWith(item.href)
    }
    return (active ?? 'dashboard') === item.id
  }

  const renderItem = (item: SidebarItem) => {
    const isActive = resolveActive(item)
    return (
      <div class="relative" key={item.id}>
        <a
          href={item.href}
          onClick={() => onNavigate?.(item.id)}
          onMouseEnter={() => setTooltip(item.id)}
          onMouseLeave={() => setTooltip(null)}
          class={`
            w-10 h-10 rounded-lg flex items-center justify-center
            transition-colors
            ${isActive ? 'bg-accent/15 text-accent' : 'text-text-tertiary hover:text-text-secondary hover:bg-surface-hover'}
          `}
          aria-label={item.label}
        >
          <svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
            <path d={item.icon} />
          </svg>
        </a>

        {/* Tooltip */}
        {tooltip === item.id && (
          <div class="absolute left-full top-1/2 -translate-y-1/2 ml-2 px-2 py-1 rounded bg-surface-overlay text-text-primary font-mono text-[10px] tracking-wider whitespace-nowrap z-50 pointer-events-none">
            {item.label}
          </div>
        )}
      </div>
    )
  }

  return (
    <aside class="fixed top-0 left-0 bottom-0 w-16 border-r border-border bg-surface-base flex flex-col items-center py-4 z-40">
      {/* Logo */}
      <a href="/admin" class="h-8 w-8 rounded bg-accent flex items-center justify-center mb-6">
        <span class="font-mono text-xs font-bold text-surface-base leading-none">Ti</span>
      </a>

      {/* Main nav */}
      <div class="flex flex-col items-center gap-1 flex-1">
        {NAV_ITEMS.map(renderItem)}
      </div>

      {/* Divider */}
      <div class="w-6 h-px bg-border my-2" />

      {/* Bottom nav */}
      <div class="flex flex-col items-center gap-1">
        {BOTTOM_ITEMS.map(renderItem)}
      </div>
    </aside>
  )
}
