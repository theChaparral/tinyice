interface SidebarItem {
  id: string
  label: string
  href: string
  icon: string // SVG content (stroke-based)
}

const NAV_ITEMS: SidebarItem[] = [
  { id: 'dashboard', label: 'Dashboard', href: '/admin',
    icon: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>' },
  { id: 'streams', label: 'Streams', href: '/admin/streams',
    icon: '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>' },
  { id: 'autodj', label: 'AutoDJ', href: '/admin/autodj',
    icon: '<circle cx="12" cy="12" r="10"/><polygon points="10,8 16,12 10,16"/>' },
  { id: 'golive', label: 'Go Live', href: '/admin/golive',
    icon: '<path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="22"/>' },
  { id: 'relays', label: 'Relays', href: '/admin/relays',
    icon: '<path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 0 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/>' },
  { id: 'transcoders', label: 'Transcode', href: '/admin/transcoders',
    icon: '<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>' },
  { id: 'studio', label: 'Studio', href: '/admin/studio',
    icon: '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>' },
]

const BOTTOM_ITEMS: SidebarItem[] = [
  { id: 'users', label: 'Users', href: '/admin/users',
    icon: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/>' },
  { id: 'pending', label: 'Pending', href: '/admin/pending',
    icon: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M20 8l-4 4 4 4"/>' },
  { id: 'security', label: 'Security', href: '/admin/security',
    icon: '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>' },
  { id: 'settings', label: 'Settings', href: '/admin/settings',
    icon: '<circle cx="12" cy="12" r="3"/><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/>' },
]

interface SidebarProps {
  activePath?: string
}

export function Sidebar({ activePath }: SidebarProps) {
  const isActive = (item: SidebarItem): boolean => {
    if (!activePath) return false
    if (item.href === '/admin') return activePath === '/admin' || activePath === '/admin/'
    return activePath.startsWith(item.href)
  }

  const renderItem = (item: SidebarItem) => {
    const active = isActive(item)
    return (
      <a
        key={item.id}
        href={item.href}
        class={`
          flex flex-col items-center gap-0.5 px-1 py-2 rounded-lg w-full
          transition-colors text-center group
          ${active
            ? 'bg-accent/10 text-accent'
            : 'text-text-tertiary hover:text-text-secondary hover:bg-surface-hover'
          }
        `}
      >
        <svg
          class="w-[18px] h-[18px] shrink-0"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          stroke-linejoin="round"
          dangerouslySetInnerHTML={{ __html: item.icon }}
        />
        <span class="font-mono text-[8px] tracking-[0.5px] leading-tight uppercase">
          {item.label}
        </span>
      </a>
    )
  }

  return (
    <aside class="fixed top-0 left-0 bottom-0 w-[72px] border-r border-border bg-surface-base flex flex-col items-center py-3 z-40">
      {/* Logo */}
      <a href="/admin" class="w-9 h-9 rounded-lg bg-accent flex items-center justify-center mb-4 shadow-[0_0_12px_var(--color-accent-glow)]">
        <span class="font-mono text-[11px] font-bold text-surface-base leading-none">Ti</span>
      </a>

      {/* Main nav */}
      <div class="flex flex-col items-center gap-0.5 flex-1 w-full px-1.5 overflow-y-auto">
        {NAV_ITEMS.map(renderItem)}
      </div>

      {/* Divider */}
      <div class="w-8 h-px bg-border my-1.5" />

      {/* Bottom nav */}
      <div class="flex flex-col items-center gap-0.5 w-full px-1.5">
        {BOTTOM_ITEMS.map(renderItem)}
      </div>
    </aside>
  )
}
