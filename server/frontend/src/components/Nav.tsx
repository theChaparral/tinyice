interface NavProps {
  branding?: {
    logoUrl: string | null
    accentColor: string
    navTitle?: string
  }
  pageTitle?: string
}

export function Nav({ branding, pageTitle }: NavProps) {
  const displayTitle = branding?.navTitle || pageTitle || 'TINYICE'

  return (
    <nav class="fixed top-0 inset-x-0 z-50 h-14 border-b border-border bg-surface-base/80 backdrop-blur-md">
      <div class="h-full flex items-center justify-between px-8 lg:px-16 xl:px-24">
        {/* Logo */}
        <a href="/" class="flex items-center gap-3">
          {branding?.logoUrl ? (
            <img src={branding.logoUrl} alt="Logo" class="h-8 w-8 rounded object-cover" />
          ) : (
            <div class="h-8 w-8 rounded bg-accent flex items-center justify-center">
              <span class="font-mono text-xs font-bold text-surface-base leading-none">
                {displayTitle.slice(0, 2).toUpperCase()}
              </span>
            </div>
          )}
          <span class="font-mono text-sm font-bold tracking-widest text-text-primary uppercase">
            {displayTitle}
          </span>
        </a>

        {/* Nav links */}
        <div class="hidden sm:flex items-center gap-6">
          <a
            href="/explore"
            class="font-mono text-xs tracking-wider text-text-secondary hover:text-text-primary transition-colors"
          >
            EXPLORE
          </a>
          <a
            href="/developers"
            class="font-mono text-xs tracking-wider text-text-secondary hover:text-text-primary transition-colors"
          >
            DEVELOPERS
          </a>
          <a
            href="/admin"
            class="font-mono text-xs tracking-wider text-accent hover:text-accent/80 transition-colors"
          >
            ADMIN
          </a>
        </div>
      </div>
    </nav>
  )
}
