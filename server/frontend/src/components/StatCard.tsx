interface StatCardProps {
  label: string
  value: string | number
  subtitle?: string
  gauge?: number // 0-100 percentage
}

export function StatCard({ label, value, subtitle, gauge }: StatCardProps) {
  return (
    <div class="rounded-lg border border-border bg-surface-raised p-4 flex flex-col gap-2">
      {/* Gauge bar */}
      {gauge !== undefined && (
        <div class="h-1 w-full rounded-full bg-surface-overlay overflow-hidden">
          <div
            class="h-full rounded-full bg-accent transition-all duration-500"
            style={{ width: `${Math.min(100, Math.max(0, gauge))}%` }}
          />
        </div>
      )}

      {/* Label */}
      <span class="font-mono text-[10px] tracking-widest uppercase text-text-tertiary">
        {label}
      </span>

      {/* Value */}
      <span class="font-mono text-2xl font-bold text-text-primary leading-none">
        {value}
      </span>

      {/* Subtitle */}
      {subtitle && (
        <span class="text-xs text-text-secondary">{subtitle}</span>
      )}
    </div>
  )
}
