export function EqBars({ bars = 5 }: { bars?: number }) {
  return (
    <div class="flex gap-[2px] h-4 items-end">
      {Array.from({ length: bars }, (_, i) => (
        <div
          key={i}
          class="w-[3px] rounded-sm bg-accent origin-bottom"
          style={{ animation: `eq-bar 0.5s ease-in-out ${i * 0.08}s infinite`, height: '100%' }}
        />
      ))}
    </div>
  )
}
