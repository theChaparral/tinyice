interface ToggleProps {
  checked: boolean
  onChange: (checked: boolean) => void
  label?: string
}

export function Toggle({ checked, onChange, label }: ToggleProps) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      class={`
        relative inline-flex items-center
        w-8 h-[18px] rounded-full
        transition-colors duration-200
        ${checked ? 'bg-accent' : 'bg-surface-overlay'}
      `}
    >
      <span
        class={`
          inline-block w-3.5 h-3.5 rounded-full bg-white
          transition-transform duration-200 ease-[var(--ease-out-expo)]
          ${checked ? 'translate-x-[15px]' : 'translate-x-[2px]'}
        `}
      />
    </button>
  )
}
