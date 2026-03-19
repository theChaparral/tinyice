interface SkeletonProps {
  class?: string
}

export function Skeleton({ class: className }: SkeletonProps) {
  return (
    <div class={`bg-surface-raised rounded-md animate-pulse ${className ?? ''}`} />
  )
}
