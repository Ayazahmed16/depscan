import type { ReactNode } from 'react'

// Every number, ID and timestamp goes through this: mono, tabular.
export function DataReadout({ children, className = '', dim = false }: {
  children: ReactNode
  className?: string
  dim?: boolean
}) {
  return (
    <span className={`font-mono tabular-nums ${dim ? 'text-on-surface-variant' : 'text-on-surface'} ${className}`}>
      {children}
    </span>
  )
}
