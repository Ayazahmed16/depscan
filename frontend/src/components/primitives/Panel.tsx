import type { ReactNode } from 'react'

// Base container for every panel: hairline border, square corners, no shadow.
export function Panel({ title, aside, icon, children, className = '', bodyClassName = '' }: {
  title?: string
  aside?: ReactNode
  icon?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section className={`border border-outline-variant bg-surface-container-low ${className}`}>
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-outline-variant/60 px-3 py-2">
          <h2 className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-primary">
            {icon}
            {title}
          </h2>
          {aside}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  )
}
