import type { ExposureLevel } from '../../lib/types'
import { Badge, Tag } from './Badge'

// How a package is reached from the project. Colour follows how directly an attacker's request can get there.
const LABEL: Record<ExposureLevel, string> = {
  web: 'reachable from a web request',
  startup: 'loaded at app start',
  command: 'commands / tasks only',
  test: 'tests only',
  none: 'not reached',
}

export function ExposureBadge({ level }: { level: ExposureLevel }) {
  if (level === 'web') return <Badge signal="critical">{LABEL[level]}</Badge>
  if (level === 'startup') return <Badge signal="warning">{LABEL[level]}</Badge>
  if (level === 'command') return <Badge signal="info">{LABEL[level]}</Badge>
  return <Tag>{LABEL[level]}</Tag>
}
