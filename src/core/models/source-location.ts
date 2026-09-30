import { normalizeRelativePath, type PathFlavor } from '../../utils/paths.js'

export type SourceLocation = Readonly<{
  file: string
  startLine: number
  startColumn?: number
  endLine?: number
  endColumn?: number
}>

export function createSourceLocation(
  location: SourceLocation,
  flavor: PathFlavor,
): SourceLocation {
  assertPositiveInteger(location.startLine, 'startLine')
  assertOptionalPositiveInteger(location.startColumn, 'startColumn')
  assertOptionalPositiveInteger(location.endLine, 'endLine')
  assertOptionalPositiveInteger(location.endColumn, 'endColumn')

  if (location.endLine !== undefined && location.endLine < location.startLine) {
    throw new Error('A source location cannot end before it starts.')
  }
  if (
    location.endLine === location.startLine &&
    location.startColumn !== undefined &&
    location.endColumn !== undefined &&
    location.endColumn < location.startColumn
  ) {
    throw new Error('A source location cannot end before it starts.')
  }

  return Object.freeze({
    ...location,
    file: normalizeRelativePath(location.file, flavor),
  })
}

export function compareSourceLocations(
  left: SourceLocation,
  right: SourceLocation,
): number {
  return (
    compareCanonicalStrings(left.file, right.file) ||
    left.startLine - right.startLine ||
    (left.startColumn ?? 0) - (right.startColumn ?? 0) ||
    (left.endLine ?? left.startLine) - (right.endLine ?? right.startLine) ||
    (left.endColumn ?? left.startColumn ?? 0) -
      (right.endColumn ?? right.startColumn ?? 0)
  )
}

function compareCanonicalStrings(left: string, right: string): number {
  const normalizedLeft = left.normalize('NFC')
  const normalizedRight = right.normalize('NFC')
  return normalizedLeft < normalizedRight
    ? -1
    : normalizedLeft > normalizedRight
      ? 1
      : 0
}

function assertPositiveInteger(value: number, name: string): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive integer.`)
  }
}

function assertOptionalPositiveInteger(value: number | undefined, name: string): void {
  if (value !== undefined) {
    assertPositiveInteger(value, name)
  }
}
