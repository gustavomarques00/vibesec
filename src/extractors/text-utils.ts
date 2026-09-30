import type { FactContext } from '../core/models/fact.js'
import type { SourceLocation } from '../core/models/source-location.js'

export { isDotenvPath } from '../utils/dotenv-path.js'

export function buildLineStarts(content: string): readonly number[] {
  const starts = [0]
  for (let index = 0; index < content.length; index += 1) {
    if (content.charCodeAt(index) === 10) starts.push(index + 1)
  }
  return starts
}

export function locationForRange(
  file: string,
  lineStarts: readonly number[],
  start: number,
  end: number,
): SourceLocation {
  const startPosition = positionAt(lineStarts, start)
  const endPosition = positionAt(lineStarts, end)
  return Object.freeze({
    file,
    startLine: startPosition.line,
    startColumn: startPosition.column,
    endLine: endPosition.line,
    endColumn: endPosition.column,
  })
}

export function positionAt(
  lineStarts: readonly number[],
  offset: number,
): Readonly<{ line: number; column: number }> {
  let low = 0
  let high = lineStarts.length
  while (low < high) {
    const middle = Math.floor((low + high) / 2)
    const lineStart = lineStarts[middle]
    if (lineStart !== undefined && lineStart <= offset) {
      low = middle + 1
    } else {
      high = middle
    }
  }
  const lineIndex = Math.max(0, low - 1)
  return Object.freeze({
    line: lineIndex + 1,
    column: offset - (lineStarts[lineIndex] ?? 0) + 1,
  })
}

export function classifyFileContext(relativePath: string): FactContext {
  const normalized = relativePath.normalize('NFC').toLowerCase()
  if (
    normalized.includes('/test/') ||
    normalized.includes('/tests/') ||
    normalized.includes('/__tests__/') ||
    /\.(?:test|spec)\.[^.]+$/u.test(normalized)
  ) {
    return 'test'
  }
  if (normalized.includes('/fixture') || normalized.includes('/fixtures/')) {
    return 'fixture'
  }
  if (
    normalized.includes('/docs/') ||
    normalized.endsWith('.md') ||
    normalized.endsWith('.mdx')
  ) {
    return 'documentation'
  }
  if (
    normalized.includes('/dist/') ||
    normalized.includes('/build/') ||
    normalized.includes('/.next/') ||
    normalized.includes('/generated/')
  ) {
    return 'generated'
  }
  if (
    normalized === '.env' ||
    normalized.startsWith('.env.') ||
    normalized.endsWith('.env') ||
    normalized.includes('/.env')
  ) {
    return 'config'
  }
  return 'unknown'
}

export function isPlaceholderText(value: string): boolean {
  const upper = value.toUpperCase()
  return (
    upper.includes('PLACEHOLDER') ||
    upper.includes('EXAMPLE') ||
    upper.includes('CHANGEME') ||
    upper.includes('TODO') ||
    upper.includes('DO_NOT_USE') ||
    upper.includes('YOUR_') ||
    upper === 'PASSWORD' ||
    upper === 'SECRET' ||
    upper === 'TOKEN' ||
    upper === 'XXXX' ||
    /^X+$/u.test(upper) ||
    /^0+$/u.test(value)
  )
}

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0
  const counts = new Map<string, number>()
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1)
  }
  let entropy = 0
  for (const count of counts.values()) {
    const probability = count / value.length
    entropy -= probability * Math.log2(probability)
  }
  return entropy
}

export function rangesOverlap(
  leftStart: number,
  leftEnd: number,
  rightStart: number,
  rightEnd: number,
): boolean {
  return leftStart < rightEnd && rightStart < leftEnd
}
