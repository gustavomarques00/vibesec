import type { SecretCandidateFact } from '../core/models/fact.js'
import type { ScanKernelContext } from '../core/scan/scan-kernel-context.js'
import {
  buildLineStarts,
  classifyFileContext,
  isPlaceholderText,
  locationForRange,
  rangesOverlap,
  shannonEntropy,
} from './text-utils.js'

const GENERIC_ASSIGNMENT =
  /\b((?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret))\s*[=:]\s*['"]?([^\s'"`]{12,})['"]?/giu

const MAX_CANDIDATE_BYTES = 4_096
const MIN_ENTROPY = 3.3

export function countGenericSecretCandidates(content: string, maximum: number): number {
  if (!Number.isSafeInteger(maximum) || maximum < 0) {
    throw new Error('Generic secret candidate limit exceeded.')
  }
  let count = 0
  for (const match of content.matchAll(GENERIC_ASSIGNMENT)) {
    if ((match[2] ?? '').length === 0) continue
    count += 1
    if (count > maximum) throw new Error('Generic secret candidate limit exceeded.')
  }
  return count
}

export function extractGenericSecretFacts(
  scan: ScanKernelContext,
  relativePath: string,
  content: string,
  occupiedRanges: readonly Readonly<{ start: number; end: number }>[] = [],
): readonly SecretCandidateFact[] {
  const facts: SecretCandidateFact[] = []
  const lineStarts = buildLineStarts(content)
  const context = classifyFileContext(relativePath)

  for (const match of content.matchAll(GENERIC_ASSIGNMENT)) {
    const bindingName = match[1]
    const rawValue = match[2]
    if (bindingName === undefined || rawValue === undefined) continue
    const valueOffset = match[0].lastIndexOf(rawValue)
    if (valueOffset < 0) continue
    const start = match.index + valueOffset
    const end = start + rawValue.length
    if (
      rawValue.length > MAX_CANDIDATE_BYTES ||
      isPlaceholderText(rawValue) ||
      shannonEntropy(rawValue) < MIN_ENTROPY ||
      occupiedRanges.some((range) => rangesOverlap(range.start, range.end, start, end))
    ) {
      continue
    }
    const protectedValue = scan.protectSecret(rawValue, { visiblePrefix: 0 })
    facts.push(
      Object.freeze({
        kind: 'secret.candidate',
        location: locationForRange(relativePath, lineStarts, start, end),
        source: Object.freeze({
          extractor: 'generic-secret-entropy',
          context,
          syntax: 'text',
        }),
        confidence: 'medium',
        secretType: 'unknown',
        bindingName: bindingName.normalize('NFC'),
        protectedValue,
        isPlaceholder: false,
      }),
    )
  }
  return Object.freeze(facts)
}
