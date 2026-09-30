import type { SecretCandidateFact } from '../core/models/fact.js'
import type { ScanKernelContext } from '../core/scan/scan-kernel-context.js'
import {
  buildLineStarts,
  classifyFileContext,
  isPlaceholderText,
  locationForRange,
  rangesOverlap,
} from './text-utils.js'

const MAX_CANDIDATE_BYTES = 8_192

type Detector = Readonly<{
  secretType: SecretCandidateFact['secretType']
  pattern: RegExp
  validate?: (value: string) => boolean
}>

const DETECTORS: readonly Detector[] = [
  {
    secretType: 'database_url',
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'`<>\\]+/giu,
    validate: (value) => /:\/\/[^/@\s]+:[^/@\s]+@/u.test(value),
  },
  {
    secretType: 'api_key',
    pattern: /\bghp_[A-Za-z0-9]{20,}\b/gu,
  },
  {
    secretType: 'api_key',
    pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/gu,
  },
  {
    secretType: 'webhook_secret',
    pattern: /\bwhsec_[A-Za-z0-9]{16,}\b/gu,
  },
  {
    secretType: 'bearer_token',
    pattern: /\bBearer\s+([A-Za-z0-9\-._~+/]+=*)\b/gu,
    validate: (value) => value.length >= 20,
  },
  {
    secretType: 'jwt',
    pattern: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/gu,
    validate: isStructuredJwt,
  },
]

export function countHighSpecificityCandidates(
  content: string,
  maximum: number,
): number {
  if (!Number.isSafeInteger(maximum) || maximum < 0) {
    throw new Error('High-specificity candidate limit exceeded.')
  }
  let count = 0
  for (const detector of DETECTORS) {
    for (const match of content.matchAll(detector.pattern)) {
      if (match[0].length === 0) continue
      count += 1
      if (count > maximum) {
        throw new Error('High-specificity candidate limit exceeded.')
      }
    }
  }
  return count
}

export function extractHighSpecificitySecretFacts(
  scan: ScanKernelContext,
  relativePath: string,
  content: string,
): readonly SecretCandidateFact[] {
  const facts: SecretCandidateFact[] = []
  const lineStarts = buildLineStarts(content)
  const context = classifyFileContext(relativePath)
  const claimed: Readonly<{ start: number; end: number }>[] = []

  for (const detector of DETECTORS) {
    for (const match of content.matchAll(detector.pattern)) {
      const rawValue =
        detector.secretType === 'bearer_token' && match[1] !== undefined
          ? match[1]
          : match[0]
      const start =
        detector.secretType === 'bearer_token' && match[1] !== undefined
          ? match.index + match[0].indexOf(match[1])
          : match.index
      const end = start + rawValue.length
      if (
        rawValue.length === 0 ||
        rawValue.length > MAX_CANDIDATE_BYTES ||
        isPlaceholderText(rawValue) ||
        (detector.validate !== undefined && !detector.validate(rawValue)) ||
        claimed.some((range) => rangesOverlap(range.start, range.end, start, end))
      ) {
        continue
      }
      claimed.push(Object.freeze({ start, end }))
      const protectedValue = scan.protectSecret(rawValue, { visiblePrefix: 0 })
      facts.push(
        Object.freeze({
          kind: 'secret.candidate',
          location: locationForRange(relativePath, lineStarts, start, end),
          source: Object.freeze({
            extractor: 'high-specificity-secret',
            context,
            syntax: 'text',
          }),
          confidence: 'high',
          secretType: detector.secretType,
          protectedValue,
          isPlaceholder: false,
        }),
      )
    }
  }
  return Object.freeze(facts)
}

function isStructuredJwt(value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 3) return false
  return parts.every((part) => part.length >= 4 && /^[A-Za-z0-9_-]+$/u.test(part))
}
