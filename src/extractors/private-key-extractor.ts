import { createPrivateKey } from 'node:crypto'

import type { SecretCandidateFact } from '../core/models/fact.js'
import type { ScanKernelContext } from '../core/scan/scan-kernel-context.js'
import {
  buildLineStarts,
  classifyFileContext,
  isPlaceholderText,
  locationForRange,
} from './text-utils.js'

const PRIVATE_KEY_BLOCK =
  /-----BEGIN ((?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----[\s\S]*?-----END \1-----/gu

export class PrivateKeyCandidateLimitError extends Error {
  constructor() {
    super('Private-key candidate limit exceeded.')
    this.name = 'PrivateKeyCandidateLimitError'
  }
}

export function countPrivateKeyCandidates(content: string, maximum: number): number {
  if (!Number.isSafeInteger(maximum) || maximum < 0) {
    throw new PrivateKeyCandidateLimitError()
  }
  let count = 0
  for (const match of content.matchAll(PRIVATE_KEY_BLOCK)) {
    if (match[0].length === 0) continue
    count += 1
    if (count > maximum) throw new PrivateKeyCandidateLimitError()
  }
  return count
}

export function extractPrivateKeyFacts(
  scan: ScanKernelContext,
  relativePath: string,
  content: string,
): readonly SecretCandidateFact[] {
  const facts: SecretCandidateFact[] = []
  const lineStarts = buildLineStarts(content)
  const context = classifyFileContext(relativePath)
  for (const match of content.matchAll(PRIVATE_KEY_BLOCK)) {
    const rawValue = match[0]
    const start = match.index
    if (isPlaceholderText(rawValue) || !isParseablePrivateKey(rawValue)) continue
    const end = start + rawValue.length
    const protectedValue = scan.protectSecret(rawValue, { visiblePrefix: 0 })
    facts.push(
      Object.freeze({
        kind: 'secret.candidate',
        location: locationForRange(relativePath, lineStarts, start, end),
        source: Object.freeze({
          extractor: 'private-key-pem',
          context,
          syntax: 'text',
        }),
        confidence: 'high',
        secretType: 'private_key',
        protectedValue,
        isPlaceholder: false,
      }),
    )
  }
  return Object.freeze(facts)
}

function isParseablePrivateKey(rawValue: string): boolean {
  try {
    return createPrivateKey(rawValue).type === 'private'
  } catch {
    return false
  }
}
