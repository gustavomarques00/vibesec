import { createHash } from 'node:crypto'

import type { SourceLocation } from '../models/source-location.js'

const RULE_ID_PATTERN = /^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$/
const HASH_LENGTH = 16

export function normalizeRuleId(ruleId: string): string {
  const normalized = ruleId.trim().toUpperCase()
  if (!RULE_ID_PATTERN.test(normalized)) {
    throw new Error('Rule IDs must use uppercase dash-separated segments.')
  }
  return normalized
}

/**
 * Produces a deterministic ID from non-sensitive source identity only.
 *
 * Evidence, snippets, fingerprints, timestamps, random values, and absolute paths
 * are intentionally absent from this API.
 */
export function createFindingId(
  validatedRuleId: string,
  canonicalLocation?: SourceLocation,
): string {
  const ruleId = normalizeRuleId(validatedRuleId)
  const canonicalIdentity = JSON.stringify([
    ruleId,
    canonicalLocation?.file ?? '<global>',
    canonicalLocation?.startLine ?? 0,
    canonicalLocation?.startColumn ?? 0,
    canonicalLocation?.endLine ?? 0,
    canonicalLocation?.endColumn ?? 0,
  ])
  const digest = createHash('sha256')
    .update(canonicalIdentity, 'utf8')
    .digest('hex')
    .slice(0, HASH_LENGTH)

  return `${ruleId}-${digest}`
}
