import { createHash } from 'node:crypto'

import type { ExternalRuleId } from './types.js'

const HASH_LENGTH = 16

/**
 * Deterministic External finding ID from rule + URL (+ optional discriminator).
 * Never includes cookie values, bodies, or Code file-path locations.
 */
export function createExternalFindingId(
  ruleId: ExternalRuleId,
  primaryUrl: string,
  discriminator = '',
): string {
  const canonicalIdentity = JSON.stringify([
    ruleId,
    primaryUrl.normalize('NFC'),
    discriminator.normalize('NFC'),
  ])
  const digest = createHash('sha256')
    .update(canonicalIdentity, 'utf8')
    .digest('hex')
    .slice(0, HASH_LENGTH)
  return `${ruleId}-${digest}`
}
