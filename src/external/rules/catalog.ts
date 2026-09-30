import type { ExternalRule, ExternalRuleId, ExternalRuleMetadata } from './types.js'
import { vsExt001 } from './vs-ext-001.js'
import { vsExt002 } from './vs-ext-002.js'
import { vsExt003 } from './vs-ext-003.js'
import { vsExt004 } from './vs-ext-004.js'
import { vsExt005 } from './vs-ext-005.js'
import { vsExt006 } from './vs-ext-006.js'
import { vsExt007 } from './vs-ext-007.js'
import { vsExt008 } from './vs-ext-008.js'
import { vsExt009 } from './vs-ext-009.js'
import { vsExt010 } from './vs-ext-010.js'
import { vsExt011 } from './vs-ext-011.js'

export const EXTERNAL_RULES: readonly ExternalRule[] = Object.freeze([
  vsExt001,
  vsExt002,
  vsExt003,
  vsExt004,
  vsExt005,
  vsExt006,
  vsExt007,
  vsExt008,
  vsExt009,
  vsExt010,
  vsExt011,
])

export const EXTERNAL_RULE_IDS: readonly ExternalRuleId[] = Object.freeze(
  EXTERNAL_RULES.map((rule) => rule.metadata.id),
)

export function getExternalRuleMetadata(): readonly ExternalRuleMetadata[] {
  return Object.freeze(EXTERNAL_RULES.map((rule) => rule.metadata))
}
