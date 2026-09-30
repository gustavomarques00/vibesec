import { normalizeRuleId } from '../ids/finding-id.js'
import { FACT_KINDS } from '../models/fact.js'
import { FINDING_SEVERITIES } from '../models/finding.js'
import type { RuleMetadata } from '../rules/rule.js'
import {
  readArray,
  readEnum,
  readExactObject,
  readNonEmptyString,
  readStringArray,
} from './primitives.js'

declare const validatedRuleMetadataBrand: unique symbol

export type ValidatedRuleMetadata = RuleMetadata & {
  readonly [validatedRuleMetadataBrand]: true
}

export function validateRuleMetadata(value: unknown): ValidatedRuleMetadata {
  const object = readExactObject(
    value,
    [
      'id',
      'version',
      'title',
      'category',
      'defaultSeverity',
      'supportedFacts',
      'references',
    ],
    [
      'id',
      'version',
      'title',
      'category',
      'defaultSeverity',
      'supportedFacts',
      'references',
    ],
  )

  const supportedFacts = Object.freeze(
    readArray(object['supportedFacts']).map((kind) => readEnum(kind, FACT_KINDS)),
  )
  const metadata: RuleMetadata = Object.freeze({
    id: normalizeRuleId(readNonEmptyString(object['id'])),
    version: readNonEmptyString(object['version']),
    title: readNonEmptyString(object['title']),
    category: readNonEmptyString(object['category']),
    defaultSeverity: readEnum(object['defaultSeverity'], FINDING_SEVERITIES),
    supportedFacts,
    references: readStringArray(object['references']),
  })

  // The brand is internal evidence that the exact runtime validator succeeded.
  return metadata as ValidatedRuleMetadata
}
