import type { RedactionBoundary } from '../../security/redaction.js'
import type { PathFlavor } from '../../utils/paths.js'
import {
  FINDING_CONFIDENCES,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
} from '../models/finding.js'
import type { FindingDraft } from '../rules/rule.js'
import { validateEvidenceDraft } from './evidence.js'
import {
  readArray,
  readEnum,
  readExactObject,
  readNonEmptyString,
  readStringArray,
} from './primitives.js'
import { validateSourceLocation } from './source-location.js'

declare const validatedFindingDraftBrand: unique symbol

export type ValidatedFindingDraft = FindingDraft & {
  readonly [validatedFindingDraftBrand]: true
}

export function validateFindingDraft(
  value: unknown,
  boundary: RedactionBoundary,
  flavor: PathFlavor,
): ValidatedFindingDraft {
  const object = readExactObject(
    value,
    [
      'description',
      'severity',
      'confidence',
      'status',
      'primaryLocation',
      'relatedLocations',
      'evidence',
      'impact',
      'remediation',
      'limitations',
      'tags',
    ],
    [
      'description',
      'confidence',
      'status',
      'relatedLocations',
      'evidence',
      'impact',
      'remediation',
      'limitations',
      'tags',
    ],
  )

  const severity =
    object['severity'] === undefined
      ? undefined
      : readEnum(object['severity'], FINDING_SEVERITIES)
  const primaryLocation =
    object['primaryLocation'] === undefined
      ? undefined
      : validateSourceLocation(object['primaryLocation'], flavor)

  const draft: FindingDraft = Object.freeze({
    description: readNonEmptyString(object['description']),
    ...(severity === undefined ? {} : { severity }),
    confidence: readEnum(object['confidence'], FINDING_CONFIDENCES),
    status: readEnum(object['status'], FINDING_STATUSES),
    ...(primaryLocation === undefined ? {} : { primaryLocation }),
    relatedLocations: Object.freeze(
      readArray(object['relatedLocations']).map((location) =>
        validateSourceLocation(location, flavor),
      ),
    ),
    evidence: Object.freeze(
      readArray(object['evidence']).map((evidence) =>
        validateEvidenceDraft(evidence, boundary, flavor),
      ),
    ),
    impact: readNonEmptyString(object['impact']),
    remediation: readNonEmptyString(object['remediation']),
    limitations: readStringArray(object['limitations']),
    tags: readStringArray(object['tags']),
  })

  boundary.assertCanonicalValueSafe(draft)
  return draft as ValidatedFindingDraft
}
