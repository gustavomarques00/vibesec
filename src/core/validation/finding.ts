import type { RedactionBoundary } from '../../security/redaction.js'
import type { PathFlavor } from '../../utils/paths.js'
import {
  FINDING_CONFIDENCES,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  type Finding,
} from '../models/finding.js'
import { normalizeRuleId } from '../ids/finding-id.js'
import { validateEvidence } from './evidence.js'
import {
  readArray,
  readEnum,
  readExactObject,
  readNonEmptyString,
  readStringArray,
} from './primitives.js'
import { validateSourceLocation } from './source-location.js'

export function validateFinding(
  value: unknown,
  boundary: RedactionBoundary,
  flavor: PathFlavor,
): Finding {
  const object = readExactObject(
    value,
    [
      'schemaVersion',
      'id',
      'ruleId',
      'ruleVersion',
      'title',
      'description',
      'category',
      'severity',
      'confidence',
      'status',
      'primaryLocation',
      'relatedLocations',
      'evidence',
      'impact',
      'remediation',
      'limitations',
      'references',
      'tags',
    ],
    [
      'schemaVersion',
      'id',
      'ruleId',
      'ruleVersion',
      'title',
      'description',
      'category',
      'severity',
      'confidence',
      'status',
      'relatedLocations',
      'evidence',
      'impact',
      'remediation',
      'limitations',
      'references',
      'tags',
    ],
  )
  const primaryLocation =
    object['primaryLocation'] === undefined
      ? undefined
      : validateSourceLocation(object['primaryLocation'], flavor)
  const schemaVersion = readEnum(object['schemaVersion'], ['1'] as const)
  const ruleId = normalizeRuleId(readNonEmptyString(object['ruleId']))
  const id = readNonEmptyString(object['id'])
  if (!id.startsWith(`${ruleId}-`)) {
    throw new Error('Finding ID does not match its rule.')
  }

  const finding: Finding = Object.freeze({
    schemaVersion,
    id,
    ruleId,
    ruleVersion: readNonEmptyString(object['ruleVersion']),
    title: readNonEmptyString(object['title']),
    description: readNonEmptyString(object['description']),
    category: readNonEmptyString(object['category']),
    severity: readEnum(object['severity'], FINDING_SEVERITIES),
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
        validateEvidence(evidence, flavor),
      ),
    ),
    impact: readNonEmptyString(object['impact']),
    remediation: readNonEmptyString(object['remediation']),
    limitations: readStringArray(object['limitations']),
    references: readStringArray(object['references']),
    tags: readStringArray(object['tags']),
  })

  boundary.assertCanonicalValueSafe(finding)
  return finding
}
