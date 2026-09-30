import { createFindingId } from '../ids/finding-id.js'
import type { RedactionBoundary } from '../../security/redaction.js'
import { sortEvidence, sortUniqueStrings } from '../../utils/deterministic-sort.js'
import type { PathFlavor } from '../../utils/paths.js'
import type { Evidence, EvidenceDraft } from './evidence.js'
import type { Finding } from './finding.js'
import { compareSourceLocations } from './source-location.js'
import type { ValidatedFindingDraft } from '../validation/finding-draft.js'
import type { ValidatedRuleMetadata } from '../validation/rule-metadata.js'
import { validateFinding } from '../validation/finding.js'

export function finalizeFinding(
  metadata: ValidatedRuleMetadata,
  draft: ValidatedFindingDraft,
  boundary: RedactionBoundary,
  flavor: PathFlavor,
): Finding {
  const relatedLocations = Object.freeze(
    [...draft.relatedLocations].sort(compareSourceLocations),
  )
  const evidence = sortEvidence(
    draft.evidence.map((item) => finalizeEvidence(item, boundary)),
  )

  const candidate: Finding = Object.freeze({
    schemaVersion: '1',
    id: createFindingId(metadata.id, draft.primaryLocation),
    ruleId: metadata.id,
    ruleVersion: metadata.version,
    title: metadata.title,
    description: draft.description,
    category: metadata.category,
    severity: draft.severity ?? metadata.defaultSeverity,
    confidence: draft.confidence,
    status: draft.status,
    ...(draft.primaryLocation === undefined
      ? {}
      : { primaryLocation: draft.primaryLocation }),
    relatedLocations,
    evidence,
    impact: draft.impact,
    remediation: draft.remediation,
    limitations: sortUniqueStrings(draft.limitations),
    references: sortUniqueStrings(metadata.references),
    tags: sortUniqueStrings(draft.tags),
  })

  return validateFinding(candidate, boundary, flavor)
}

function finalizeEvidence(
  evidence: EvidenceDraft,
  boundary: RedactionBoundary,
): Evidence {
  const redactedSnippet =
    evidence.redactedSnippet === undefined
      ? undefined
      : boundary.resolveSanitizedText(evidence.redactedSnippet)
  const secretFingerprint =
    evidence.secretFingerprint === undefined
      ? undefined
      : boundary.resolveFingerprint(evidence.secretFingerprint)
  return Object.freeze({
    kind: evidence.kind,
    summary: evidence.summary,
    ...(redactedSnippet === undefined ? {} : { redactedSnippet }),
    locations: Object.freeze([...evidence.locations].sort(compareSourceLocations)),
    ...(secretFingerprint === undefined ? {} : { secretFingerprint }),
  })
}
