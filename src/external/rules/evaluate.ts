import { compareExternalStrings } from '../domain/ordering.js'
import type { ExternalObservationGraph } from '../domain/observations.js'
import { EXTERNAL_RULES } from './catalog.js'
import { createExternalFindingId } from './finding-id.js'
import type {
  ExternalFinding,
  ExternalFindingEvidence,
  ExternalFindingDraft,
  ExternalRuleEvaluationContext,
} from './types.js'

/**
 * Evaluate all External VS-EXT rules against an observation graph.
 * Pure: no network, filesystem, or wall-clock reads.
 */
export function evaluateExternalRules(
  graph: ExternalObservationGraph,
  context: ExternalRuleEvaluationContext,
): readonly ExternalFinding[] {
  const drafts: ExternalFindingDraft[] = []
  for (const rule of EXTERNAL_RULES) {
    drafts.push(...rule.evaluate(graph, context))
  }

  const findings = drafts.map((draft) => finalizeDraft(draft))
  const deduped = dedupeById(findings)
  return Object.freeze(sortFindings(deduped))
}

function finalizeDraft(draft: ExternalFindingDraft): ExternalFinding {
  const rule = EXTERNAL_RULES.find((entry) => entry.metadata.id === draft.ruleId)
  if (rule === undefined) {
    throw new Error(`Unknown External rule: ${draft.ruleId}`)
  }

  const evidence: ExternalFindingEvidence[] = draft.evidence.map((item) =>
    Object.freeze({
      kind: item.kind,
      summary: item.summary,
      location:
        item.location ?? Object.freeze({ kind: 'url' as const, url: draft.primaryUrl }),
      ...(item.redactedSnippet !== undefined
        ? { redactedSnippet: item.redactedSnippet }
        : {}),
    }),
  )

  return Object.freeze({
    schemaVersion: '1',
    id: createExternalFindingId(
      draft.ruleId,
      draft.primaryUrl,
      draft.discriminator ?? '',
    ),
    ruleId: draft.ruleId,
    ruleVersion: rule.metadata.version,
    title: rule.metadata.title,
    description: draft.description,
    category: rule.metadata.category,
    severity: draft.severity ?? rule.metadata.defaultSeverity,
    confidence: draft.confidence,
    status: draft.status,
    primaryUrl: draft.primaryUrl,
    evidence: Object.freeze(evidence),
    impact: draft.impact,
    remediation: draft.remediation,
    limitations: Object.freeze([...draft.limitations]),
    tags: Object.freeze([...draft.tags]),
  })
}

function dedupeById(findings: readonly ExternalFinding[]): ExternalFinding[] {
  const seen = new Set<string>()
  const result: ExternalFinding[] = []
  for (const finding of findings) {
    if (seen.has(finding.id)) continue
    seen.add(finding.id)
    result.push(finding)
  }
  return result
}

function sortFindings(findings: readonly ExternalFinding[]): ExternalFinding[] {
  return [...findings].sort((left, right) => {
    const byRule = compareExternalStrings(left.ruleId, right.ruleId)
    if (byRule !== 0) return byRule
    const byUrl = compareExternalStrings(left.primaryUrl, right.primaryUrl)
    if (byUrl !== 0) return byUrl
    return compareExternalStrings(left.id, right.id)
  })
}
