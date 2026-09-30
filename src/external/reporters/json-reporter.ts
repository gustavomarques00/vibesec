import type {
  ExternalFinding,
  ExternalJsonReportDocument,
  ExternalScanResult,
} from './result.js'
import { boundExternalReportText } from './safe-text.js'

/**
 * Deterministic External JSON document (schemaVersion ext-1).
 * Pure formatting — no rule evaluation or network.
 */
export function createExternalJsonReportDocument(
  result: ExternalScanResult,
): ExternalJsonReportDocument {
  return Object.freeze({
    schemaVersion: 'ext-1',
    target: boundExternalReportText(result.target),
    effectiveUrl: boundExternalReportText(result.effectiveUrl),
    summary: result.summary,
    findings: Object.freeze(result.findings.map((finding) => boundFinding(finding))),
    limitations: Object.freeze(
      result.limitations.map((item) => boundExternalReportText(item)),
    ),
    evaluationTimeMs: result.evaluationTimeMs,
    requestsConsumed: result.requestsConsumed,
  })
}

export function renderExternalJsonReport(result: ExternalScanResult): string {
  return `${JSON.stringify(createExternalJsonReportDocument(result))}\n`
}

function boundFinding(finding: ExternalFinding): ExternalFinding {
  return Object.freeze({
    ...finding,
    title: boundExternalReportText(finding.title),
    description: boundExternalReportText(finding.description),
    primaryUrl: boundExternalReportText(finding.primaryUrl),
    impact: boundExternalReportText(finding.impact),
    remediation: boundExternalReportText(finding.remediation),
    limitations: Object.freeze(
      finding.limitations.map((item) => boundExternalReportText(item)),
    ),
    tags: Object.freeze([...finding.tags]),
    evidence: Object.freeze(
      finding.evidence.map((item) =>
        Object.freeze({
          kind: item.kind,
          summary: boundExternalReportText(item.summary),
          location: Object.freeze({
            kind: 'url' as const,
            url: boundExternalReportText(item.location.url),
          }),
          ...(item.redactedSnippet !== undefined
            ? { redactedSnippet: boundExternalReportText(item.redactedSnippet) }
            : {}),
        }),
      ),
    ),
  })
}
