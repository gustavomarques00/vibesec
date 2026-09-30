import type { ExternalFinding, ExternalScanResult } from './result.js'
import { boundExternalReportText } from './safe-text.js'

const SCOPE_LINE =
  'Passive bounded analysis of the publicly observable surface (no auth, exploitation, fuzzing, or crawling).'

/**
 * Human-readable External terminal report.
 * Pure formatting — no rule evaluation or network.
 */
export function renderExternalTerminalReport(result: ExternalScanResult): string {
  const { summary } = result
  const lines = [
    'VibeSec External',
    '',
    `Target: ${boundExternalReportText(result.target)}`,
    `Effective URL: ${boundExternalReportText(result.effectiveUrl)}`,
    `Findings: ${String(summary.total)}`,
    `Critical: ${String(summary.critical)} | High: ${String(summary.high)} | Medium: ${String(summary.medium)} | Low: ${String(summary.low)} | Info: ${String(summary.info)}`,
    SCOPE_LINE,
  ]

  if (summary.total === 0) {
    lines.push('', 'No findings detected by this scan.')
  } else {
    for (const finding of result.findings) {
      lines.push('', ...formatFinding(finding))
    }
  }

  if (result.limitations.length > 0) {
    lines.push('', 'Limitations:')
    for (const limitation of result.limitations) {
      lines.push(`- ${boundExternalReportText(limitation)}`)
    }
  }

  return `${lines.join('\n')}\n`
}

function formatFinding(finding: ExternalFinding): string[] {
  const lines = [
    `[${finding.severity.toUpperCase()}] ${boundExternalReportText(finding.ruleId)}`,
    boundExternalReportText(finding.title),
    boundExternalReportText(finding.description),
    boundExternalReportText(finding.primaryUrl),
  ]
  for (const evidence of finding.evidence) {
    lines.push(`Evidence: ${boundExternalReportText(evidence.summary)}`)
  }
  return lines
}
