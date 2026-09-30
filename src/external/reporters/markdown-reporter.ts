import type { ExternalFinding, ExternalScanResult } from './result.js'
import { boundExternalMarkdownText } from './safe-text.js'

const SCOPE_LINE =
  'VibeSec External performs passive, bounded analysis of the publicly observable surface. It does not perform authentication, exploitation, fuzzing, brute force, or indiscriminate crawling.'

/**
 * Deterministic External Markdown report.
 * Pure formatting — no rule evaluation or network.
 */
export function renderExternalMarkdownReport(result: ExternalScanResult): string {
  const { summary } = result
  const lines = [
    '# VibeSec External Security Report',
    '',
    `- Target: \`${boundExternalMarkdownText(result.target)}\``,
    `- Effective URL: \`${boundExternalMarkdownText(result.effectiveUrl)}\``,
    `- Findings: ${String(summary.total)}`,
    `- Critical: ${String(summary.critical)}`,
    `- High: ${String(summary.high)}`,
    `- Medium: ${String(summary.medium)}`,
    `- Low: ${String(summary.low)}`,
    `- Info: ${String(summary.info)}`,
    '',
    SCOPE_LINE,
  ]

  lines.push('', '## Findings')

  if (summary.total === 0) {
    lines.push('', 'No findings detected by this scan.')
  } else {
    for (const finding of result.findings) {
      lines.push('', ...formatFinding(finding))
    }
  }

  lines.push('', '## Limitations')
  if (result.limitations.length === 0) {
    lines.push('', 'No scan limitations were recorded for this run.')
  } else {
    for (const limitation of result.limitations) {
      lines.push(`- ${boundExternalMarkdownText(limitation)}`)
    }
  }

  return `${lines.join('\n')}\n`
}

function formatFinding(finding: ExternalFinding): string[] {
  const lines = [
    `### ${boundExternalMarkdownText(finding.ruleId)} — ${boundExternalMarkdownText(finding.title)}`,
    '',
    `- Severity: ${finding.severity}`,
    `- URL: \`${boundExternalMarkdownText(finding.primaryUrl)}\``,
    `- Observation: ${boundExternalMarkdownText(finding.description)}`,
  ]
  for (const evidence of finding.evidence) {
    lines.push(`- Evidence: ${boundExternalMarkdownText(evidence.summary)}`)
  }
  return lines
}
