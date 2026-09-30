import type { Finding } from '../core/models/finding.js'
import type { ScanReportSummary } from '../core/models/scan-report.js'
import { escapeMarkdownText } from './display-text.js'

export function renderMarkdownReport(
  summary: ScanReportSummary,
  findings: readonly Finding[],
): string {
  const lines = [
    '# VibeSec local scan',
    '',
    `- Target: \`${escapeMarkdownText(summary.target)}\``,
    `- Files scanned: ${String(summary.filesScanned)}`,
    `- Files skipped: ${String(summary.filesSkipped)}`,
    `- Findings: ${String(findings.length)}`,
  ]
  for (const finding of findings) {
    const location =
      finding.primaryLocation === undefined
        ? 'global'
        : `${escapeMarkdownText(finding.primaryLocation.file)}:${String(finding.primaryLocation.startLine)}`
    lines.push(
      '',
      `## ${escapeMarkdownText(finding.title)}`,
      '',
      `- ID: \`${finding.id}\``,
      `- Severity: ${finding.severity}`,
      `- Status: ${finding.status}`,
      `- Confidence: ${finding.confidence}`,
      `- Location: \`${location}\``,
      '',
      escapeMarkdownText(finding.description),
      '',
      `**Remediation:** ${escapeMarkdownText(finding.remediation)}`,
    )
  }
  return `${lines.join('\n')}\n`
}
