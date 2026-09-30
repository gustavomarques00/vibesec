import type { Finding } from '../core/models/finding.js'
import type { ScanReportSummary } from '../core/models/scan-report.js'
import { escapeDisplayText } from './display-text.js'

export function renderTerminalReport(
  summary: ScanReportSummary,
  findings: readonly Finding[],
): string {
  const lines = [
    'VibeSec local scan',
    `Target: ${escapeDisplayText(summary.target)}`,
    `Files scanned: ${String(summary.filesScanned)}`,
    `Files skipped: ${String(summary.filesSkipped)}`,
    `Findings: ${String(findings.length)}`,
  ]
  for (const finding of findings) {
    const location =
      finding.primaryLocation === undefined
        ? 'global'
        : `${escapeDisplayText(finding.primaryLocation.file)}:${String(finding.primaryLocation.startLine)}`
    lines.push(
      '',
      `[${finding.severity.toUpperCase()}] ${escapeDisplayText(finding.title)}`,
      `${finding.id} · ${location}`,
      escapeDisplayText(finding.description),
      `Status: ${finding.status}; confidence: ${finding.confidence}`,
      `Remediation: ${escapeDisplayText(finding.remediation)}`,
    )
  }
  return `${lines.join('\n')}\n`
}
