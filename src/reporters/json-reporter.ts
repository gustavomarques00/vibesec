import type { Finding } from '../core/models/finding.js'
import type {
  ScanReportDocument,
  ScanReportSummary,
} from '../core/models/scan-report.js'

export function createJsonReportDocument(
  summary: ScanReportSummary,
  findings: readonly Finding[],
): ScanReportDocument {
  return Object.freeze({
    schemaVersion: '1',
    target: summary.target,
    filesScanned: summary.filesScanned,
    filesSkipped: summary.filesSkipped,
    findings,
  })
}
