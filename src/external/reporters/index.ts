import { renderExternalJsonReport } from './json-reporter.js'
import { renderExternalMarkdownReport } from './markdown-reporter.js'
import type { ExternalReportFormat, ExternalScanResult } from './result.js'
import { renderExternalTerminalReport } from './terminal-reporter.js'

export {
  createExternalScanResult,
  deriveExternalLimitations,
  summarizeExternalFindings,
} from './result.js'
export type {
  ExternalFindingSeveritySummary,
  ExternalJsonReportDocument,
  ExternalReportFormat,
  ExternalScanResult,
} from './result.js'

export {
  createExternalJsonReportDocument,
  renderExternalJsonReport,
} from './json-reporter.js'
export { renderExternalMarkdownReport } from './markdown-reporter.js'
export { renderExternalTerminalReport } from './terminal-reporter.js'
export {
  boundExternalMarkdownText,
  boundExternalReportText,
  EXTERNAL_REPORT_TEXT_MAX,
} from './safe-text.js'

/**
 * Format an ExternalScanResult for the requested output channel.
 * Reporters remain pure formatters.
 */
export function renderExternalReport(
  result: ExternalScanResult,
  format: ExternalReportFormat,
): string {
  switch (format) {
    case 'json':
      return renderExternalJsonReport(result)
    case 'markdown':
      return renderExternalMarkdownReport(result)
    case 'terminal':
      return renderExternalTerminalReport(result)
  }
}
