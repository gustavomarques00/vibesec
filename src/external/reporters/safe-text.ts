import { escapeDisplayText, escapeMarkdownText } from '../../reporters/display-text.js'

/** Max characters for remote-influenced display fields in reporters. */
export const EXTERNAL_REPORT_TEXT_MAX = 200 as const

/**
 * Bound + control-sanitize remote-influenced text for terminal/JSON display fields.
 */
export function boundExternalReportText(
  value: string,
  max = EXTERNAL_REPORT_TEXT_MAX,
): string {
  const sanitized = escapeDisplayText(value)
  if (sanitized.length <= max) return sanitized
  return `${sanitized.slice(0, max - 1)}…`
}

/**
 * Bound + Markdown-escape remote-influenced text.
 */
export function boundExternalMarkdownText(
  value: string,
  max = EXTERNAL_REPORT_TEXT_MAX,
): string {
  const sanitized = escapeMarkdownText(value)
  if (sanitized.length <= max) return sanitized
  return `${sanitized.slice(0, max - 1)}…`
}

export { escapeDisplayText, escapeMarkdownText }
