import type { Finding } from './finding.js'

export type ReportFormat = 'terminal' | 'json' | 'markdown'

export type ScanReportSummary = Readonly<{
  target: string
  filesScanned: number
  filesSkipped: number
}>

export type ScanReportDocument = Readonly<{
  schemaVersion: '1'
  target: string
  filesScanned: number
  filesSkipped: number
  findings: readonly Finding[]
}>
