export { scanLocalProject, LocalScanError } from './application/scan-local-project.js'
export type {
  LocalScanOptions,
  LocalScanResult,
  ReportFormat,
} from './application/scan-local-project.js'
export {
  FINDING_CONFIDENCES,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
} from './core/models/finding.js'
export { FACT_KINDS } from './core/models/fact.js'
export type {
  Finding,
  FindingConfidence,
  FindingSeverity,
  FindingStatus,
} from './core/models/finding.js'
export type {
  AuthGuardFact,
  ClientQueryFact,
  DangerousSinkFact,
  EnvironmentBindingFact,
  Fact,
  FactContext,
  FactKind,
  FactSource,
  GitFileFact,
  SecretCandidateFact,
  StackFact,
  SupabasePolicyFact,
  SupabaseRlsFact,
  SupabaseTableFact,
} from './core/models/fact.js'
export type { Evidence, EvidenceDraft, EvidenceKind } from './core/models/evidence.js'
export {
  compareSourceLocations,
  createSourceLocation,
} from './core/models/source-location.js'
export type { SourceLocation } from './core/models/source-location.js'
export type {
  ScanReportDocument,
  ScanReportSummary,
} from './core/models/scan-report.js'
export type { FindingDraft, Rule, RuleMetadata } from './core/rules/rule.js'
export type { RuleContext } from './core/rules/rule-context.js'
export {
  ScanKernelContext,
  ScanKernelLifecycleError,
} from './core/scan/scan-kernel-context.js'
export type {
  ScanKernelOptions,
  ScanKernelState,
} from './core/scan/scan-kernel-context.js'
export { KernelValidationError } from './core/validation/primitives.js'
export { UnsafeOutputError } from './security/redaction.js'
export type { RedactionOptions } from './security/redaction.js'
export type {
  IssuedSecretFingerprint,
  ProtectedSensitiveValue,
  SafeOutput,
  SanitizedText,
} from './security/tokens.js'
export { DuplicateFindingIdError } from './utils/deterministic-sort.js'
export { normalizeRelativePath, toTargetRelativePath } from './utils/paths.js'
export type { PathFlavor } from './utils/paths.js'
