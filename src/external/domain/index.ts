export {
  EXTERNAL_BUDGET_DEFAULTS,
  EXTERNAL_BUDGET_HARD_SAFETY_MAX,
  createExternalScanBudgets,
} from './budgets.js'
export type { ExternalScanBudgetOverrides, ExternalScanBudgets } from './budgets.js'

export {
  InvalidExternalBudgetError,
  InvalidExternalTargetError,
  UnsupportedExternalPortError,
  UnsupportedExternalSchemeError,
} from './errors.js'

export { EXTERNAL_EVIDENCE_KINDS } from './evidence.js'
export type {
  ExternalEvidenceDraft,
  ExternalEvidenceKind,
  ExternalEvidenceLocation,
} from './evidence.js'

export { createEmptyExternalObservationGraph } from './observations.js'
export type {
  ExternalAssetObservation,
  ExternalBlockedRedirectObservation,
  ExternalBlockedRedirectReason,
  ExternalCookieAttributeObservation,
  ExternalCookieSameSite,
  ExternalFactStatus,
  ExternalHeaderObservation,
  ExternalHstsObservation,
  ExternalHttpMethod,
  ExternalHttpResponseObservation,
  ExternalObservationGraph,
  ExternalRedirectObservation,
  ExternalSecurityHeaderId,
  ExternalSecurityHeaderObservation,
  ExternalTlsObservation,
} from './observations.js'

export { compareExternalStrings, sortExternalStrings } from './ordering.js'

export { normalizeExternalTarget, toExternalOrigin } from './target.js'
export type {
  ExternalOrigin,
  ExternalScheme,
  ExternalTargetInput,
  NormalizedExternalTarget,
} from './target.js'
