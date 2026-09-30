export {
  EXTERNAL_ACCEPT,
  EXTERNAL_ACCEPT_ENCODING,
  EXTERNAL_MAX_ADDRESS_ATTEMPTS,
  EXTERNAL_USER_AGENT,
  REDIRECT_STATUS_CODES,
} from './constants.js'

export { createNodeDnsResolver } from './dns-resolver.js'
export { createNodePinnedHttpConnector } from './node-connector.js'
export { createOutboundHttpCapability } from './orchestrator.js'
export type { OutboundHttpCapabilityDeps } from './orchestrator.js'
export {
  addressFamily,
  canonicalRemoteAddress,
  selectPinnedAddressOrder,
} from './pin-selection.js'
export { createProductionOutboundHttpCapability } from './production.js'

export {
  BlockedDestinationError,
  ConnectionFailedError,
  ConnectTimeoutError,
  DnsFailureError,
  ExternalTransportError,
  HeaderTooLargeError,
  InvalidExternalMethodError,
  OverallDeadlineExceededError,
  RedirectBlockedError,
  RedirectBudgetExceededError,
  RedirectLoopError,
  RemoteAddressMismatchError,
  RequestBudgetExceededError,
  ResponseTimeoutError,
  ResponseTooLargeError,
  TlsFailureError,
} from './errors.js'

export type {
  DnsLookupResult,
  DnsResolver,
  ExternalRawHeader,
  ExternalRawHopObservation,
  ExternalRawObservation,
  ExternalRawTlsMetadata,
  ExternalRequestContext,
  ExternalRequestPlan,
  OutboundHttpCapability,
  PinnedConnectRequest,
  PinnedConnectResponse,
  PinnedHttpConnector,
} from './types.js'
