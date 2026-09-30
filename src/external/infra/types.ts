import type { ExternalScanBudgets } from '../domain/budgets.js'
import type {
  ExternalHttpMethod,
  ExternalRedirectObservation,
} from '../domain/observations.js'
import type { NormalizedExternalTarget } from '../domain/target.js'

export type ExternalRequestPlan = Readonly<{
  /** Absolute http(s) URL or bare host accepted by normalizeExternalTarget. */
  target: string | NormalizedExternalTarget
  method: ExternalHttpMethod
}>

export type ExternalRequestContext = Readonly<{
  budgets: ExternalScanBudgets
  /** Optional external abort; overall deadline still applies. */
  signal?: AbortSignal
}>

export type ExternalRawHeader = Readonly<{
  name: string
  value: string
}>

export type ExternalRawTlsMetadata = Readonly<{
  authorized: boolean
  protocol?: string
  authorizationError?: string
}>

/**
 * Bounded hop capture for later E1.4 observation extraction.
 * Body bytes are scan-lifecycle scoped and never logged by infra.
 */
export type ExternalRawHopObservation = Readonly<{
  requestUrl: string
  method: ExternalHttpMethod
  statusCode: number
  headers: readonly ExternalRawHeader[]
  body: Uint8Array
  pinnedAddress: string
  remoteAddress: string
  tls?: ExternalRawTlsMetadata
}>

export type ExternalRawObservation = Readonly<{
  initialRequestUrl: string
  finalUrl: string
  method: ExternalHttpMethod
  hops: readonly ExternalRawHopObservation[]
  redirects: readonly ExternalRedirectObservation[]
}>

export type OutboundHttpCapability = Readonly<{
  request(
    plan: ExternalRequestPlan,
    context: ExternalRequestContext,
  ): Promise<ExternalRawObservation>
}>

export type DnsLookupResult = Readonly<{
  addresses: readonly string[]
}>

export type DnsResolver = Readonly<{
  lookupAll(hostname: string): Promise<DnsLookupResult>
}>

export type PinnedConnectRequest = Readonly<{
  scheme: 'http' | 'https'
  hostname: string
  port: 80 | 443
  pathname: string
  search: string
  method: ExternalHttpMethod
  /** Approved address actually used for TCP connect. */
  pinnedAddress: string
  /** All approved addresses for this hop (post-connect membership check). */
  approvedAddresses: readonly string[]
  maxResponseBytes: number
  maxHeaderBytes: number
  connectTimeoutMs: number
  responseTimeoutMs: number
  signal?: AbortSignal
}>

export type PinnedConnectResponse = Readonly<{
  statusCode: number
  headers: readonly ExternalRawHeader[]
  body: Uint8Array
  pinnedAddress: string
  remoteAddress: string
  tls?: ExternalRawTlsMetadata
}>

export type PinnedHttpConnector = Readonly<{
  connect(request: PinnedConnectRequest): Promise<PinnedConnectResponse>
}>
