import type { ExternalScanBudgets } from '../domain/budgets.js'
import {
  InvalidExternalTargetError,
  UnsupportedExternalPortError,
  UnsupportedExternalSchemeError,
} from '../domain/errors.js'
import type {
  ExternalHttpMethod,
  ExternalRedirectObservation,
} from '../domain/observations.js'
import {
  isSameExternalOrigin,
  normalizeExternalTarget,
  type ExternalOrigin,
  type NormalizedExternalTarget,
} from '../domain/target.js'
import {
  evaluateNormalizedDestination,
  evaluateResolvedAddressSet,
} from '../policy/destination-policy.js'
import { parseIpAddress } from '../policy/ip-address.js'
import { EXTERNAL_MAX_ADDRESS_ATTEMPTS, REDIRECT_STATUS_CODES } from './constants.js'
import {
  BlockedDestinationError,
  ConnectionFailedError,
  DnsFailureError,
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
import { selectPinnedAddressOrder } from './pin-selection.js'
import type {
  DnsResolver,
  ExternalRawHopObservation,
  ExternalRawObservation,
  ExternalRequestContext,
  ExternalRequestPlan,
  OutboundHttpCapability,
  PinnedHttpConnector,
} from './types.js'

export type OutboundHttpCapabilityDeps = Readonly<{
  resolveDns: DnsResolver
  connect: PinnedHttpConnector
  nowMs?: () => number
}>

/**
 * Creates the External outbound HTTP capability with injectable DNS/connector.
 * Production wiring uses Node implementations; tests use fakes.
 */
export function createOutboundHttpCapability(
  deps: OutboundHttpCapabilityDeps,
): OutboundHttpCapability {
  const nowMs = deps.nowMs ?? (() => Date.now())

  return Object.freeze({
    async request(
      plan: ExternalRequestPlan,
      context: ExternalRequestContext,
    ): Promise<ExternalRawObservation> {
      assertMethod(plan.method)
      const budgets = context.budgets
      const effectiveMaxRequests = resolveEffectiveMaxRequests(budgets, context)
      const startedAt = nowMs()
      const deadlineAt = startedAt + budgets.overallDeadlineMs

      const initial = resolvePlanTarget(plan.target)
      const hops: ExternalRawHopObservation[] = []
      const redirects: ExternalRedirectObservation[] = []
      const visited = new Set<string>([initial.requestUrl])

      let current = initial
      let method = plan.method
      let requestsUsed = 0
      let redirectsUsed = 0

      for (;;) {
        assertWithinDeadline(deadlineAt, nowMs, context.signal)

        if (requestsUsed >= effectiveMaxRequests) {
          throw new RequestBudgetExceededError()
        }

        const authorized = await authorizeDestination(
          current,
          deps.resolveDns,
          deadlineAt,
          nowMs,
          context.signal,
        )

        const attemptOrder = selectPinnedAddressOrder(
          authorized.approved,
          EXTERNAL_MAX_ADDRESS_ATTEMPTS,
        )

        if (attemptOrder.length === 0) {
          throw new BlockedDestinationError()
        }

        const hop = await attemptPinnedConnections({
          target: current,
          method,
          attemptOrder,
          approvedAddresses: authorized.approved,
          budgets,
          effectiveMaxRequests,
          deadlineAt,
          nowMs,
          signal: context.signal,
          connect: deps.connect,
          requestsUsed,
        })
        requestsUsed = hop.requestsUsed
        hops.push(hop.observation)

        if (!REDIRECT_STATUS_CODES.has(hop.observation.statusCode)) {
          return Object.freeze({
            initialRequestUrl: initial.requestUrl,
            finalUrl: current.requestUrl,
            method: plan.method,
            hops: Object.freeze([...hops]),
            redirects: Object.freeze([...redirects]),
            requestsConsumed: requestsUsed,
          })
        }

        if (redirectsUsed >= budgets.maxRedirects) {
          throw new RedirectBudgetExceededError()
        }

        const location = findHeaderValue(hop.observation.headers, 'location')
        if (location === undefined || location.trim().length === 0) {
          throw new RedirectBlockedError()
        }

        let next: NormalizedExternalTarget
        try {
          next = normalizeRedirectTarget(current.requestUrl, location)
        } catch {
          throw new RedirectBlockedError()
        }

        if (current.scheme === 'https' && next.scheme === 'http') {
          throw new RedirectBlockedError()
        }

        if (
          context.sameOriginRedirects !== undefined &&
          !isSameOriginTarget(context.sameOriginRedirects, next)
        ) {
          throw new RedirectBlockedError()
        }

        if (visited.has(next.requestUrl)) {
          throw new RedirectLoopError()
        }
        visited.add(next.requestUrl)

        const staticDecision = evaluateNormalizedDestination(next)
        if (
          staticDecision.kind === 'BLOCKED_STATICALLY' ||
          staticDecision.kind === 'IP_DENIED' ||
          staticDecision.kind === 'INVALID'
        ) {
          throw new RedirectBlockedError()
        }

        redirects.push(
          Object.freeze({
            index: redirectsUsed,
            fromUrl: current.requestUrl,
            toUrl: next.requestUrl,
            statusCode: hop.observation.statusCode,
          }),
        )
        redirectsUsed += 1
        method = nextRedirectMethod(method, hop.observation.statusCode)
        current = next
      }
    },
  })
}

type AuthorizedAddresses = Readonly<{
  approved: readonly string[]
}>

async function authorizeDestination(
  target: NormalizedExternalTarget,
  resolveDns: DnsResolver,
  deadlineAt: number,
  nowMs: () => number,
  signal: AbortSignal | undefined,
): Promise<AuthorizedAddresses> {
  const staticDecision = evaluateNormalizedDestination(target)
  if (staticDecision.kind === 'BLOCKED_STATICALLY') {
    throw new BlockedDestinationError()
  }
  if (staticDecision.kind === 'IP_DENIED' || staticDecision.kind === 'INVALID') {
    throw new BlockedDestinationError()
  }

  if (staticDecision.kind === 'IP_ALLOWED') {
    const canonical =
      staticDecision.ip?.canonical ?? parseIpAddress(target.hostname)?.canonical
    if (canonical === undefined) throw new BlockedDestinationError()
    return Object.freeze({ approved: Object.freeze([canonical]) })
  }

  assertWithinDeadline(deadlineAt, nowMs, signal)
  let lookup
  try {
    lookup = await withDeadline(
      resolveDns.lookupAll(target.hostname),
      deadlineAt,
      nowMs,
      signal,
    )
  } catch (error) {
    if (
      error instanceof OverallDeadlineExceededError ||
      error instanceof DnsFailureError
    ) {
      throw error
    }
    throw new DnsFailureError()
  }

  const policy = evaluateResolvedAddressSet(target.hostname, lookup.addresses)
  if (policy.decision !== 'ALLOW') {
    throw new BlockedDestinationError()
  }

  const approved = Object.freeze(
    policy.approved
      .map((verdict) => verdict.canonical ?? verdict.input)
      .filter((address) => parseIpAddress(address) !== undefined),
  )
  if (approved.length === 0) throw new BlockedDestinationError()
  return Object.freeze({ approved })
}

async function attemptPinnedConnections(args: {
  target: NormalizedExternalTarget
  method: ExternalHttpMethod
  attemptOrder: readonly string[]
  approvedAddresses: readonly string[]
  budgets: ExternalScanBudgets
  effectiveMaxRequests: number
  deadlineAt: number
  nowMs: () => number
  signal: AbortSignal | undefined
  connect: PinnedHttpConnector
  requestsUsed: number
}): Promise<{
  observation: ExternalRawHopObservation
  requestsUsed: number
}> {
  let requestsUsed = args.requestsUsed
  let lastError: Error | undefined

  for (const pinnedAddress of args.attemptOrder) {
    assertWithinDeadline(args.deadlineAt, args.nowMs, args.signal)
    if (requestsUsed >= args.effectiveMaxRequests) {
      throw new RequestBudgetExceededError()
    }

    const remainingOverall = Math.max(0, args.deadlineAt - args.nowMs())
    const connectTimeoutMs = Math.min(args.budgets.connectTimeoutMs, remainingOverall)
    const responseTimeoutMs = Math.min(args.budgets.responseTimeoutMs, remainingOverall)
    if (connectTimeoutMs <= 0 || responseTimeoutMs <= 0) {
      throw new OverallDeadlineExceededError()
    }

    requestsUsed += 1
    try {
      const response = await args.connect.connect({
        scheme: args.target.scheme,
        hostname: args.target.hostname,
        port: args.target.port,
        pathname: args.target.pathname,
        search: args.target.search,
        method: args.method,
        pinnedAddress,
        approvedAddresses: args.approvedAddresses,
        maxResponseBytes: args.budgets.maxResponseBytes,
        maxHeaderBytes: args.budgets.maxHeaderBytes,
        connectTimeoutMs,
        responseTimeoutMs,
        ...(args.signal !== undefined ? { signal: args.signal } : {}),
      })

      return {
        requestsUsed,
        observation: Object.freeze({
          requestUrl: args.target.requestUrl,
          method: args.method,
          statusCode: response.statusCode,
          headers: response.headers,
          body: response.body,
          pinnedAddress: response.pinnedAddress,
          remoteAddress: response.remoteAddress,
          ...(response.tls !== undefined ? { tls: response.tls } : {}),
        }),
      }
    } catch (error) {
      lastError = error instanceof Error ? error : new ConnectionFailedError()
      if (
        error instanceof BlockedDestinationError ||
        error instanceof RequestBudgetExceededError ||
        error instanceof OverallDeadlineExceededError ||
        error instanceof RedirectBlockedError ||
        error instanceof RedirectLoopError ||
        error instanceof RedirectBudgetExceededError ||
        error instanceof RemoteAddressMismatchError ||
        error instanceof TlsFailureError ||
        error instanceof HeaderTooLargeError ||
        error instanceof ResponseTooLargeError ||
        error instanceof ResponseTimeoutError
      ) {
        throw error
      }
      // Connection/connect-timeout: try next approved address if any remain.
    }
  }

  throw lastError ?? new ConnectionFailedError()
}

function resolveEffectiveMaxRequests(
  budgets: ExternalScanBudgets,
  context: ExternalRequestContext,
): number {
  if (context.maxRequestsOverride === undefined) return budgets.maxRequests
  return Math.max(0, Math.min(budgets.maxRequests, context.maxRequestsOverride))
}

function isSameOriginTarget(
  origin: ExternalOrigin,
  target: NormalizedExternalTarget,
): boolean {
  return isSameExternalOrigin(origin, {
    scheme: target.scheme,
    hostname: target.hostname,
    port: target.port,
    origin: target.origin,
  })
}

function resolvePlanTarget(
  target: string | NormalizedExternalTarget,
): NormalizedExternalTarget {
  if (typeof target === 'string') {
    return normalizeExternalTarget(target)
  }
  return target
}

function normalizeRedirectTarget(
  currentUrl: string,
  location: string,
): NormalizedExternalTarget {
  let absolute: URL
  try {
    absolute = new URL(location, currentUrl)
  } catch {
    throw new RedirectBlockedError()
  }
  if (absolute.username !== '' || absolute.password !== '') {
    throw new RedirectBlockedError()
  }
  try {
    return normalizeExternalTarget(absolute.toString())
  } catch (error) {
    if (
      error instanceof UnsupportedExternalSchemeError ||
      error instanceof UnsupportedExternalPortError ||
      error instanceof InvalidExternalTargetError
    ) {
      throw new RedirectBlockedError()
    }
    throw new RedirectBlockedError()
  }
}

function nextRedirectMethod(
  current: ExternalHttpMethod,
  statusCode: number,
): ExternalHttpMethod {
  if (statusCode === 303) return 'GET'
  return current
}

function findHeaderValue(
  headers: readonly { name: string; value: string }[],
  name: string,
): string | undefined {
  const lower = name.toLowerCase()
  for (const header of headers) {
    if (header.name.toLowerCase() === lower) return header.value
  }
  return undefined
}

function assertMethod(method: ExternalHttpMethod): void {
  // Runtime guard for untyped/JS call sites; type system already restricts callers.
  const value = method as string
  if (value !== 'GET' && value !== 'HEAD') {
    throw new InvalidExternalMethodError()
  }
}

function assertWithinDeadline(
  deadlineAt: number,
  nowMs: () => number,
  signal: AbortSignal | undefined,
): void {
  if (signal?.aborted) throw new OverallDeadlineExceededError()
  if (nowMs() >= deadlineAt) throw new OverallDeadlineExceededError()
}

async function withDeadline<T>(
  promise: Promise<T>,
  deadlineAt: number,
  nowMs: () => number,
  signal: AbortSignal | undefined,
): Promise<T> {
  const remaining = deadlineAt - nowMs()
  if (remaining <= 0 || signal?.aborted) {
    throw new OverallDeadlineExceededError()
  }

  let timer: NodeJS.Timeout | undefined
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new OverallDeadlineExceededError())
        }, remaining)
        signal?.addEventListener(
          'abort',
          () => {
            reject(new OverallDeadlineExceededError())
          },
          { once: true },
        )
      }),
    ])
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}
