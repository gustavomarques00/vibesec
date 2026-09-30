/**
 * Typed External transport errors (E1.3).
 * Messages are intentional and must not include response bodies or secrets.
 */

export class ExternalTransportError extends Error {
  readonly code: string
  /** Outbound attempts already consumed when the failure occurred (budget accounting). */
  readonly requestsConsumed?: number

  constructor(code: string, message: string, requestsConsumed?: number) {
    super(message)
    this.name = 'ExternalTransportError'
    this.code = code
    if (requestsConsumed !== undefined) {
      this.requestsConsumed = requestsConsumed
    }
  }
}

export class DnsFailureError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super('DnsFailure', 'DNS resolution failed.', requestsConsumed)
    this.name = 'DnsFailureError'
  }
}

export class BlockedDestinationError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super('BlockedDestination', 'The destination is not allowed.', requestsConsumed)
    this.name = 'BlockedDestinationError'
  }
}

export class ConnectTimeoutError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super('ConnectTimeout', 'Connection timed out.', requestsConsumed)
    this.name = 'ConnectTimeoutError'
  }
}

export class ConnectionFailedError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super('ConnectionFailed', 'Connection failed.', requestsConsumed)
    this.name = 'ConnectionFailedError'
  }
}

export class RemoteAddressMismatchError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super(
      'RemoteAddressMismatch',
      'Connected remote address did not match the approved pin set.',
      requestsConsumed,
    )
    this.name = 'RemoteAddressMismatchError'
  }
}

export class TlsFailureError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super(
      'TlsFailure',
      'TLS handshake or certificate verification failed.',
      requestsConsumed,
    )
    this.name = 'TlsFailureError'
  }
}

export class RedirectBlockedError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super(
      'RedirectBlocked',
      'Redirect target was blocked by External policy.',
      requestsConsumed,
    )
    this.name = 'RedirectBlockedError'
  }
}

export class RedirectLoopError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super('RedirectLoop', 'Redirect loop detected.', requestsConsumed)
    this.name = 'RedirectLoopError'
  }
}

export class RedirectBudgetExceededError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super('RedirectBudgetExceeded', 'Redirect budget exceeded.', requestsConsumed)
    this.name = 'RedirectBudgetExceededError'
  }
}

export class RequestBudgetExceededError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super('RequestBudgetExceeded', 'Request budget exceeded.', requestsConsumed)
    this.name = 'RequestBudgetExceededError'
  }
}

export class ResponseTimeoutError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super('ResponseTimeout', 'Response timed out.', requestsConsumed)
    this.name = 'ResponseTimeoutError'
  }
}

export class ResponseTooLargeError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super(
      'ResponseTooLarge',
      'Response body exceeded the configured byte limit.',
      requestsConsumed,
    )
    this.name = 'ResponseTooLargeError'
  }
}

export class HeaderTooLargeError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super(
      'HeaderTooLarge',
      'Response headers exceeded the configured byte limit.',
      requestsConsumed,
    )
    this.name = 'HeaderTooLargeError'
  }
}

export class OverallDeadlineExceededError extends ExternalTransportError {
  constructor(requestsConsumed?: number) {
    super(
      'OverallDeadlineExceeded',
      'Overall External request deadline exceeded.',
      requestsConsumed,
    )
    this.name = 'OverallDeadlineExceededError'
  }
}

export class InvalidExternalMethodError extends ExternalTransportError {
  constructor() {
    super('InvalidMethod', 'Only GET and HEAD methods are permitted.')
    this.name = 'InvalidExternalMethodError'
  }
}
