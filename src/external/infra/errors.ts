/**
 * Typed External transport errors (E1.3).
 * Messages are intentional and must not include response bodies or secrets.
 */

export class ExternalTransportError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'ExternalTransportError'
    this.code = code
  }
}

export class DnsFailureError extends ExternalTransportError {
  constructor() {
    super('DnsFailure', 'DNS resolution failed.')
    this.name = 'DnsFailureError'
  }
}

export class BlockedDestinationError extends ExternalTransportError {
  constructor() {
    super('BlockedDestination', 'The destination is not allowed.')
    this.name = 'BlockedDestinationError'
  }
}

export class ConnectTimeoutError extends ExternalTransportError {
  constructor() {
    super('ConnectTimeout', 'Connection timed out.')
    this.name = 'ConnectTimeoutError'
  }
}

export class ConnectionFailedError extends ExternalTransportError {
  constructor() {
    super('ConnectionFailed', 'Connection failed.')
    this.name = 'ConnectionFailedError'
  }
}

export class RemoteAddressMismatchError extends ExternalTransportError {
  constructor() {
    super(
      'RemoteAddressMismatch',
      'Connected remote address did not match the approved pin set.',
    )
    this.name = 'RemoteAddressMismatchError'
  }
}

export class TlsFailureError extends ExternalTransportError {
  constructor() {
    super('TlsFailure', 'TLS handshake or certificate verification failed.')
    this.name = 'TlsFailureError'
  }
}

export class RedirectBlockedError extends ExternalTransportError {
  constructor() {
    super('RedirectBlocked', 'Redirect target was blocked by External policy.')
    this.name = 'RedirectBlockedError'
  }
}

export class RedirectLoopError extends ExternalTransportError {
  constructor() {
    super('RedirectLoop', 'Redirect loop detected.')
    this.name = 'RedirectLoopError'
  }
}

export class RedirectBudgetExceededError extends ExternalTransportError {
  constructor() {
    super('RedirectBudgetExceeded', 'Redirect budget exceeded.')
    this.name = 'RedirectBudgetExceededError'
  }
}

export class RequestBudgetExceededError extends ExternalTransportError {
  constructor() {
    super('RequestBudgetExceeded', 'Request budget exceeded.')
    this.name = 'RequestBudgetExceededError'
  }
}

export class ResponseTimeoutError extends ExternalTransportError {
  constructor() {
    super('ResponseTimeout', 'Response timed out.')
    this.name = 'ResponseTimeoutError'
  }
}

export class ResponseTooLargeError extends ExternalTransportError {
  constructor() {
    super('ResponseTooLarge', 'Response body exceeded the configured byte limit.')
    this.name = 'ResponseTooLargeError'
  }
}

export class HeaderTooLargeError extends ExternalTransportError {
  constructor() {
    super('HeaderTooLarge', 'Response headers exceeded the configured byte limit.')
    this.name = 'HeaderTooLargeError'
  }
}

export class OverallDeadlineExceededError extends ExternalTransportError {
  constructor() {
    super('OverallDeadlineExceeded', 'Overall External request deadline exceeded.')
    this.name = 'OverallDeadlineExceededError'
  }
}

export class InvalidExternalMethodError extends ExternalTransportError {
  constructor() {
    super('InvalidMethod', 'Only GET and HEAD methods are permitted.')
    this.name = 'InvalidExternalMethodError'
  }
}
