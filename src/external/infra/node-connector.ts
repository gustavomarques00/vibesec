import http from 'node:http'
import https from 'node:https'
import type { IncomingMessage, RequestOptions } from 'node:http'
import type { PeerCertificate } from 'node:tls'

import {
  EXTERNAL_ACCEPT,
  EXTERNAL_ACCEPT_ENCODING,
  EXTERNAL_USER_AGENT,
} from './constants.js'
import {
  ConnectionFailedError,
  ConnectTimeoutError,
  HeaderTooLargeError,
  OverallDeadlineExceededError,
  RemoteAddressMismatchError,
  ResponseTimeoutError,
  ResponseTooLargeError,
  TlsFailureError,
} from './errors.js'
import { addressFamily, canonicalRemoteAddress } from './pin-selection.js'
import type {
  ExternalRawHeader,
  PinnedConnectRequest,
  PinnedConnectResponse,
  PinnedHttpConnector,
} from './types.js'

interface LookupCallback {
  (error: NodeJS.ErrnoException | null, address: string, family: number): void
  (
    error: NodeJS.ErrnoException | null,
    addresses: readonly { address: string; family: number }[],
  ): void
}

/**
 * Production pinned HTTP(S) connector.
 *
 * Connects via a custom dns.lookup that returns ONLY the pinned address
 * (no second uncontrolled hostname resolution). Original hostname is preserved
 * for Host and TLS SNI. Certificate verification remains enabled.
 *
 * Does not honor HTTP_PROXY / HTTPS_PROXY / ALL_PROXY (Node http(s) built-ins
 * do not apply ambient proxy env by default; we also avoid undici/fetch).
 */
export function createNodePinnedHttpConnector(): PinnedHttpConnector {
  return Object.freeze({
    connect(request: PinnedConnectRequest): Promise<PinnedConnectResponse> {
      return performPinnedRequest(request)
    },
  })
}

function performPinnedRequest(
  request: PinnedConnectRequest,
): Promise<PinnedConnectResponse> {
  return new Promise((resolve, reject) => {
    let settled = false
    const timers: {
      connect: NodeJS.Timeout | undefined
      response: NodeJS.Timeout | undefined
    } = { connect: undefined, response: undefined }
    let req: http.ClientRequest | undefined

    const fail = (error: Error): void => {
      if (settled) return
      settled = true
      clearTimer(timers.connect)
      clearTimer(timers.response)
      req?.destroy()
      reject(error)
    }

    const succeed = (value: PinnedConnectResponse): void => {
      if (settled) return
      settled = true
      clearTimer(timers.connect)
      clearTimer(timers.response)
      resolve(value)
    }

    if (request.signal?.aborted) {
      fail(new OverallDeadlineExceededError())
      return
    }

    const onAbort = (): void => {
      fail(new OverallDeadlineExceededError())
    }
    request.signal?.addEventListener('abort', onAbort, { once: true })

    const family = addressFamily(request.pinnedAddress)
    const approved = new Set(
      request.approvedAddresses
        .map((address) => canonicalRemoteAddress(address))
        .filter((address): address is string => address !== undefined),
    )

    const lookup = (
      _hostname: string,
      options: unknown,
      callback: LookupCallback,
    ): void => {
      const all =
        typeof options === 'object' &&
        options !== null &&
        'all' in options &&
        (options as { all?: boolean }).all === true
      if (all) {
        callback(null, [{ address: request.pinnedAddress, family }])
        return
      }
      callback(null, request.pinnedAddress, family)
    }

    const options: RequestOptions = {
      protocol: `${request.scheme}:`,
      hostname: request.hostname,
      port: request.port,
      path: `${request.pathname}${request.search}`,
      method: request.method,
      headers: {
        Host: formatHostHeader(request.hostname, request.port, request.scheme),
        'User-Agent': EXTERNAL_USER_AGENT,
        Accept: EXTERNAL_ACCEPT,
        'Accept-Encoding': EXTERNAL_ACCEPT_ENCODING,
        Connection: 'close',
      },
      lookup: lookup as RequestOptions['lookup'],
      // Agent undefined → ephemeral connection; no pooling reuse surprises.
      agent: false,
      timeout: request.connectTimeoutMs,
    }

    if (request.scheme === 'https') {
      Object.assign(options, {
        servername: request.hostname,
        rejectUnauthorized: true,
      })
    }

    const transport = request.scheme === 'https' ? https : http

    try {
      req = transport.request(options, (response) => {
        clearTimer(timers.connect)
        void handleResponse(request, response, approved, succeed, fail)
      })
    } catch {
      fail(new ConnectionFailedError())
      return
    }

    timers.connect = setTimeout(() => {
      fail(new ConnectTimeoutError())
    }, request.connectTimeoutMs)

    timers.response = setTimeout(() => {
      fail(new ResponseTimeoutError())
    }, request.responseTimeoutMs)

    req.on('socket', (socket) => {
      socket.setTimeout(0)
      const verify = (): void => {
        const remote = canonicalRemoteAddress(socket.remoteAddress ?? '')
        if (remote === undefined || !approved.has(remote)) {
          socket.destroy()
          fail(new RemoteAddressMismatchError())
        }
      }
      if (socket.connecting) {
        socket.once('connect', verify)
      } else {
        verify()
      }
    })

    req.on('timeout', () => {
      fail(new ConnectTimeoutError())
    })

    req.on('error', (error: NodeJS.ErrnoException) => {
      if (
        error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
        error.code === 'CERT_HAS_EXPIRED'
      ) {
        fail(new TlsFailureError())
        return
      }
      if (
        typeof error.message === 'string' &&
        (error.message.includes('certificate') ||
          error.message.includes('SSL') ||
          error.message.includes('TLS'))
      ) {
        fail(new TlsFailureError())
        return
      }
      fail(new ConnectionFailedError())
    })

    // No request body. Never write payload.
    req.end()
  })
}

async function handleResponse(
  request: PinnedConnectRequest,
  response: IncomingMessage,
  approved: ReadonlySet<string>,
  succeed: (value: PinnedConnectResponse) => void,
  fail: (error: Error) => void,
): Promise<void> {
  try {
    const headerBytes = measureRawHeaderBytes(response)
    if (headerBytes > request.maxHeaderBytes) {
      response.destroy()
      fail(new HeaderTooLargeError())
      return
    }

    const contentLength = readContentLength(response.headers['content-length'])
    if (contentLength !== undefined && contentLength > request.maxResponseBytes) {
      response.destroy()
      fail(new ResponseTooLargeError())
      return
    }

    const remote =
      canonicalRemoteAddress(response.socket.remoteAddress ?? '') ??
      request.pinnedAddress
    if (!approved.has(remote)) {
      response.destroy()
      fail(new RemoteAddressMismatchError())
      return
    }

    const headers = freezeHeaders(response)
    const body = await readBodyBounded(response, request.maxResponseBytes)
    const tls = readTlsMetadata(request.scheme, response)

    succeed(
      Object.freeze({
        statusCode: response.statusCode ?? 0,
        headers,
        body,
        pinnedAddress: request.pinnedAddress,
        remoteAddress: remote,
        ...(tls !== undefined ? { tls } : {}),
      }),
    )
  } catch (error) {
    response.destroy()
    fail(error instanceof Error ? error : new ConnectionFailedError())
  }
}

function readBodyBounded(
  response: IncomingMessage,
  maxResponseBytes: number,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0

    response.on('data', (chunk: Buffer | string) => {
      const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : chunk
      total += buffer.length
      if (total > maxResponseBytes) {
        response.destroy()
        reject(new ResponseTooLargeError())
        return
      }
      chunks.push(buffer)
    })

    response.on('end', () => {
      resolve(new Uint8Array(Buffer.concat(chunks)))
    })

    response.on('error', () => {
      reject(new ConnectionFailedError())
    })
  })
}

function freezeHeaders(response: IncomingMessage): readonly ExternalRawHeader[] {
  const headers: ExternalRawHeader[] = []
  const raw = response.rawHeaders
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index]
    const value = raw[index + 1]
    if (name === undefined || value === undefined) continue
    headers.push(Object.freeze({ name, value }))
  }
  return Object.freeze(headers)
}

function measureRawHeaderBytes(response: IncomingMessage): number {
  let total = 0
  for (const part of response.rawHeaders) {
    total += Buffer.byteLength(part, 'utf8')
  }
  // Account for separators roughly (: and CRLF) without trusting Content-Length.
  total += response.rawHeaders.length * 2
  return total
}

function readContentLength(value: string | string[] | undefined): number | undefined {
  if (typeof value !== 'string') return undefined
  if (!/^\d+$/u.test(value)) return undefined
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < 0) return undefined
  return parsed
}

function readTlsMetadata(
  scheme: 'http' | 'https',
  response: IncomingMessage,
): PinnedConnectResponse['tls'] {
  if (scheme !== 'https') return undefined
  const socket = response.socket as IncomingMessage['socket'] & {
    authorized?: boolean
    authorizationError?: Error | null
    getProtocol?: () => string | false
    getPeerCertificate?: () => PeerCertificate
  }
  const authorized = socket.authorized === true
  const protocol = socket.getProtocol?.()
  const authorizationError =
    socket.authorizationError instanceof Error
      ? socket.authorizationError.message
      : undefined
  return Object.freeze({
    authorized,
    ...(typeof protocol === 'string' ? { protocol } : {}),
    ...(authorizationError !== undefined ? { authorizationError } : {}),
  })
}

function formatHostHeader(
  hostname: string,
  port: 80 | 443,
  scheme: 'http' | 'https',
): string {
  const host = hostname.includes(':') ? `[${hostname}]` : hostname
  const defaultPort = scheme === 'https' ? 443 : 80
  if (port === defaultPort) return host
  return `${host}:${String(port)}`
}

function clearTimer(timer: NodeJS.Timeout | undefined): void {
  if (timer !== undefined) clearTimeout(timer)
}
