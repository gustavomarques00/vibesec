import { createHmac, randomBytes } from 'node:crypto'
import { isProxy } from 'node:util/types'

import { walkCanonicalStrings } from './safe-object-walker.js'
import type {
  IssuedSecretFingerprint,
  ProtectedSensitiveValue,
  SafeOutput,
  SanitizedText,
} from './tokens.js'

const REDACTED = '[REDACTED]'
const FINGERPRINT_BYTES = 12

export class UnsafeOutputError extends Error {
  constructor() {
    super('Unsafe output was blocked by the VibeSec redaction boundary.')
    this.name = 'UnsafeOutputError'
  }
}

export type RedactionOptions = Readonly<{
  visiblePrefix?: number
}>

/**
 * Scan-scoped security boundary for all sensitive values.
 *
 * A single instance must be created per scan and shared by extraction, finalization,
 * error formatting, and output serialization.
 */
export class RedactionBoundary {
  readonly #hmacKey = randomBytes(32)
  readonly #knownRawValues = new Set<string>()
  readonly #knownJsonEscapedValues = new Set<string>()
  readonly #sanitizedTexts = new WeakMap<object, string>()
  readonly #fingerprints = new WeakMap<object, string>()
  readonly #protectedValues = new WeakSet()
  readonly #safeOutputs = new WeakMap<object, string>()
  #destroyed: boolean

  private constructor() {
    this.#destroyed = false
  }

  static create(): RedactionBoundary {
    return new RedactionBoundary()
  }

  protect(rawValue: string, options: RedactionOptions = {}): ProtectedSensitiveValue {
    this.#assertActive()
    if (rawValue.length === 0) {
      throw new Error('A sensitive value must not be empty.')
    }

    for (const variant of [
      rawValue,
      rawValue.normalize('NFC'),
      rawValue.normalize('NFD'),
    ]) {
      this.#knownRawValues.add(variant)
      this.#knownJsonEscapedValues.add(jsonEscape(variant))
    }

    const redacted = this.#issueSanitizedText(
      redactRawValue(rawValue, options.visiblePrefix ?? 0),
    )
    const fingerprint = this.#issueFingerprint(rawValue)
    const protectedValue = Object.freeze({ redacted, fingerprint })
    this.#protectedValues.add(protectedValue)
    return protectedValue
  }

  sanitizeText(text: string): SanitizedText {
    this.#assertActive()
    return this.#issueSanitizedText(this.#redactKnownValues(text))
  }

  assertProtectedValue(value: unknown): asserts value is ProtectedSensitiveValue {
    this.#assertActive()
    if (
      typeof value !== 'object' ||
      value === null ||
      !this.#protectedValues.has(value)
    ) {
      throw new UnsafeOutputError()
    }
  }

  assertSanitizedText(value: unknown): asserts value is SanitizedText {
    this.#assertActive()
    if (
      typeof value !== 'object' ||
      value === null ||
      !this.#sanitizedTexts.has(value)
    ) {
      throw new UnsafeOutputError()
    }
  }

  resolveSanitizedText(value: SanitizedText): string {
    this.assertSanitizedText(value)
    const resolved = this.#sanitizedTexts.get(value)
    if (resolved === undefined) throw new UnsafeOutputError()
    return resolved
  }

  assertFingerprint(value: unknown): asserts value is IssuedSecretFingerprint {
    this.#assertActive()
    if (typeof value !== 'object' || value === null || !this.#fingerprints.has(value)) {
      throw new UnsafeOutputError()
    }
  }

  resolveFingerprint(value: IssuedSecretFingerprint): string {
    this.assertFingerprint(value)
    const resolved = this.#fingerprints.get(value)
    if (resolved === undefined) throw new UnsafeOutputError()
    return resolved
  }

  assertCanonicalValueSafe(value: unknown): void {
    this.#assertActive()
    try {
      walkCanonicalStrings(value, (text) => this.#assertRawTextSafe(text))
    } catch (error) {
      if (error instanceof UnsafeOutputError) throw error
      throw new UnsafeOutputError()
    }
  }

  serializeCanonicalJson(value: unknown, space?: number): SafeOutput {
    this.assertCanonicalValueSafe(value)
    assertNoInheritedToJson()
    let serialized: string
    try {
      // This is deliberately the only serialization of the canonical DTO.
      serialized = JSON.stringify(value, undefined, space)
    } catch {
      throw new UnsafeOutputError()
    }
    this.#assertSerializedJsonSafe(serialized)
    return this.#issueSafeOutput(serialized)
  }

  authorizeOutput(output: string): SafeOutput {
    this.#assertActive()
    this.#assertRawTextSafe(output)
    this.#assertSerializedJsonSafe(output)
    return this.#issueSafeOutput(output)
  }

  readOutput(output: SafeOutput): string {
    this.#assertActive()
    const resolved = this.#safeOutputs.get(output)
    if (resolved === undefined) throw new UnsafeOutputError()
    return resolved
  }

  formatError(error: unknown): SafeOutput {
    this.#assertActive()
    const safe = readErrorDataProperties(error)
    return this.authorizeOutput(
      `${this.#redactKnownValues(safe.name)}: ${this.#redactKnownValues(safe.message)}`,
    )
  }

  destroy(): void {
    this.#assertActive()
    this.#knownRawValues.clear()
    this.#knownJsonEscapedValues.clear()
    this.#hmacKey.fill(0)
    this.#destroyed = true
  }

  #issueSanitizedText(text: string): SanitizedText {
    return issueOpaqueToken<SanitizedText>((token) => {
      this.#sanitizedTexts.set(token, text)
    })
  }

  #issueFingerprint(raw: string): IssuedSecretFingerprint {
    const digest = createHmac('sha256', this.#hmacKey).update(raw, 'utf8').digest()
    const serialized = `hmac-sha256:${digest
      .subarray(0, FINGERPRINT_BYTES)
      .toString('hex')}`
    return issueOpaqueToken<IssuedSecretFingerprint>((token) => {
      this.#fingerprints.set(token, serialized)
    })
  }

  #issueSafeOutput(output: string): SafeOutput {
    return issueOpaqueToken<SafeOutput>((token) => {
      this.#safeOutputs.set(token, output)
    })
  }

  #assertRawTextSafe(text: string): void {
    for (const raw of this.#knownRawValues) {
      if (text.includes(raw)) throw new UnsafeOutputError()
    }
  }

  #assertSerializedJsonSafe(serialized: string): void {
    this.#assertRawTextSafe(serialized)
    for (const escaped of this.#knownJsonEscapedValues) {
      if (serialized.includes(escaped)) throw new UnsafeOutputError()
    }
  }

  #redactKnownValues(text: string): string {
    let sanitized = text
    for (const raw of this.#knownRawValues) {
      sanitized = sanitized.replaceAll(raw, REDACTED)
    }
    return sanitized
  }

  #assertActive(): void {
    if (this.#destroyed) {
      throw new Error('The scan redaction boundary is closed.')
    }
  }
}

function redactRawValue(raw: string, requestedPrefix: number): string {
  const visiblePrefix = Math.max(0, Math.min(12, requestedPrefix))
  if (visiblePrefix === 0 || raw.length < visiblePrefix + 8) {
    return REDACTED
  }

  return `${raw.slice(0, visiblePrefix)}...████████`
}

function jsonEscape(raw: string): string {
  return JSON.stringify(raw).slice(1, -1)
}

function issueOpaqueToken<Token extends object>(
  register: (token: Token) => void,
): Token {
  // The cast is isolated to the issuer; runtime provenance is enforced by WeakMap.
  const token = Object.freeze(Object.create(null)) as Token
  register(token)
  return token
}

function readErrorDataProperties(error: unknown): { name: string; message: string } {
  const fallback = { name: 'Error', message: 'An unknown error occurred.' }
  if (typeof error !== 'object' || error === null || isProxy(error)) return fallback

  try {
    const descriptors = Object.getOwnPropertyDescriptors(error)
    const name = readOwnString(descriptors['name']) ?? fallback.name
    const message = readOwnString(descriptors['message']) ?? fallback.message
    return { name, message }
  } catch {
    return fallback
  }
}

function readOwnString(descriptor: PropertyDescriptor | undefined): string | undefined {
  return descriptor !== undefined &&
    'value' in descriptor &&
    typeof descriptor.value === 'string'
    ? descriptor.value
    : undefined
}

function assertNoInheritedToJson(): void {
  if (
    Reflect.getOwnPropertyDescriptor(Object.prototype, 'toJSON') !== undefined ||
    Reflect.getOwnPropertyDescriptor(Array.prototype, 'toJSON') !== undefined
  ) {
    throw new UnsafeOutputError()
  }
}
