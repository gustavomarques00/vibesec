import type { RedactionBoundary } from '../../security/redaction.js'
import type { PathFlavor } from '../../utils/paths.js'
import { type Evidence, type EvidenceDraft } from '../models/evidence.js'
import {
  readArray,
  readEnum,
  readExactObject,
  readNonEmptyString,
} from './primitives.js'
import { validateSourceLocation } from './source-location.js'

const EVIDENCE_KINDS = ['code', 'config', 'migration', 'correlation'] as const

declare const validatedEvidenceDraftBrand: unique symbol

export type ValidatedEvidenceDraft = EvidenceDraft & {
  readonly [validatedEvidenceDraftBrand]: true
}

export function validateEvidenceDraft(
  value: unknown,
  boundary: RedactionBoundary,
  flavor: PathFlavor,
): ValidatedEvidenceDraft {
  const object = readExactObject(
    value,
    ['kind', 'summary', 'redactedSnippet', 'locations', 'secretFingerprint'],
    ['kind', 'summary', 'locations'],
  )
  const redactedSnippet = object['redactedSnippet']
  const secretFingerprint = object['secretFingerprint']

  if (redactedSnippet !== undefined) {
    boundary.assertSanitizedText(redactedSnippet)
  }
  if (secretFingerprint !== undefined) {
    boundary.assertFingerprint(secretFingerprint)
  }

  const draft: EvidenceDraft = Object.freeze({
    kind: readEnum(object['kind'], EVIDENCE_KINDS),
    summary: readNonEmptyString(object['summary']),
    ...(redactedSnippet === undefined ? {} : { redactedSnippet }),
    locations: Object.freeze(
      readArray(object['locations']).map((location) =>
        validateSourceLocation(location, flavor),
      ),
    ),
    ...(secretFingerprint === undefined ? {} : { secretFingerprint }),
  })

  return draft as ValidatedEvidenceDraft
}

export function validateEvidence(value: unknown, flavor: PathFlavor): Evidence {
  const object = readExactObject(
    value,
    ['kind', 'summary', 'redactedSnippet', 'locations', 'secretFingerprint'],
    ['kind', 'summary', 'locations'],
  )
  const redactedSnippet =
    object['redactedSnippet'] === undefined
      ? undefined
      : readNonEmptyString(object['redactedSnippet'])
  const secretFingerprint =
    object['secretFingerprint'] === undefined
      ? undefined
      : validateSerializedFingerprint(object['secretFingerprint'])

  return Object.freeze({
    kind: readEnum(object['kind'], EVIDENCE_KINDS),
    summary: readNonEmptyString(object['summary']),
    ...(redactedSnippet === undefined ? {} : { redactedSnippet }),
    locations: Object.freeze(
      readArray(object['locations']).map((location) =>
        validateSourceLocation(location, flavor),
      ),
    ),
    ...(secretFingerprint === undefined ? {} : { secretFingerprint }),
  })
}

function validateSerializedFingerprint(value: unknown): string {
  const fingerprint = readNonEmptyString(value)
  if (!/^hmac-sha256:[a-f0-9]{24}$/.test(fingerprint)) {
    throw new Error('Serialized fingerprint validation failed.')
  }
  return fingerprint
}
