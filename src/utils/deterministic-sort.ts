import type { Finding } from '../core/models/finding.js'
import type { Evidence } from '../core/models/evidence.js'

export class DuplicateFindingIdError extends Error {
  constructor() {
    super('Duplicate finding IDs are not allowed in a finalized scan.')
    this.name = 'DuplicateFindingIdError'
  }
}

export function compareCanonicalStrings(left: string, right: string): number {
  const normalizedLeft = left.normalize('NFC')
  const normalizedRight = right.normalize('NFC')
  if (normalizedLeft < normalizedRight) return -1
  if (normalizedLeft > normalizedRight) return 1
  return left < right ? -1 : left > right ? 1 : 0
}

export function compareFindings(left: Finding, right: Finding): number {
  return compareCanonicalStrings(left.id, right.id)
}

export function sortFindings(findings: readonly Finding[]): readonly Finding[] {
  const sorted = [...findings].sort(compareFindings)
  for (let index = 1; index < sorted.length; index += 1) {
    if (sorted[index - 1]?.id === sorted[index]?.id) {
      throw new DuplicateFindingIdError()
    }
  }
  return Object.freeze(sorted)
}

export function sortEvidence(evidence: readonly Evidence[]): readonly Evidence[] {
  return Object.freeze(
    [...evidence].sort((left, right) =>
      compareCanonicalStrings(evidenceKey(left), evidenceKey(right)),
    ),
  )
}

export function sortUniqueStrings(values: readonly string[]): readonly string[] {
  return Object.freeze(
    [...new Set(values.map((value) => value.normalize('NFC')))].sort(
      compareCanonicalStrings,
    ),
  )
}

function evidenceKey(evidence: Evidence): string {
  return JSON.stringify([
    evidence.kind,
    evidence.summary.normalize('NFC'),
    evidence.redactedSnippet?.normalize('NFC') ?? '',
    evidence.secretFingerprint ?? '',
    evidence.locations.map((location) => [
      location.file.normalize('NFC'),
      location.startLine,
      location.startColumn ?? 0,
      location.endLine ?? 0,
      location.endColumn ?? 0,
    ]),
  ])
}
