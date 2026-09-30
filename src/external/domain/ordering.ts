import { compareCanonicalStrings } from '../../utils/deterministic-sort.js'

/**
 * Locale-independent string comparison for External collections that need
 * ordered identity (not sequence-preserving lists such as redirect hops).
 */
export function compareExternalStrings(left: string, right: string): number {
  return compareCanonicalStrings(left, right)
}

export function sortExternalStrings(values: readonly string[]): readonly string[] {
  return Object.freeze(
    [...new Set(values.map((value) => value.normalize('NFC')))].sort(
      compareExternalStrings,
    ),
  )
}
