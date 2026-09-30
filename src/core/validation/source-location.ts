import { createSourceLocation, type SourceLocation } from '../models/source-location.js'
import type { PathFlavor } from '../../utils/paths.js'
import {
  readExactObject,
  readNonEmptyString,
  readPositiveInteger,
} from './primitives.js'

const LOCATION_KEYS = [
  'file',
  'startLine',
  'startColumn',
  'endLine',
  'endColumn',
] as const

export function validateSourceLocation(
  value: unknown,
  flavor: PathFlavor,
): SourceLocation {
  const object = readExactObject(value, LOCATION_KEYS, ['file', 'startLine'])
  const startColumn =
    object['startColumn'] === undefined
      ? undefined
      : readPositiveInteger(object['startColumn'])
  const endLine =
    object['endLine'] === undefined ? undefined : readPositiveInteger(object['endLine'])
  const endColumn =
    object['endColumn'] === undefined
      ? undefined
      : readPositiveInteger(object['endColumn'])

  return createSourceLocation(
    {
      file: readNonEmptyString(object['file']),
      startLine: readPositiveInteger(object['startLine']),
      ...(startColumn === undefined ? {} : { startColumn }),
      ...(endLine === undefined ? {} : { endLine }),
      ...(endColumn === undefined ? {} : { endColumn }),
    },
    flavor,
  )
}
