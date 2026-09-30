import { isProxy } from 'node:util/types'

export class UnsafeStructureError extends Error {
  constructor() {
    super('Unsafe or non-canonical data structure was rejected.')
    this.name = 'UnsafeStructureError'
  }
}

/**
 * Walks canonical JSON data without reading properties through ordinary property
 * access. Accessors, custom prototypes, sparse arrays, symbols, cycles, and values
 * unsupported by JSON are rejected.
 */
export function walkCanonicalStrings(
  value: unknown,
  visit: (value: string) => void,
): void {
  walk(value, visit, new WeakSet())
}

function walk(
  value: unknown,
  visit: (value: string) => void,
  ancestors: WeakSet<object>,
): void {
  if (typeof value === 'string') {
    visit(value)
    return
  }
  if (value === null || typeof value === 'boolean') return
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new UnsafeStructureError()
    return
  }
  if (typeof value !== 'object') throw new UnsafeStructureError()
  if (isProxy(value)) throw new UnsafeStructureError()

  if (ancestors.has(value)) throw new UnsafeStructureError()
  ancestors.add(value)

  try {
    if (Array.isArray(value)) {
      walkArray(value, visit, ancestors)
    } else {
      walkObject(value, visit, ancestors)
    }
  } catch (error) {
    if (error instanceof UnsafeStructureError) throw error
    throw new UnsafeStructureError()
  } finally {
    ancestors.delete(value)
  }
}

function walkArray(
  value: readonly unknown[],
  visit: (value: string) => void,
  ancestors: WeakSet<object>,
): void {
  if (Reflect.getPrototypeOf(value) !== Array.prototype) {
    throw new UnsafeStructureError()
  }

  const keys = Reflect.ownKeys(value)
  if (keys.some((key) => typeof key === 'symbol')) throw new UnsafeStructureError()

  const lengthDescriptor = Reflect.getOwnPropertyDescriptor(value, 'length')
  if (!isDataDescriptor(lengthDescriptor)) {
    throw new UnsafeStructureError()
  }
  const { value: length } = lengthDescriptor
  if (typeof length !== 'number') throw new UnsafeStructureError()
  const numericKeys = keys
    .filter((key): key is string => typeof key === 'string' && key !== 'length')
    .sort((left, right) => Number(left) - Number(right))

  if (
    numericKeys.length !== length ||
    numericKeys.some((key, index) => key !== String(index))
  ) {
    throw new UnsafeStructureError()
  }

  for (const key of numericKeys) {
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key)
    if (!isDataDescriptor(descriptor)) {
      throw new UnsafeStructureError()
    }
    walk(descriptor.value, visit, ancestors)
  }
}

function walkObject(
  value: object,
  visit: (value: string) => void,
  ancestors: WeakSet<object>,
): void {
  const prototype = Reflect.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    throw new UnsafeStructureError()
  }

  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === 'symbol') throw new UnsafeStructureError()
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key)
    if (!isDataDescriptor(descriptor) || !descriptor.enumerable) {
      throw new UnsafeStructureError()
    }
    walk(descriptor.value, visit, ancestors)
  }
}

type UnknownDataDescriptor = Omit<PropertyDescriptor, 'value' | 'get' | 'set'> & {
  value: unknown
  get?: never
  set?: never
}

function isDataDescriptor(
  descriptor: PropertyDescriptor | undefined,
): descriptor is UnknownDataDescriptor {
  return (
    descriptor !== undefined &&
    Object.prototype.hasOwnProperty.call(descriptor, 'value') &&
    descriptor.get === undefined &&
    descriptor.set === undefined
  )
}
