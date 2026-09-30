import { isProxy } from 'node:util/types'

export class KernelValidationError extends Error {
  constructor() {
    super('Kernel input failed runtime validation.')
    this.name = 'KernelValidationError'
  }
}

export function readOwnDataProperty(value: unknown, key: string): unknown {
  try {
    if (
      typeof value !== 'object' ||
      value === null ||
      isProxy(value) ||
      Array.isArray(value)
    ) {
      throw new KernelValidationError()
    }
    const prototype = Reflect.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      throw new KernelValidationError()
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    return readDescriptorValue(descriptor)
  } catch (error) {
    if (error instanceof KernelValidationError) throw error
    throw new KernelValidationError()
  }
}

export function readExactObject(
  value: unknown,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[],
): Readonly<Record<string, unknown>> {
  try {
    if (
      typeof value !== 'object' ||
      value === null ||
      isProxy(value) ||
      Array.isArray(value)
    ) {
      throw new KernelValidationError()
    }
    const prototype = Reflect.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      throw new KernelValidationError()
    }

    const ownKeys = Reflect.ownKeys(value)
    if (ownKeys.some((key) => typeof key === 'symbol')) {
      throw new KernelValidationError()
    }

    const keys = ownKeys.filter((key): key is string => typeof key === 'string')
    if (
      keys.some((key) => !allowedKeys.includes(key)) ||
      requiredKeys.some((key) => !keys.includes(key))
    ) {
      throw new KernelValidationError()
    }

    const result: Record<string, unknown> = {}
    for (const key of keys) {
      const descriptor = Reflect.getOwnPropertyDescriptor(value, key)
      result[key] = readDescriptorValue(descriptor)
    }
    return Object.freeze(result)
  } catch (error) {
    if (error instanceof KernelValidationError) throw error
    throw new KernelValidationError()
  }
}

export function readArray(value: unknown): readonly unknown[] {
  try {
    if (
      typeof value !== 'object' ||
      value === null ||
      isProxy(value) ||
      !Array.isArray(value) ||
      Reflect.getPrototypeOf(value) !== Array.prototype
    ) {
      throw new KernelValidationError()
    }
    const keys = Reflect.ownKeys(value)
    if (keys.some((key) => typeof key === 'symbol')) {
      throw new KernelValidationError()
    }
    const lengthDescriptor = Reflect.getOwnPropertyDescriptor(value, 'length')
    const length = readDescriptorValue(lengthDescriptor)
    if (typeof length !== 'number') throw new KernelValidationError()
    const numericKeys = keys
      .filter((key): key is string => typeof key === 'string')
      .filter((key) => key !== 'length')
      .sort((left, right) => Number(left) - Number(right))
    if (
      numericKeys.length !== length ||
      numericKeys.some((key, index) => key !== String(index))
    ) {
      throw new KernelValidationError()
    }
    const result = numericKeys.map((key) => {
      const descriptor = Reflect.getOwnPropertyDescriptor(value, key)
      return readDescriptorValue(descriptor)
    })
    return Object.freeze(result)
  } catch (error) {
    if (error instanceof KernelValidationError) throw error
    throw new KernelValidationError()
  }
}

export function readString(value: unknown): string {
  if (typeof value !== 'string') throw new KernelValidationError()
  return value.normalize('NFC')
}

export function readNonEmptyString(value: unknown): string {
  const text = readString(value)
  if (text.length === 0) throw new KernelValidationError()
  return text
}

export function readBoolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new KernelValidationError()
  return value
}

export function readPositiveInteger(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new KernelValidationError()
  }
  return value
}

export function readNonNegativeInteger(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new KernelValidationError()
  }
  return value
}

export function readEnum<const Values extends readonly string[]>(
  value: unknown,
  values: Values,
): Values[number] {
  if (typeof value === 'string') {
    for (const candidate of values) {
      if (candidate === value) return candidate
    }
  }
  throw new KernelValidationError()
}

export function readStringArray(value: unknown): readonly string[] {
  return Object.freeze(readArray(value).map(readString))
}

function readDescriptorValue(descriptor: PropertyDescriptor | undefined): unknown {
  if (
    descriptor === undefined ||
    !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
    descriptor.get !== undefined ||
    descriptor.set !== undefined
  ) {
    throw new KernelValidationError()
  }
  // PropertyDescriptor.value is `any` in lib.d.ts; downgrade it to unknown at
  // this validation boundary so callers must narrow it before use.
  return descriptor.value as unknown
}
