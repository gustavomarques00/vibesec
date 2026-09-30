import path from 'node:path'

export type PathFlavor = 'windows' | 'posix'

const WINDOWS_DRIVE_PATH = /^[A-Za-z]:/
const WINDOWS_UNC_OR_DEVICE_PATH = /^(?:\\\\|\/\/)/

/**
 * Canonicalizes a target-relative path for IDs and output.
 *
 * Absolute paths and paths escaping the target are rejected so host details cannot
 * accidentally become part of a finding.
 */
export function normalizeRelativePath(
  relativePath: string,
  flavor: PathFlavor,
): string {
  if (relativePath.length === 0 || relativePath.includes('\0')) {
    throw new Error('A source path must not be empty.')
  }

  const unicodeNormalized = relativePath.normalize('NFC')
  if (flavor === 'windows') {
    if (
      WINDOWS_DRIVE_PATH.test(unicodeNormalized) ||
      WINDOWS_UNC_OR_DEVICE_PATH.test(unicodeNormalized) ||
      path.win32.isAbsolute(unicodeNormalized)
    ) {
      throw new Error('A source path must be relative to the scan target.')
    }
  } else if (path.posix.isAbsolute(unicodeNormalized)) {
    throw new Error('A source path must be relative to the scan target.')
  }

  const separatorsNormalized =
    flavor === 'windows' ? unicodeNormalized.replaceAll('\\', '/') : unicodeNormalized
  const normalized = path.posix.normalize(separatorsNormalized).replace(/^\.\//, '')
  if (normalized === '.' || normalized === '..' || normalized.startsWith('../')) {
    throw new Error('A source path must remain inside the scan target.')
  }

  return normalized
}

/**
 * Converts an absolute or relative source path into a canonical target-relative path.
 */
export function toTargetRelativePath(
  targetRoot: string,
  sourcePath: string,
  flavor: PathFlavor,
): string {
  const pathApi = flavor === 'windows' ? path.win32 : path.posix
  if (
    flavor === 'windows' &&
    (WINDOWS_UNC_OR_DEVICE_PATH.test(sourcePath.normalize('NFC')) ||
      WINDOWS_UNC_OR_DEVICE_PATH.test(targetRoot.normalize('NFC')) ||
      !path.win32.isAbsolute(targetRoot))
  ) {
    throw new Error('The Windows target path must be absolute and non-UNC.')
  }
  if (flavor === 'posix' && !path.posix.isAbsolute(targetRoot)) {
    throw new Error('The POSIX target path must be absolute.')
  }
  const relative = pathApi.isAbsolute(sourcePath)
    ? pathApi.relative(pathApi.resolve(targetRoot), pathApi.resolve(sourcePath))
    : sourcePath

  return normalizeRelativePath(relative, flavor)
}
