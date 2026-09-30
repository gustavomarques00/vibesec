import { describe, expect, it } from 'vitest'

import {
  createSourceLocation,
  normalizeRelativePath,
  toTargetRelativePath,
} from '../src/index.js'

describe('cross-platform normalization and stable IDs', () => {
  it('normalizes Windows and POSIX paths to the same target-relative form', () => {
    expect(
      toTargetRelativePath('C:\\repo', 'C:\\repo\\src\\config.ts', 'windows'),
    ).toBe('src/config.ts')
    expect(toTargetRelativePath('/repo', '/repo/src/config.ts', 'posix')).toBe(
      'src/config.ts',
    )
    expect(normalizeRelativePath('.\\src\\config.ts', 'windows')).toBe('src/config.ts')
  })

  it('rejects absolute paths and target traversal in ID inputs', () => {
    expect(() =>
      normalizeRelativePath('C:\\Users\\person\\secret.ts', 'windows'),
    ).toThrow('relative')
    expect(() => normalizeRelativePath('../../outside.ts', 'posix')).toThrow('inside')
    expect(() => normalizeRelativePath('/home/person/secret.ts', 'posix')).toThrow(
      'relative',
    )
    expect(() => normalizeRelativePath('C:relative.ts', 'windows')).toThrow('relative')
    expect(() =>
      normalizeRelativePath('\\\\server\\share\\file.ts', 'windows'),
    ).toThrow('relative')
    expect(() => normalizeRelativePath('\\\\?\\C:\\repo\\file.ts', 'windows')).toThrow(
      'relative',
    )
    expect(() => normalizeRelativePath('.', 'posix')).toThrow('inside')
    expect(() => normalizeRelativePath('bad\0path', 'posix')).toThrow()
  })

  it('creates equivalent canonical locations for explicit platform flavors', () => {
    const windowsStyle = createSourceLocation(
      {
        file: 'src\\config.ts',
        startLine: 8,
      },
      'windows',
    )
    const posixStyle = createSourceLocation(
      {
        file: 'src/config.ts',
        startLine: 8,
      },
      'posix',
    )

    expect(windowsStyle).toEqual(posixStyle)
  })

  it('preserves a POSIX filename containing a backslash', () => {
    expect(normalizeRelativePath('src/name\\with-backslash.ts', 'posix')).toBe(
      'src/name\\with-backslash.ts',
    )
  })

  it('normalizes Unicode paths to NFC', () => {
    expect(normalizeRelativePath('src/cafe\u0301.ts', 'posix')).toBe('src/café.ts')
  })
})
