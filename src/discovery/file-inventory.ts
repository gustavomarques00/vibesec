import { lstat, readdir, realpath } from 'node:fs/promises'
import path from 'node:path'

import {
  readEnum,
  readExactObject,
  readPositiveInteger,
} from '../core/validation/primitives.js'
import { compareCanonicalStrings } from '../utils/deterministic-sort.js'
import { normalizeRelativePath, type PathFlavor } from '../utils/paths.js'
import { isIgnoredDirectoryName } from './ignore-policy.js'

export const DEFAULT_MAX_FILE_BYTES = 1024 * 1024
export const MAX_MAX_FILE_BYTES = 16 * 1024 * 1024
export const DEFAULT_MAX_FILES = 10_000
export const DEFAULT_MAX_ENTRIES = 50_000
export const DEFAULT_MAX_TOTAL_BYTES = 100 * 1024 * 1024

export type DiscoveredLocalFile = Readonly<{
  relativePath: string
  absolutePath: string
  size: number
  device: number
  inode: number
}>

export type LocalFileInventory = Readonly<{
  files: readonly DiscoveredLocalFile[]
  filesSkipped: number
  maxFileBytes: number
  targetRealPath: string
}>

export type FileInventoryOptions = Readonly<{
  pathFlavor: PathFlavor
  maxFileBytes?: number
}>

export class LocalInventoryError extends Error {
  constructor() {
    super('Unable to inventory the local target.')
    this.name = 'LocalInventoryError'
  }
}

export async function inventoryLocalFiles(
  targetRoot: string,
  options: FileInventoryOptions,
): Promise<LocalFileInventory> {
  try {
    if (typeof targetRoot !== 'string' || targetRoot.length === 0) {
      throw new LocalInventoryError()
    }
    const object = readExactObject(
      options,
      ['pathFlavor', 'maxFileBytes'],
      ['pathFlavor'],
    )
    const pathFlavor = readEnum(object['pathFlavor'], ['windows', 'posix'] as const)
    const nativeFlavor: PathFlavor = process.platform === 'win32' ? 'windows' : 'posix'
    if (pathFlavor !== nativeFlavor) throw new LocalInventoryError()
    const maxFileBytes =
      object['maxFileBytes'] === undefined
        ? DEFAULT_MAX_FILE_BYTES
        : readPositiveInteger(object['maxFileBytes'])
    if (maxFileBytes > MAX_MAX_FILE_BYTES) throw new LocalInventoryError()

    const root = path.resolve(targetRoot)
    const rootStat = await lstat(root)
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
      throw new LocalInventoryError()
    }
    const targetRealPath = await realpath(root)

    let filesSkipped = 0
    let entriesVisited = 0
    let totalBytes = 0
    const files: DiscoveredLocalFile[] = []
    const canonicalPaths = new Set<string>()

    const visit = async (
      directory: string,
      expectedDevice: number,
      expectedInode: number,
    ): Promise<void> => {
      await assertStableDirectory(
        directory,
        targetRealPath,
        expectedDevice,
        expectedInode,
      )
      const entries = await readdir(directory, { withFileTypes: true })
      entries.sort((left, right) => compareCanonicalStrings(left.name, right.name))

      for (const entry of entries) {
        entriesVisited += 1
        if (entriesVisited > DEFAULT_MAX_ENTRIES) throw new LocalInventoryError()
        await assertStableDirectory(
          directory,
          targetRealPath,
          expectedDevice,
          expectedInode,
        )
        if (entry.name.includes('\0')) {
          filesSkipped += 1
          continue
        }
        const absolutePath = path.join(directory, entry.name)
        const stat = await lstat(absolutePath)
        if (stat.isSymbolicLink()) {
          filesSkipped += 1
          continue
        }
        if (stat.isDirectory()) {
          if (isIgnoredDirectoryName(entry.name)) {
            filesSkipped += 1
          } else {
            await visit(absolutePath, stat.dev, stat.ino)
          }
          continue
        }
        if (!stat.isFile() || stat.size > maxFileBytes) {
          filesSkipped += 1
          continue
        }

        const absoluteRealPath = await realpath(absolutePath)
        assertContainedPath(targetRealPath, absoluteRealPath)
        const relativePath = normalizeRelativePath(
          path.relative(root, absolutePath),
          pathFlavor,
        )
        if (canonicalPaths.has(relativePath)) throw new LocalInventoryError()
        canonicalPaths.add(relativePath)
        totalBytes += stat.size
        if (files.length >= DEFAULT_MAX_FILES || totalBytes > DEFAULT_MAX_TOTAL_BYTES) {
          throw new LocalInventoryError()
        }
        files.push(
          Object.freeze({
            relativePath,
            absolutePath: absoluteRealPath,
            size: stat.size,
            device: stat.dev,
            inode: stat.ino,
          }),
        )
      }
      await assertStableDirectory(
        directory,
        targetRealPath,
        expectedDevice,
        expectedInode,
      )
    }

    await visit(root, rootStat.dev, rootStat.ino)
    return Object.freeze({
      files: Object.freeze(files),
      filesSkipped,
      maxFileBytes,
      targetRealPath,
    })
  } catch (error) {
    if (error instanceof LocalInventoryError) throw error
    throw new LocalInventoryError()
  }
}

async function assertStableDirectory(
  directory: string,
  targetRealPath: string,
  expectedDevice: number,
  expectedInode: number,
): Promise<void> {
  const stat = await lstat(directory)
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.dev !== expectedDevice ||
    stat.ino !== expectedInode
  ) {
    throw new LocalInventoryError()
  }
  assertContainedPath(targetRealPath, await realpath(directory))
}

export function assertContainedPath(
  targetRealPath: string,
  candidateRealPath: string,
): void {
  const relative = path.relative(targetRealPath, candidateRealPath)
  if (
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new LocalInventoryError()
  }
}
