import { spawn } from 'node:child_process'
import { lstat } from 'node:fs/promises'
import path from 'node:path'

import { normalizeRelativePath, type PathFlavor } from '../utils/paths.js'

export type GitFileStatus = 'tracked' | 'untracked' | 'ignored' | 'unknown'

export const DEFAULT_MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024
export const DEFAULT_GIT_TIMEOUT_MS = 10_000

export class GitProvenanceError extends Error {
  constructor() {
    super('Unable to resolve local Git provenance.')
    this.name = 'GitProvenanceError'
  }
}

export async function resolveGitProvenance(
  targetRoot: string,
  relativePaths: readonly string[],
  pathFlavor: PathFlavor,
  options: Readonly<{
    maxOutputBytes?: number
    timeoutMs?: number
  }> = {},
): Promise<ReadonlyMap<string, GitFileStatus>> {
  const result = new Map<string, GitFileStatus>()
  for (const relativePath of relativePaths) {
    result.set(normalizeRelativePath(relativePath, pathFlavor), 'unknown')
  }

  try {
    if (typeof targetRoot !== 'string' || targetRoot.length === 0) {
      return result
    }
    const root = path.resolve(targetRoot)
    const gitMeta = await lstat(path.join(root, '.git')).catch(() => undefined)
    if (gitMeta === undefined || (!gitMeta.isDirectory() && !gitMeta.isFile())) {
      return result
    }

    const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_GIT_OUTPUT_BYTES
    const timeoutMs = options.timeoutMs ?? DEFAULT_GIT_TIMEOUT_MS
    if (
      !Number.isSafeInteger(maxOutputBytes) ||
      maxOutputBytes < 1 ||
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 1
    ) {
      throw new GitProvenanceError()
    }

    const inside = await runGit(
      root,
      ['rev-parse', '--is-inside-work-tree'],
      maxOutputBytes,
      timeoutMs,
    )
    if (inside.code !== 0 || inside.stdout.toString('utf8').trim() !== 'true') {
      return result
    }

    const tracked = await listNulPaths(
      root,
      ['ls-files', '-z', '--cached'],
      maxOutputBytes,
      timeoutMs,
      pathFlavor,
    )
    const untracked = await listNulPaths(
      root,
      ['ls-files', '-z', '--others', '--exclude-standard'],
      maxOutputBytes,
      timeoutMs,
      pathFlavor,
    )
    const ignored = await listNulPaths(
      root,
      ['ls-files', '-z', '--others', '--ignored', '--exclude-standard'],
      maxOutputBytes,
      timeoutMs,
      pathFlavor,
    )

    for (const relativePath of result.keys()) {
      if (tracked.has(relativePath)) result.set(relativePath, 'tracked')
      else if (ignored.has(relativePath)) result.set(relativePath, 'ignored')
      else if (untracked.has(relativePath)) result.set(relativePath, 'untracked')
      else result.set(relativePath, 'unknown')
    }
    return result
  } catch {
    return result
  }
}

async function listNulPaths(
  cwd: string,
  args: readonly string[],
  maxOutputBytes: number,
  timeoutMs: number,
  pathFlavor: PathFlavor,
): Promise<ReadonlySet<string>> {
  const listed = await runGit(cwd, args, maxOutputBytes, timeoutMs)
  if (listed.code !== 0) throw new GitProvenanceError()
  const paths = new Set<string>()
  for (const entry of listed.stdout.toString('utf8').split('\0')) {
    if (entry.length === 0) continue
    paths.add(normalizeRelativePath(entry.replaceAll('\\', '/'), pathFlavor))
  }
  return paths
}

function runGit(
  cwd: string,
  args: readonly string[],
  maxOutputBytes: number,
  timeoutMs: number,
): Promise<Readonly<{ code: number; stdout: Buffer }>> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'git',
      ['-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never', ...args],
      {
        cwd,
        env: {
          PATH: process.env['PATH'],
          SystemRoot: process.env['SystemRoot'],
          GIT_TERMINAL_PROMPT: '0',
          GIT_OPTIONAL_LOCKS: '0',
          GIT_CONFIG_NOSYSTEM: '1',
          LANG: 'C',
          LC_ALL: 'C',
        },
        shell: false,
        windowsHide: true,
      },
    )

    const chunks: Buffer[] = []
    let total = 0
    let settled = false

    const finish = (error?: Error, code = 1): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error !== undefined) reject(error)
      else resolve({ code, stdout: Buffer.concat(chunks) })
    }

    const timer = setTimeout(() => {
      child.kill()
      finish(new GitProvenanceError())
    }, timeoutMs)

    child.stdout.on('data', (chunk: Buffer) => {
      total += chunk.length
      if (total > maxOutputBytes) {
        child.kill()
        finish(new GitProvenanceError())
        return
      }
      chunks.push(chunk)
    })
    child.stderr.on('data', () => {
      // Discard stderr: filenames or paths must not leak into errors.
    })
    child.on('error', () => finish(new GitProvenanceError()))
    child.on('close', (code) => finish(undefined, code ?? 1))
  })
}
