import { open, realpath } from 'node:fs/promises'

import type { Fact, GitFileFact } from '../core/models/fact.js'
import type { ScanKernelContext } from '../core/scan/scan-kernel-context.js'
import {
  assertContainedPath,
  inventoryLocalFiles,
  LocalInventoryError,
  type FileInventoryOptions,
} from '../discovery/file-inventory.js'
import { resolveGitProvenance } from '../targets/git-provenance.js'
import { isDotenvPath } from '../utils/dotenv-path.js'
import {
  extractDotenvFacts,
  extractClientPrefixBindingFacts,
} from './dotenv-extractor.js'
import {
  countGenericSecretCandidates,
  extractGenericSecretFacts,
} from './generic-secret-extractor.js'
import {
  countHighSpecificityCandidates,
  extractHighSpecificitySecretFacts,
} from './high-specificity-secret-extractor.js'
import {
  countPrivateKeyCandidates,
  extractPrivateKeyFacts,
} from './private-key-extractor.js'
import { extractSupabaseKeyFacts } from './supabase-key-extractor.js'
import { extractSupabaseSqlFacts } from './supabase-sql-extractor.js'
import { extractAuthGuardFacts } from './auth-guard-extractor.js'
import { extractClientQueryFacts } from './client-query-extractor.js'
import { extractDangerousSinkFacts } from './dangerous-sink-extractor.js'

export const DEFAULT_MAX_FACTS = 10_000

export type LocalScanExtraction = Readonly<{
  facts: readonly Fact[]
  filesScanned: number
  filesSkipped: number
}>

export type LocalPrivateKeyExtraction = Readonly<{
  facts: readonly Fact[]
  filesScanned: number
  filesSkipped: number
}>

export async function extractLocalScanFacts(
  scan: ScanKernelContext,
  targetRoot: string,
  options: FileInventoryOptions,
): Promise<LocalScanExtraction> {
  try {
    return await extractFromInventory(scan, targetRoot, options)
  } catch (error) {
    if (error instanceof LocalInventoryError) throw error
    throw new LocalInventoryError()
  }
}

/** @deprecated Prefer extractLocalScanFacts; retained for Phase 2 API compatibility. */
export async function extractPrivateKeyFactsFromLocalTarget(
  scan: ScanKernelContext,
  targetRoot: string,
  options: FileInventoryOptions,
): Promise<LocalPrivateKeyExtraction> {
  const extraction = await extractLocalScanFacts(scan, targetRoot, options)
  return Object.freeze({
    facts: Object.freeze(
      extraction.facts.filter((fact) => fact.kind === 'secret.candidate'),
    ),
    filesScanned: extraction.filesScanned,
    filesSkipped: extraction.filesSkipped,
  })
}

async function extractFromInventory(
  scan: ScanKernelContext,
  targetRoot: string,
  options: FileInventoryOptions,
): Promise<LocalScanExtraction> {
  const inventory = await inventoryLocalFiles(targetRoot, options)
  const relativePaths = inventory.files.map((file) => file.relativePath)
  const gitStatuses = await resolveGitProvenance(
    targetRoot,
    relativePaths,
    options.pathFlavor,
  )

  const facts: Fact[] = []
  let candidatesInspected = 0
  let filesScanned = 0
  let filesSkipped = inventory.filesSkipped

  for (const file of inventory.files) {
    assertContainedPath(inventory.targetRealPath, await realpath(file.absolutePath))
    const handle = await open(file.absolutePath, 'r')
    try {
      const openedStat = await handle.stat()
      if (
        !openedStat.isFile() ||
        openedStat.dev !== file.device ||
        openedStat.ino !== file.inode
      ) {
        throw new LocalInventoryError()
      }

      const buffer = Buffer.alloc(inventory.maxFileBytes + 1)
      let bytesRead = 0
      while (bytesRead < buffer.length) {
        const result = await handle.read(
          buffer,
          bytesRead,
          buffer.length - bytesRead,
          null,
        )
        if (result.bytesRead === 0) break
        bytesRead += result.bytesRead
      }
      const finalStat = await handle.stat()
      assertContainedPath(inventory.targetRealPath, await realpath(file.absolutePath))
      if (
        finalStat.dev !== file.device ||
        finalStat.ino !== file.inode ||
        finalStat.size !== file.size ||
        bytesRead !== file.size ||
        bytesRead > inventory.maxFileBytes
      ) {
        throw new LocalInventoryError()
      }
      const bytes = buffer.subarray(0, bytesRead)
      if (bytes.includes(0)) {
        filesSkipped += 1
        continue
      }
      let content: string
      try {
        content = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
      } catch {
        filesSkipped += 1
        continue
      }

      const remaining = DEFAULT_MAX_FACTS - candidatesInspected
      candidatesInspected += countPrivateKeyCandidates(content, remaining)
      candidatesInspected += countHighSpecificityCandidates(
        content,
        DEFAULT_MAX_FACTS - candidatesInspected,
      )
      candidatesInspected += countGenericSecretCandidates(
        content,
        DEFAULT_MAX_FACTS - candidatesInspected,
      )

      const privateKeys = extractPrivateKeyFacts(scan, file.relativePath, content)
      const dotenv = extractDotenvFacts(scan, file.relativePath, content)
      const dotenvFirst = isDotenvPath(file.relativePath)
      const seedOccupied = dotenvFirst
        ? dotenv.secrets.map((fact) => locationOffsets(content, fact.location))
        : []
      const supabaseKeys = extractSupabaseKeyFacts(
        scan,
        file.relativePath,
        content,
        seedOccupied,
      )
      const occupiedAfterKeys = [
        ...seedOccupied,
        ...privateKeys.map((fact) => locationOffsets(content, fact.location)),
        ...supabaseKeys.secrets.map((fact) => locationOffsets(content, fact.location)),
      ]
      const highSpecificity = extractHighSpecificitySecretFacts(
        scan,
        file.relativePath,
        content,
      ).filter((fact) => {
        const range = locationOffsets(content, fact.location)
        return !occupiedAfterKeys.some(
          (item) => range.start < item.end && item.start < range.end,
        )
      })
      const occupied = [
        ...occupiedAfterKeys,
        ...highSpecificity.map((fact) => locationOffsets(content, fact.location)),
      ]
      const generic = extractGenericSecretFacts(
        scan,
        file.relativePath,
        content,
        occupied,
      )
      const dotenvSecrets = dotenvFirst
        ? dotenv.secrets
        : dotenv.secrets.filter((secret) => {
            const range = locationOffsets(content, secret.location)
            return !occupied.some(
              (item) => range.start < item.end && item.start < range.end,
            )
          })
      const supabaseSql = extractSupabaseSqlFacts(file.relativePath, content)
      const authGuards = extractAuthGuardFacts(file.relativePath, content)
      const clientQueries = extractClientQueryFacts(file.relativePath, content)
      const dangerousSinks = extractDangerousSinkFacts(file.relativePath, content)
      const clientBindings = extractClientPrefixBindingFacts(file.relativePath, content)
      const gitFact = createGitFileFact(
        file.relativePath,
        gitStatuses.get(file.relativePath) ?? 'unknown',
      )

      const batch: Fact[] = [
        gitFact,
        ...privateKeys,
        ...supabaseKeys.secrets,
        ...supabaseKeys.inventory,
        ...highSpecificity,
        ...generic,
        ...dotenv.bindings,
        ...dotenvSecrets,
        ...clientBindings,
        ...supabaseSql,
        ...authGuards,
        ...clientQueries,
        ...dangerousSinks,
      ]
      if (facts.length + batch.length > DEFAULT_MAX_FACTS) {
        throw new LocalInventoryError()
      }
      facts.push(...batch)
      filesScanned += 1
    } finally {
      await handle.close()
    }
  }

  return Object.freeze({
    facts: Object.freeze(facts),
    filesScanned,
    filesSkipped,
  })
}

function createGitFileFact(
  relativePath: string,
  tracking: GitFileFact['tracking'],
): GitFileFact {
  return Object.freeze({
    kind: 'git.file',
    location: Object.freeze({ file: relativePath, startLine: 1 }),
    source: Object.freeze({
      extractor: 'git-provenance',
      context: 'unknown',
      syntax: 'text',
    }),
    confidence: tracking === 'unknown' ? 'low' : 'high',
    tracking,
  })
}

function locationOffsets(
  content: string,
  location: Readonly<{
    file: string
    startLine: number
    startColumn?: number
    endLine?: number
    endColumn?: number
  }>,
): Readonly<{ start: number; end: number }> {
  const starts = [0]
  for (let index = 0; index < content.length; index += 1) {
    if (content.charCodeAt(index) === 10) starts.push(index + 1)
  }
  const startLineIndex = Math.max(0, location.startLine - 1)
  const endLineIndex = Math.max(0, (location.endLine ?? location.startLine) - 1)
  const start =
    (starts[startLineIndex] ?? 0) + Math.max(0, (location.startColumn ?? 1) - 1)
  const end =
    (starts[endLineIndex] ?? start) + Math.max(0, (location.endColumn ?? 1) - 1)
  return Object.freeze({ start, end: Math.max(start, end) })
}
