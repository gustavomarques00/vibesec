import { generateKeyPairSync } from 'node:crypto'
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { scanLocalProject } from '../src/application/scan-local-project.js'
import { ScanKernelContext } from '../src/core/scan/scan-kernel-context.js'
import { inventoryLocalFiles } from '../src/discovery/file-inventory.js'
import {
  countPrivateKeyCandidates,
  extractPrivateKeyFacts,
} from '../src/extractors/private-key-extractor.js'
import { privateKeyMaterialRule } from '../src/rules/private-key-material-rule.js'
import type { PathFlavor } from '../src/utils/paths.js'

const PRIVATE_KEY = generateSyntheticPrivateKey()
const OTHER_PRIVATE_KEY = generateSyntheticPrivateKey()
const CANARY = privateKeyBodyLine(PRIVATE_KEY)
const PLACEHOLDER_KEY = `-----BEGIN PRIVATE KEY-----
EXAMPLE_PLACEHOLDER_DO_NOT_USE
-----END PRIVATE KEY-----`
const flavor: PathFlavor = process.platform === 'win32' ? 'windows' : 'posix'
const temporaryDirectories: string[] = []

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  )
})

describe('Phase 2 local inventory', () => {
  it('walks deterministically and skips ignored, binary, and oversized files', async () => {
    const root = await temporaryDirectory()
    await mkdir(path.join(root, 'nested'))
    await mkdir(path.join(root, 'node_modules'))
    await writeFile(path.join(root, 'z.txt'), 'z')
    await writeFile(path.join(root, 'nested', 'a.txt'), 'a')
    await writeFile(path.join(root, 'node_modules', 'ignored.txt'), PRIVATE_KEY)
    await writeFile(path.join(root, 'binary.bin'), Buffer.from([1, 0, 2]))
    await writeFile(path.join(root, 'large.txt'), 'x'.repeat(33))

    const inventory = await inventoryLocalFiles(root, {
      pathFlavor: flavor,
      maxFileBytes: 32,
    })

    expect(inventory.files.map((file) => file.relativePath)).toEqual([
      'binary.bin',
      'nested/a.txt',
      'z.txt',
    ])
    expect(inventory.filesSkipped).toBe(2)
  })

  it('does not follow a symlink when the host permits creating one', async () => {
    const root = await temporaryDirectory()
    const outside = await temporaryDirectory()
    await writeFile(path.join(outside, 'secret.txt'), PRIVATE_KEY)
    try {
      await symlink(
        path.join(outside, 'secret.txt'),
        path.join(root, 'linked-secret.txt'),
      )
    } catch {
      return
    }

    const inventory = await inventoryLocalFiles(root, { pathFlavor: flavor })
    expect(inventory.files).toEqual([])
    expect(inventory.filesSkipped).toBe(1)
  })

  it('returns a generic error without disclosing the absolute target', async () => {
    const missing = path.join(await temporaryDirectory(), 'missing-target')
    await expect(inventoryLocalFiles(missing, { pathFlavor: flavor })).rejects.toThrow(
      'Unable to inventory the local target.',
    )
    await expect(
      inventoryLocalFiles(missing, { pathFlavor: flavor }),
    ).rejects.not.toThrow(missing)
  })
})

describe('Phase 2 private-key vertical slice', () => {
  it('turns raw material into a protected fact and finalized finding', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const facts = extractPrivateKeyFacts(scan, 'src/key.pem', PRIVATE_KEY)
    expect(facts).toHaveLength(1)
    expect(JSON.stringify(facts)).not.toContain(CANARY)

    const context = scan.createRuleContext(facts)
    const evaluated = scan.evaluateRule(privateKeyMaterialRule, context)
    expect(evaluated).toHaveLength(1)
    const findings = scan.finalizeScan()
    const serialized = scan.readOutput(scan.serializeFindings())

    expect(findings[0]).toMatchObject({
      ruleId: 'VS-SEC-001',
      ruleVersion: '1.1.0',
      title: 'Private key material in local source',
      severity: 'high',
      confidence: 'high',
      status: 'confirmed',
    })
    expect(serialized).not.toContain(CANARY)
    expect(serialized).toContain('[REDACTED]')
    scan.close()
  })

  it('does not create a finding for an explicit placeholder', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const facts = extractPrivateKeyFacts(scan, 'fixtures/key.pem', PLACEHOLDER_KEY)
    const context = scan.createRuleContext(facts)
    expect(scan.evaluateRule(privateKeyMaterialRule, context)).toEqual([])
    scan.finalizeScan()
    scan.close()
  })

  it('rejects a delimited block that is not a parseable private key', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const malformed =
      '-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----'
    expect(extractPrivateKeyFacts(scan, 'src/fake.pem', malformed)).toEqual([])
    scan.finalizeScan()
    scan.close()
  })

  it('bounds candidate amplification before cryptographic parsing', () => {
    const malformed =
      '-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----'
    expect(() => countPrivateKeyCandidates(`${malformed}\n${malformed}`, 1)).toThrow(
      'Private-key candidate limit exceeded.',
    )
  })

  it('keeps finding IDs independent from secret and fingerprint values', () => {
    const first = findingIdFor(PRIVATE_KEY)
    const second = findingIdFor(OTHER_PRIVATE_KEY)
    expect(first).toBe(second)
  })
})

describe('Phase 2 reporters and orchestration', () => {
  it('rejects hostile report DTOs without executing accessors', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    scan.finalizeScan()
    let getterExecuted = false
    const hostile = { target: 'target', filesScanned: 0, filesSkipped: 0 }
    Object.defineProperty(hostile, 'target', {
      enumerable: true,
      get() {
        getterExecuted = true
        return 'target'
      },
    })
    expect(() => scan.serializeReport(hostile)).toThrow()
    expect(getterExecuted).toBe(false)
    scan.close()
  })

  it('binds rendered output to the issuing scan context', () => {
    const first = ScanKernelContext.create({ pathFlavor: 'posix' })
    const second = ScanKernelContext.create({ pathFlavor: 'posix' })
    first.finalizeScan()
    second.finalizeScan()
    const output = first.renderReport(
      { target: 'target', filesScanned: 0, filesSkipped: 0 },
      'terminal',
    )
    expect(() => second.readOutput(output)).toThrow()
    first.close()
    second.close()
  })

  it.each(['terminal', 'json', 'markdown'] as const)(
    'renders a safe deterministic %s report',
    async (format) => {
      const root = await temporaryDirectory()
      await writeFile(path.join(root, 'key.pem'), PRIVATE_KEY)

      const first = await scanLocalProject(root, { pathFlavor: flavor, format })
      const second = await scanLocalProject(root, { pathFlavor: flavor, format })

      expect(first.findingCount).toBe(1)
      expect(first.output).not.toContain(CANARY)
      if (format === 'json') {
        const firstReport: unknown = JSON.parse(first.output)
        const secondReport: unknown = JSON.parse(second.output)
        expect(withoutFingerprints(firstReport)).toEqual(
          withoutFingerprints(secondReport),
        )
      } else {
        expect(first.output).toBe(second.output)
      }
    },
  )

  it('escapes bidirectional control characters in display reports', async () => {
    const root = await temporaryDirectory()
    await writeFile(path.join(root, 'key\u202Ecod.pem'), PRIVATE_KEY)
    const result = await scanLocalProject(root, {
      pathFlavor: flavor,
      format: 'terminal',
    })
    expect(result.output).not.toContain('\u202E')
    expect(result.output).toContain('\\u202e')
  })

  it('never executes code found in the target', async () => {
    const root = await temporaryDirectory()
    const marker = path.join(root, 'executed.txt')
    await writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({ scripts: { postinstall: `echo unsafe > "${marker}"` } }),
    )
    await scanLocalProject(root, { pathFlavor: flavor, format: 'json' })
    await expect(
      import('node:fs/promises').then(({ lstat }) => lstat(marker)),
    ).rejects.toThrow()
  })

  it('rejects unsafe per-file allocation limits before reading', async () => {
    const root = await temporaryDirectory()
    await writeFile(path.join(root, 'small.txt'), 'small')
    await expect(
      scanLocalProject(root, {
        pathFlavor: flavor,
        format: 'json',
        maxFileBytes: 32 * 1024 * 1024,
      }),
    ).rejects.toThrow('The local scan could not be completed.')
  })
})

function findingIdFor(raw: string): string {
  const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
  const facts = extractPrivateKeyFacts(scan, 'src/key.pem', raw)
  const context = scan.createRuleContext(facts)
  scan.evaluateRule(privateKeyMaterialRule, context)
  const [finding] = scan.finalizeScan()
  scan.close()
  if (finding === undefined) throw new Error('Expected a finding.')
  return finding.id
}

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), 'vibesec-phase2-'))
  temporaryDirectories.push(directory)
  return directory
}

function withoutFingerprints(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(withoutFingerprints)
  if (value === null || typeof value !== 'object') return value
  const result: Record<string, unknown> = {}
  for (const [key, nested] of Object.entries(value)) {
    if (key !== 'secretFingerprint') result[key] = withoutFingerprints(nested)
  }
  return result
}

function generateSyntheticPrivateKey(): string {
  return generateKeyPairSync('ed25519').privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  })
}

function privateKeyBodyLine(privateKey: string): string {
  const line = privateKey.split('\n')[1]
  if (line === undefined || line.length < 16) {
    throw new Error('Expected synthetic private-key material.')
  }
  return line
}
