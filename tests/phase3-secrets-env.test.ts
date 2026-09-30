import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'

import { afterEach, describe, expect, it } from 'vitest'

import { scanLocalProject } from '../src/application/scan-local-project.js'
import { ScanKernelContext } from '../src/core/scan/scan-kernel-context.js'
import { extractHighSpecificitySecretFacts } from '../src/extractors/high-specificity-secret-extractor.js'
import { extractGenericSecretFacts } from '../src/extractors/generic-secret-extractor.js'
import { extractDotenvFacts } from '../src/extractors/dotenv-extractor.js'
import { extractLocalScanFacts } from '../src/extractors/local-private-key-scan.js'
import { extractPrivateKeyFacts } from '../src/extractors/private-key-extractor.js'
import { highSpecificityCredentialRule } from '../src/rules/high-specificity-credential-rule.js'
import { genericCredentialCandidateRule } from '../src/rules/generic-credential-candidate-rule.js'
import { clientEnvExposureRule } from '../src/rules/client-env-exposure-rule.js'
import { trackedEnvSecretRule } from '../src/rules/tracked-env-secret-rule.js'
import { privateKeyMaterialRule } from '../src/rules/private-key-material-rule.js'
import { resolveGitProvenance } from '../src/targets/git-provenance.js'
import type { PathFlavor } from '../src/utils/paths.js'

const flavor: PathFlavor = process.platform === 'win32' ? 'windows' : 'posix'
const temporaryDirectories: string[] = []

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  )
})

describe('Phase 3 Git provenance', () => {
  it('marks files unknown when Git metadata is absent', async () => {
    const root = await temporaryDirectory()
    await writeFile(path.join(root, 'a.txt'), 'hello')
    const statuses = await resolveGitProvenance(root, ['a.txt'], flavor)
    expect(statuses.get('a.txt')).toBe('unknown')
  })

  it('distinguishes tracked and untracked files in a local repository', async () => {
    const root = await temporaryDirectory()
    if (!initializeGitRepository(root)) return
    await writeFile(path.join(root, 'tracked.txt'), 'tracked')
    await writeFile(path.join(root, 'loose.txt'), 'loose')
    runGit(root, ['add', 'tracked.txt'])
    runGit(root, [
      '-c',
      'user.name=VibeSec',
      '-c',
      'user.email=vibesec@example.test',
      'commit',
      '-m',
      'init',
    ])

    const statuses = await resolveGitProvenance(
      root,
      ['tracked.txt', 'loose.txt'],
      flavor,
    )
    expect(statuses.get('tracked.txt')).toBe('tracked')
    expect(statuses.get('loose.txt')).toBe('untracked')
  })
})

describe('Phase 3 secret taxonomy', () => {
  it('detects high-specificity credentials without leaking canaries', () => {
    const canary = ['VIBESEC', 'P3', 'DB', 'CANARY', '7F31A9'].join('_')
    const content = [
      'DATABASE_URL=postgres://app:',
      canary,
      '@localhost:5432/app\n',
    ].join('')
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const facts = extractHighSpecificitySecretFacts(scan, 'config.env', content)
    expect(facts).toHaveLength(1)
    expect(facts[0]?.secretType).toBe('database_url')
    expect(JSON.stringify(facts)).not.toContain(canary)
    scan.finalizeScan()
    scan.close()
  })

  it('emits suspicious generic candidates and skips placeholders', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const content = [
      'api_key=aB3dE5fG7hJ9kL1mN2pQ4rS',
      'password=CHANGEME_password_value',
    ].join('\n')
    const facts = extractGenericSecretFacts(scan, 'src/config.ts', content)
    expect(facts).toHaveLength(1)
    expect(facts[0]?.secretType).toBe('unknown')
    expect(facts[0]?.isPlaceholder).toBe(false)
    scan.finalizeScan()
    scan.close()
  })

  it('does not let VS-SEC-003 duplicate a high-specificity location', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const content =
      'webhook_secret=whsec_abcdefghijklmnopqrstuv\napi_key=aB3dE5fG7hJ9kL1mN2pQ4rS\n'
    const high = extractHighSpecificitySecretFacts(scan, 'app.ts', content)
    const generic = extractGenericSecretFacts(scan, 'app.ts', content, [
      { start: 0, end: content.indexOf('\n') },
    ])
    const context = scan.createRuleContext([...high, ...generic])
    expect(scan.evaluateRule(highSpecificityCredentialRule, context)).toHaveLength(1)
    expect(scan.evaluateRule(genericCredentialCandidateRule, context)).toHaveLength(1)
    scan.finalizeScan()
    scan.close()
  })
})

describe('Phase 3 environment rules', () => {
  it('confirms client-prefix exposure for sensitive dotenv values', () => {
    const canary = ['VIBESEC', 'P3', 'VITE', 'CANARY', '88C2'].join('_')
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const content = [
      'VITE_DATABASE_URL=',
      'postgres://app:',
      canary,
      '@db.internal/app\n',
    ].join('')
    const dotenv = extractDotenvFacts(scan, '.env', content)
    const context = scan.createRuleContext([...dotenv.bindings, ...dotenv.secrets])
    const findings = scan.evaluateRule(clientEnvExposureRule, context)
    expect(findings).toHaveLength(1)
    expect(findings[0]?.status).toBe('confirmed')
    expect(JSON.stringify(findings)).not.toContain(canary)
    scan.finalizeScan()
    scan.close()
  })

  it('requires tracked provenance before VS-ENV-002', async () => {
    const root = await temporaryDirectory()
    if (!initializeGitRepository(root)) return
    const canary = ['VIBESEC', 'P3', 'ENV', 'TRACKED', '55AA'].join('_')
    await writeFile(
      path.join(root, '.env'),
      ['API_SECRET=', canary, '_highEntropyValue991\n'].join(''),
    )
    await writeFile(
      path.join(root, '.env.local'),
      ['API_SECRET=', canary, '_local\n'].join(''),
    )
    runGit(root, ['add', '.env'])
    runGit(root, [
      '-c',
      'user.name=VibeSec',
      '-c',
      'user.email=vibesec@example.test',
      'commit',
      '-m',
      'env',
    ])

    const scan = ScanKernelContext.create({ pathFlavor: flavor })
    const extraction = await extractLocalScanFacts(scan, root, {
      pathFlavor: flavor,
    })
    const context = scan.createRuleContext(extraction.facts)
    const trackedFindings = scan.evaluateRule(trackedEnvSecretRule, context)
    expect(trackedFindings.length).toBeGreaterThan(0)
    expect(trackedFindings.every((finding) => finding.status === 'confirmed')).toBe(
      true,
    )
    expect(JSON.stringify(trackedFindings)).not.toContain(canary)
    scan.finalizeScan()
    scan.close()
  })
})

describe('Phase 3 orchestration', () => {
  it('upgrades private-key severity when the file is Git-tracked', async () => {
    const root = await temporaryDirectory()
    if (!initializeGitRepository(root)) return
    const privateKey = generateKeyPairSync('ed25519').privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    })
    await writeFile(path.join(root, 'key.pem'), privateKey)
    runGit(root, ['add', 'key.pem'])
    runGit(root, [
      '-c',
      'user.name=VibeSec',
      '-c',
      'user.email=vibesec@example.test',
      'commit',
      '-m',
      'key',
    ])

    const result = await scanLocalProject(root, {
      pathFlavor: flavor,
      format: 'json',
    })
    const report = JSON.parse(result.output) as {
      findings: { ruleId: string; severity: string; description: string }[]
    }
    const finding = report.findings.find((item) => item.ruleId === 'VS-SEC-001')
    expect(finding?.severity).toBe('critical')
    expect(finding?.description).toContain('Git-tracked')
  })

  it('keeps findings deterministic across equivalent scans', async () => {
    const root = await temporaryDirectory()
    const canary = ['VIBESEC', 'P3', 'DET', 'CANARY', '01'].join('_')
    await writeFile(
      path.join(root, 'secrets.txt'),
      [
        'postgres://app:',
        canary,
        '@localhost/db\n',
        'api_key=aB3dE5fG7hJ9kL1mN2pQ4rS\n',
      ].join(''),
    )
    const first = await scanLocalProject(root, { pathFlavor: flavor, format: 'json' })
    const second = await scanLocalProject(root, {
      pathFlavor: flavor,
      format: 'json',
    })
    expect(withoutFingerprints(JSON.parse(first.output))).toEqual(
      withoutFingerprints(JSON.parse(second.output)),
    )
  })

  it('scans public-prefix dotenv files without duplicate finding IDs', async () => {
    const root = await temporaryDirectory()
    const canary = ['VIBESEC', 'P3', 'DUP', 'CANARY', '22'].join('_')
    await writeFile(
      path.join(root, '.env'),
      ['VITE_DATABASE_URL=postgres://app:', canary, '@localhost/db\n'].join(''),
    )
    const result = await scanLocalProject(root, {
      pathFlavor: flavor,
      format: 'json',
    })
    const report = JSON.parse(result.output) as {
      findings: { id: string; ruleId: string }[]
    }
    const ids = report.findings.map((finding) => finding.id)
    expect(new Set(ids).size).toBe(ids.length)
    expect(report.findings.some((finding) => finding.ruleId === 'VS-ENV-001')).toBe(
      true,
    )
  })

  it('maps scan failures to LocalScanError without leaking internal errors', async () => {
    await expect(
      scanLocalProject('', { pathFlavor: flavor, format: 'json' }),
    ).rejects.toThrow('The local scan could not be completed.')
  })

  it('never claims Git tracking when provenance is unknown', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const privateKey = generateKeyPairSync('ed25519').privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    })
    const facts = [
      Object.freeze({
        kind: 'git.file' as const,
        location: Object.freeze({ file: 'key.pem', startLine: 1 }),
        source: Object.freeze({
          extractor: 'git-provenance',
          context: 'unknown' as const,
          syntax: 'text' as const,
        }),
        confidence: 'low' as const,
        tracking: 'unknown' as const,
      }),
      ...extractPrivateKeyFacts(scan, 'key.pem', privateKey),
    ]
    const context = scan.createRuleContext(facts)
    const [finding] = scan.evaluateRule(privateKeyMaterialRule, context)
    expect(finding?.description).not.toContain('Git-tracked')
    expect(finding?.limitations.join(' ')).toContain('tracked by Git')
    scan.finalizeScan()
    scan.close()
  })
})

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), 'vibesec-phase3-'))
  temporaryDirectories.push(directory)
  return directory
}

function initializeGitRepository(root: string): boolean {
  const init = runGit(root, ['init'])
  if (init.status !== 0) return false
  runGit(root, ['config', 'user.name', 'VibeSec'])
  runGit(root, ['config', 'user.email', 'vibesec@example.test'])
  return true
}

function runGit(cwd: string, args: readonly string[]) {
  return spawnSync('git', ['-c', 'core.hooksPath=/dev/null', ...args], {
    cwd,
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
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
