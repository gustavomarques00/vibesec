import { mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

import { afterEach, describe, expect, it } from 'vitest'

import { scanLocalProject } from '../src/application/scan-local-project.js'
import { runCli } from '../src/cli/run.js'
import { extractDangerousSinkFacts } from '../src/extractors/dangerous-sink-extractor.js'
import { extractAuthGuardFacts } from '../src/extractors/auth-guard-extractor.js'
import { extractSupabaseSqlFacts } from '../src/extractors/supabase-sql-extractor.js'
import { stripLineAndBlockComments } from '../src/extractors/source-sanitize.js'
import { escapeDisplayText } from '../src/reporters/display-text.js'
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

describe('Phase 6 malformed and hostile targets', () => {
  it('survives unterminated comments, strings, and malformed SQL', async () => {
    const root = await temporaryDirectory()
    await mkdir(path.join(root, 'src'), { recursive: true })
    await mkdir(path.join(root, 'supabase', 'migrations'), { recursive: true })
    await writeFile(
      path.join(root, 'src', 'broken.ts'),
      '/* unterminated\neval(userInput)\nconst x = "unterminated\n',
    )
    await writeFile(
      path.join(root, 'supabase', 'migrations', 'bad.sql'),
      'CREATE TABLE ((((;\nALTER TABLE only_half ENABLE\n',
    )
    const result = await scanLocalProject(root, {
      pathFlavor: flavor,
      format: 'json',
    })
    expect(typeof result.filesScanned).toBe('number')
    expect(result.filesScanned).toBeGreaterThanOrEqual(0)
  })

  it('never executes target payloads that would mutate the host', async () => {
    const root = await temporaryDirectory()
    const marker = path.join(root, 'EXECUTED.marker')
    await mkdir(path.join(root, 'src'), { recursive: true })
    await writeFile(
      path.join(root, 'src', 'boom.js'),
      [
        'import { writeFileSync } from "node:fs";',
        `writeFileSync(${JSON.stringify(marker)}, "executed");`,
        'throw new Error("SHOULD_NOT_RUN");',
      ].join('\n'),
    )
    await scanLocalProject(root, { pathFlavor: flavor, format: 'json' })
    await expect(readFile(marker, 'utf8')).rejects.toThrow()
  })

  it('keeps canaries out of reporters when secrets sit near auth/dang code', async () => {
    const canary = ['VIBESEC', 'P6', 'CANARY', 'A1B2'].join('_')
    const root = await temporaryDirectory()
    await mkdir(path.join(root, 'src'), { recursive: true })
    await writeFile(
      path.join(root, 'src', 'mixed.ts'),
      [
        `const password = "${canary}_highEntropyValue991";`,
        'if (isAdmin) return null;',
        'eval(userInput);',
      ].join('\n'),
    )
    const result = await scanLocalProject(root, {
      pathFlavor: flavor,
      format: 'json',
    })
    expect(result.output).not.toContain(canary)
    expect(result.output).not.toContain(JSON.stringify(canary).slice(1, -1))
  })
})

describe('Phase 6 false-positive / evasion fixtures', () => {
  it('does not flag comments, docs strings, constants, or sanitized sinks', () => {
    const negative = [
      '// eval(userInput)',
      'const tip = "document.write(x)"',
      'eval("1+1")',
      'el.innerHTML = DOMPurify.sanitize(userHtml)',
      'localStorage.getItem("sb-abc-auth-token")',
    ].join('\n')
    const sinks = extractDangerousSinkFacts('src/neg.ts', negative).filter(
      (fact) => fact.input !== 'constant' && fact.sanitizer === undefined,
    )
    expect(sinks).toHaveLength(0)
    expect(
      extractAuthGuardFacts(
        'src/neg.ts',
        'localStorage.getItem("sb-abc-auth-token")\n',
      ).filter((fact) => fact.subject?.startsWith('storage:')),
    ).toHaveLength(0)
  })

  it('still detects supported multiline / spaced dangerous calls', () => {
    const facts = extractDangerousSinkFacts('src/pos.ts', 'eval (\n  userInput\n)\n')
    expect(facts.some((fact) => fact.sink === 'eval')).toBe(true)
  })

  it('bounds SQL inventory under pathological statement amplification', () => {
    const sql = 'CREATE TABLE t (id int);\n'.repeat(30)
    expect(() =>
      extractSupabaseSqlFacts('supabase/migrations/x.sql', sql, {
        maxStatements: 5,
      }),
    ).toThrow(/limits exceeded/u)
  })
})

describe('Phase 6 parser / regex safety', () => {
  it('comment stripper completes on large pathological input within a budget', () => {
    const huge = `${'/*'.repeat(5_000)}${'a'.repeat(20_000)}${'*/'.repeat(5_000)}`
    const started = Date.now()
    const stripped = stripLineAndBlockComments(huge)
    expect(Date.now() - started).toBeLessThan(2_000)
    expect(stripped.length).toBe(huge.length)
  })

  it('escapes terminal control and bidi characters in display text', () => {
    const raw = 'evil\u001b[31mRED\u202Epath'
    const escaped = escapeDisplayText(raw)
    expect(escaped).not.toContain('\u001b')
    expect(escaped).not.toContain('\u202E')
  })
})

describe('Phase 6 CLI contract', () => {
  it('returns documented exit codes for usage, clean, and dirty scans', async () => {
    const clean = await temporaryDirectory()
    await writeFile(path.join(clean, 'ok.txt'), 'hello')
    const dirty = await temporaryDirectory()
    await mkdir(path.join(dirty, 'src'), { recursive: true })
    await writeFile(path.join(dirty, 'src', 'x.ts'), 'eval(userInput)\n')

    const usage: string[] = []
    expect(
      await runCli(
        [],
        { stdout: () => undefined, stderr: (t) => usage.push(t) },
        process.platform,
      ),
    ).toBe(2)

    const cleanOut: string[] = []
    expect(
      await runCli(
        ['scan', clean, '--format', 'json'],
        { stdout: (t) => cleanOut.push(t), stderr: () => undefined },
        process.platform,
      ),
    ).toBe(0)

    const dirtyOut: string[] = []
    expect(
      await runCli(
        ['scan', dirty, '--format', 'json'],
        { stdout: (t) => dirtyOut.push(t), stderr: () => undefined },
        process.platform,
      ),
    ).toBe(1)
    expect(dirtyOut.join('')).toContain('VS-DANG-001')
  })

  it('keeps scan failures generic without absolute path leakage', async () => {
    const errors: string[] = []
    const code = await runCli(
      [
        'scan',
        path.join('C:', 'definitely-missing-vibesec-target'),
        '--format',
        'json',
      ],
      { stdout: () => undefined, stderr: (t) => errors.push(t) },
      process.platform,
    )
    expect(code).toBe(2)
    expect(errors.join('')).toBe('VibeSec: scan failed.\n')
    expect(errors.join('')).not.toMatch(/C:\\|Users\\/u)
  })
})

describe('Phase 6 determinism and package readiness', () => {
  it('produces identical JSON for equivalent scans ignoring fingerprints', async () => {
    const root = await temporaryDirectory()
    await mkdir(path.join(root, 'src'), { recursive: true })
    await writeFile(path.join(root, 'src', 'a.ts'), 'eval(userInput)\n')
    const first = await scanLocalProject(root, { pathFlavor: flavor, format: 'json' })
    const second = await scanLocalProject(root, {
      pathFlavor: flavor,
      format: 'json',
    })
    expect(withoutFingerprints(JSON.parse(first.output))).toEqual(
      withoutFingerprints(JSON.parse(second.output)),
    )
  })

  it('exposes a shebang on the CLI entry and packs README', async () => {
    const built = spawnSync('npm', ['run', 'build'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      shell: true,
    })
    expect(built.status).toBe(0)
    const packed = spawnSync('npm', ['pack', '--dry-run'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      shell: true,
    })
    expect(packed.status).toBe(0)
    const packText = `${packed.stdout}\n${packed.stderr}`
    expect(packText).toContain('README.md')
    expect(packText).toContain('dist/cli/main.js')
    const main = await readFile(
      path.join(process.cwd(), 'dist', 'cli', 'main.js'),
      'utf8',
    )
    expect(main.startsWith('#!/usr/bin/env node')).toBe(true)
  })
})

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), 'vibesec-phase6-'))
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
