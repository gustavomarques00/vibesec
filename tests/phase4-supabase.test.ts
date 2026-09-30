import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { scanLocalProject } from '../src/application/scan-local-project.js'
import { ScanKernelContext } from '../src/core/scan/scan-kernel-context.js'
import { extractSupabaseKeyFacts } from '../src/extractors/supabase-key-extractor.js'
import { extractSupabaseSqlFacts } from '../src/extractors/supabase-sql-extractor.js'
import { supabaseBroadPolicyRule } from '../src/rules/supabase-broad-policy-rule.js'
import { supabaseMissingRlsRule } from '../src/rules/supabase-missing-rls-rule.js'
import { supabaseRlsDisabledRule } from '../src/rules/supabase-rls-disabled-rule.js'
import { supabaseServiceRoleClientRule } from '../src/rules/supabase-service-role-client-rule.js'
import { supabaseServiceRoleServerRule } from '../src/rules/supabase-service-role-server-rule.js'
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

describe('Phase 4 Supabase SQL inventory', () => {
  it('extracts tables, RLS toggles, and policies from migrations', () => {
    const sql = [
      'CREATE TABLE public.profiles (id uuid primary key);',
      'ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;',
      'CREATE POLICY owner_read ON public.profiles FOR SELECT TO authenticated USING (auth.uid() = id);',
      'CREATE POLICY open_all ON public.notes FOR ALL TO anon USING (true) WITH CHECK (true);',
    ].join('\n')
    const facts = extractSupabaseSqlFacts('supabase/migrations/001_init.sql', sql)
    expect(facts.some((fact) => fact.kind === 'supabase.table')).toBe(true)
    expect(facts.some((fact) => fact.kind === 'supabase.rls' && fact.enabled)).toBe(
      true,
    )
    const broad = facts.find(
      (fact) => fact.kind === 'supabase.policy' && fact.policyName === 'open_all',
    )
    expect(broad?.kind === 'supabase.policy' && broad.isBroad).toBe(true)
  })

  it('flags final DISABLE RLS and missing RLS separately', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const enabled = extractSupabaseSqlFacts(
      'supabase/migrations/001.sql',
      'CREATE TABLE public.items (id int);\nALTER TABLE public.items ENABLE ROW LEVEL SECURITY;',
    )
    const disabled = extractSupabaseSqlFacts(
      'supabase/migrations/002.sql',
      'ALTER TABLE public.items DISABLE ROW LEVEL SECURITY;',
    )
    const missing = extractSupabaseSqlFacts(
      'supabase/migrations/003.sql',
      'CREATE TABLE public.orphan (id int);',
    )
    const context = scan.createRuleContext([...enabled, ...disabled, ...missing])
    const disabledFindings = scan.evaluateRule(supabaseRlsDisabledRule, context)
    const missingFindings = scan.evaluateRule(supabaseMissingRlsRule, context)
    expect(disabledFindings).toHaveLength(1)
    expect(disabledFindings[0]?.status).toBe('confirmed')
    expect(disabledFindings[0]?.limitations.join(' ')).toContain('production')
    expect(
      missingFindings.some((finding) => finding.status === 'requires_authorization'),
    ).toBe(true)
    expect(
      missingFindings.every(
        (finding) =>
          !finding.description.toLowerCase().includes('production is disabled'),
      ),
    ).toBe(true)
    scan.finalizeScan()
    scan.close()
  })

  it('marks broad anon policies as suspicious', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const facts = extractSupabaseSqlFacts(
      'supabase/migrations/010.sql',
      'CREATE POLICY open_all ON public.notes FOR ALL TO anon USING (true);',
    )
    const findings = scan.evaluateRule(
      supabaseBroadPolicyRule,
      scan.createRuleContext(facts),
    )
    expect(findings).toHaveLength(1)
    expect(findings[0]?.status).toBe('suspicious')
    scan.finalizeScan()
    scan.close()
  })
})

describe('Phase 4 Supabase key taxonomy', () => {
  it('confirms client service-role JWT without leaking the canary', () => {
    const token = mintJwt({ role: 'service_role', ref: 'vibesec-phase4' })
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const extracted = extractSupabaseKeyFacts(
      scan,
      'src/client/config.ts',
      `export const KEY = "${token}";\n`,
    )
    expect(extracted.secrets).toHaveLength(1)
    scan.evaluateRule(
      supabaseServiceRoleClientRule,
      scan.createRuleContext(extracted.secrets),
    )
    const findings = scan.finalizeScan()
    expect(findings).toHaveLength(1)
    expect(findings[0]?.ruleId).toBe('VS-SUP-001')
    expect(findings[0]?.severity).toBe('critical')
    expect(JSON.stringify(findings)).not.toContain(token)
    scan.close()
  })

  it('inventories anon keys without emitting SUP findings', () => {
    const token = mintJwt({ role: 'anon', ref: 'vibesec-phase4' })
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const extracted = extractSupabaseKeyFacts(
      scan,
      'src/client/config.ts',
      `export const KEY = "${token}";\n`,
    )
    expect(extracted.secrets).toHaveLength(0)
    expect(extracted.inventory.length).toBeGreaterThan(0)
    scan.evaluateRule(
      supabaseServiceRoleClientRule,
      scan.createRuleContext([...extracted.secrets, ...extracted.inventory]),
    )
    expect(scan.finalizeScan()).toHaveLength(0)
    scan.close()
  })

  it('classifies server-path service-role literals as VS-SUP-002', () => {
    const canary = ['sb', 'secret', 'VIBESECP4SERVERKEY991'].join('_')
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const extracted = extractSupabaseKeyFacts(
      scan,
      'server/db.ts',
      `const key = "${canary}";\n`,
    )
    scan.evaluateRule(
      supabaseServiceRoleServerRule,
      scan.createRuleContext(extracted.secrets),
    )
    const findings = scan.finalizeScan()
    expect(findings).toHaveLength(1)
    expect(findings[0]?.ruleId).toBe('VS-SUP-002')
    expect(JSON.stringify(findings)).not.toContain(canary)
    scan.close()
  })

  it('ignores malformed JWT payloads and never persists raw tokens', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const extracted = extractSupabaseKeyFacts(
      scan,
      'src/client/config.ts',
      'const bad = "eyJhbGciOiJub25lIn0.%%%notbase64%%%.sig";\n',
    )
    expect(extracted.secrets).toHaveLength(0)
    scan.finalizeScan()
    scan.close()
  })

  it('bounds SQL statement amplification', () => {
    const huge = `${'CREATE TABLE t0 (id int);\n'.repeat(10)}CREATE TABLE boom (id int);`
    expect(() =>
      extractSupabaseSqlFacts('supabase/migrations/x.sql', huge, {
        maxStatements: 5,
      }),
    ).toThrow('Supabase SQL inventory limits exceeded.')
  })
})

describe('Phase 4 orchestration', () => {
  it('scans a Supabase fixture project without network and without secret leak', async () => {
    const root = await temporaryDirectory()
    const migrations = path.join(root, 'supabase', 'migrations')
    await mkdir(migrations, { recursive: true })
    await mkdir(path.join(root, 'src'), { recursive: true })
    const serviceToken = mintJwt({ role: 'service_role', iss: 'supabase' })
    await writeFile(
      path.join(migrations, '001_create.sql'),
      [
        'CREATE TABLE public.profiles (id uuid primary key);',
        'CREATE TABLE public.open_notes (id uuid primary key);',
        'ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;',
        'CREATE POLICY open_notes ON public.open_notes FOR SELECT TO anon USING (true);',
        'ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;',
      ].join('\n'),
    )
    await writeFile(
      path.join(root, 'src', 'client.ts'),
      ['export const service = "', serviceToken, '";\n'].join(''),
    )

    const result = await scanLocalProject(root, {
      pathFlavor: flavor,
      format: 'json',
    })
    const report = JSON.parse(result.output) as {
      findings: { ruleId: string; status: string }[]
    }
    const ids = report.findings.map((finding) => finding.ruleId)
    expect(ids).toContain('VS-SUP-001')
    expect(ids).toContain('VS-SUP-003')
    expect(ids).toContain('VS-SUP-005')
    expect(result.output).not.toContain(serviceToken)
  })
})

function mintJwt(claims: Record<string, string>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString(
    'base64url',
  )
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url')
  return `${header}.${payload}.sig`
}

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), 'vibesec-phase4-'))
  temporaryDirectories.push(directory)
  return directory
}
