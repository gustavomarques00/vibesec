import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { scanLocalProject } from '../src/application/scan-local-project.js'
import { ScanKernelContext } from '../src/core/scan/scan-kernel-context.js'
import { extractAuthGuardFacts } from '../src/extractors/auth-guard-extractor.js'
import { extractClientQueryFacts } from '../src/extractors/client-query-extractor.js'
import { extractDangerousSinkFacts } from '../src/extractors/dangerous-sink-extractor.js'
import { extractSupabaseSqlFacts } from '../src/extractors/supabase-sql-extractor.js'
import { clientQueryMissingAuthzRule } from '../src/rules/client-query-missing-authz-rule.js'
import { dynamicEvalRule } from '../src/rules/dynamic-eval-rule.js'
import { dynamicRawSqlRule } from '../src/rules/dynamic-raw-sql-rule.js'
import { dynamicShellExecRule } from '../src/rules/dynamic-shell-exec-rule.js'
import { frontendOnlyAuthRule } from '../src/rules/frontend-only-auth-rule.js'
import { storageRoleAuthRule } from '../src/rules/storage-role-auth-rule.js'
import { unsafeHtmlSinkRule } from '../src/rules/unsafe-html-sink-rule.js'
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

describe('Phase 5 AUTH', () => {
  it('flags frontend-only role checks as suspicious', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const facts = extractAuthGuardFacts(
      'src/components/Admin.tsx',
      'if (isAdmin) { return <Panel /> }\n',
    )
    scan.evaluateRule(frontendOnlyAuthRule, scan.createRuleContext(facts))
    const findings = scan.finalizeScan()
    expect(findings.some((finding) => finding.ruleId === 'VS-AUTH-001')).toBe(true)
    expect(findings[0]?.status).toBe('suspicious')
    scan.close()
  })

  it('does not flag client guards when server enforcement exists', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const client = extractAuthGuardFacts(
      'src/components/Admin.tsx',
      'if (isAdmin) { return <Panel /> }\n',
    )
    const server = extractAuthGuardFacts(
      'server/auth.ts',
      'export function requireAuth() { return true }\n',
    )
    scan.evaluateRule(
      frontendOnlyAuthRule,
      scan.createRuleContext([...client, ...server]),
    )
    expect(scan.finalizeScan()).toHaveLength(0)
    scan.close()
  })

  it('flags storage role reads but ignores supabase auth token keys', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const bad = extractAuthGuardFacts(
      'src/auth.ts',
      'const role = localStorage.getItem("isAdmin")\n',
    )
    const ok = extractAuthGuardFacts(
      'src/session.ts',
      'localStorage.getItem("sb-xyz-auth-token")\n',
    )
    expect(ok.some((fact) => fact.subject?.startsWith('storage:'))).toBe(false)
    scan.evaluateRule(storageRoleAuthRule, scan.createRuleContext(bad))
    const findings = scan.finalizeScan()
    expect(findings.some((finding) => finding.ruleId === 'VS-AUTH-002')).toBe(true)
    scan.close()
  })

  it('ignores role mentions inside comments', () => {
    const facts = extractAuthGuardFacts(
      'src/x.ts',
      '// if (isAdmin) show panel\nconst x = 1\n',
    )
    expect(facts).toHaveLength(0)
  })
})

describe('Phase 5 AUTHZ', () => {
  it('requires authorization for client queries without ownership/RLS', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const queries = extractClientQueryFacts(
      'src/client.ts',
      "const rows = await supabase.from('notes').select('*')\n",
    )
    scan.evaluateRule(clientQueryMissingAuthzRule, scan.createRuleContext(queries))
    const findings = scan.finalizeScan()
    expect(findings[0]?.ruleId).toBe('VS-AUTHZ-001')
    expect(findings[0]?.status).toBe('requires_authorization')
    expect(findings[0]?.description.toLowerCase()).not.toContain('confirmed idor')
    scan.close()
  })

  it('suppresses AUTHZ when ownership filter or RLS policy is observed', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const queries = extractClientQueryFacts(
      'src/client.ts',
      "await supabase.from('notes').select('*').eq('user_id', uid)\n",
    )
    const policies = extractSupabaseSqlFacts(
      'supabase/migrations/001.sql',
      'CREATE POLICY owner ON public.notes FOR SELECT TO authenticated USING (auth.uid() = user_id);',
    )
    scan.evaluateRule(
      clientQueryMissingAuthzRule,
      scan.createRuleContext([...queries, ...policies]),
    )
    expect(scan.finalizeScan()).toHaveLength(0)
    scan.close()
  })
})

describe('Phase 5 DANG', () => {
  it('flags dynamic eval and ignores constant eval', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const dynamic = extractDangerousSinkFacts('src/a.ts', 'eval(userInput)\n')
    const constant = extractDangerousSinkFacts('src/b.ts', 'eval("1+1")\n')
    scan.evaluateRule(
      dynamicEvalRule,
      scan.createRuleContext([...dynamic, ...constant]),
    )
    const findings = scan.finalizeScan()
    expect(findings).toHaveLength(1)
    expect(findings[0]?.ruleId).toBe('VS-DANG-001')
    expect(findings[0]?.status).toBe('suspicious')
    scan.close()
  })

  it('flags unsafe HTML sinks and suppresses sanitized ones', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const unsafe = extractDangerousSinkFacts('src/App.tsx', 'el.innerHTML = userHtml\n')
    const safe = extractDangerousSinkFacts(
      'src/Safe.tsx',
      'el.innerHTML = DOMPurify.sanitize(userHtml)\n',
    )
    scan.evaluateRule(unsafeHtmlSinkRule, scan.createRuleContext([...unsafe, ...safe]))
    const findings = scan.finalizeScan()
    expect(findings).toHaveLength(1)
    expect(findings[0]?.ruleId).toBe('VS-DANG-002')
    expect(findings[0]?.description.toLowerCase()).not.toContain('xss confirmed')
    scan.close()
  })

  it('flags dynamic shell and raw SQL on server paths', () => {
    const scan = ScanKernelContext.create({ pathFlavor: 'posix' })
    const shell = extractDangerousSinkFacts('server/run.ts', 'exec(`ls ${dir}`)\n')
    const sql = extractDangerousSinkFacts(
      'server/db.ts',
      'db.query(`select * from users where id = ${id}`)\n',
    )
    scan.evaluateRule(dynamicShellExecRule, scan.createRuleContext(shell))
    scan.evaluateRule(dynamicRawSqlRule, scan.createRuleContext(sql))
    const findings = scan.finalizeScan()
    const ids = findings.map((finding) => finding.ruleId)
    expect(ids).toContain('VS-DANG-003')
    expect(ids).toContain('VS-DANG-004')
    scan.close()
  })

  it('ignores dangerous API names inside strings', () => {
    const facts = extractDangerousSinkFacts(
      'src/docs.ts',
      'const tip = "never call eval(userInput) in production"\n',
    )
    expect(facts).toHaveLength(0)
  })
})

describe('Phase 5 orchestration', () => {
  it('scans a representative fixture without executing target code', async () => {
    const root = await temporaryDirectory()
    await mkdir(path.join(root, 'src'), { recursive: true })
    await mkdir(path.join(root, 'server'), { recursive: true })
    await writeFile(
      path.join(root, 'src', 'Admin.tsx'),
      'export const x = () => { if (isAdmin) return null }\n',
    )
    await writeFile(
      path.join(root, 'src', 'page.tsx'),
      "await client.from('notes').select('*')\neval(code)\n",
    )
    await writeFile(
      path.join(root, 'server', 'run.ts'),
      'import { exec } from "node:child_process"\nexec(cmd)\n',
    )
    await writeFile(
      path.join(root, 'payload.js'),
      'throw new Error("TARGET_MUST_NOT_EXECUTE")\n',
    )

    const result = await scanLocalProject(root, {
      pathFlavor: flavor,
      format: 'json',
    })
    const report = JSON.parse(result.output) as {
      findings: { ruleId: string }[]
    }
    const ids = report.findings.map((finding) => finding.ruleId)
    expect(ids).toContain('VS-AUTH-001')
    expect(ids).toContain('VS-AUTHZ-001')
    expect(ids).toContain('VS-DANG-001')
    expect(ids).toContain('VS-DANG-003')
    expect(result.output).not.toContain('TARGET_MUST_NOT_EXECUTE')
  })
})

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), 'vibesec-phase5-'))
  temporaryDirectories.push(directory)
  return directory
}
