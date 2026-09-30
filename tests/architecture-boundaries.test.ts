import { readFileSync, readdirSync } from 'node:fs'
import { builtinModules } from 'node:module'
import path from 'node:path'

import ts from 'typescript'
import { describe, expect, it } from 'vitest'

import * as publicApi from '../src/index.js'

describe('architectural capability boundaries', () => {
  it('keeps sensitive and Node capabilities out of rules and reporters', () => {
    const roots = ['src/core/rules', 'src/rules', 'src/reporters']
    const violations: string[] = []

    for (const root of roots) {
      const absoluteRoot = path.resolve(root)
      let files: string[]
      try {
        files = readdirSync(absoluteRoot, {
          recursive: true,
          encoding: 'utf8',
        }).filter((file) => file.endsWith('.ts'))
      } catch {
        continue
      }

      for (const file of files) {
        const source = readFileSync(path.join(absoluteRoot, file), 'utf8')
        const imports = collectModuleSpecifiers(source, file)
        if (imports.some(isRestrictedModule)) violations.push(`${root}/${file}`)
      }
    }

    expect(violations).toEqual([])
  })

  it('does not expose raw-secret or unrestricted ID capabilities publicly', () => {
    expect(Object.keys(publicApi)).not.toContain('RedactionBoundary')
    expect(Object.keys(publicApi)).not.toContain('SensitiveValue')
    expect(Object.keys(publicApi)).not.toContain('consumeSensitiveValue')
    expect(Object.keys(publicApi)).not.toContain('createFindingId')
    expect(Object.keys(publicApi)).not.toContain('finalizeFinding')
    expect(Object.keys(publicApi)).not.toContain('inventoryLocalTextFiles')
    expect(Object.keys(publicApi)).not.toContain('inventoryLocalFiles')
    expect(Object.keys(publicApi)).not.toContain('extractPrivateKeyFacts')
    expect(Object.keys(publicApi)).not.toContain(
      'extractPrivateKeyFactsFromLocalTarget',
    )
    expect(Object.keys(publicApi)).not.toContain('privateKeyMaterialRule')
    expect(Object.keys(publicApi)).not.toContain('resolveGitProvenance')
    expect(Object.keys(publicApi)).not.toContain('extractLocalScanFacts')
  })

  it('recognizes template-literal and non-static capability imports', () => {
    expect(collectModuleSpecifiers('void import(`node:fs`)', 'test.ts')).toContain(
      'node:fs',
    )
    expect(
      collectModuleSpecifiers('void import(`node:${capability}`)', 'test.ts'),
    ).toContain('<dynamic-module>')
    expect(collectModuleSpecifiers('require(`child_process`)', 'test.ts')).toContain(
      'child_process',
    )
  })
})

function collectModuleSpecifiers(source: string, file: string): readonly string[] {
  const sourceFile = ts.createSourceFile(
    file,
    source,
    ts.ScriptTarget.Latest,
    false,
    ts.ScriptKind.TS,
  )
  const modules: string[] = []

  function visit(node: ts.Node): void {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier !== undefined &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      modules.push(node.moduleSpecifier.text)
    }
    if (
      ts.isCallExpression(node) &&
      (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(node.expression) && node.expression.text === 'require'))
    ) {
      const [specifier] = node.arguments
      if (
        specifier !== undefined &&
        (ts.isStringLiteral(specifier) || ts.isNoSubstitutionTemplateLiteral(specifier))
      ) {
        modules.push(specifier.text)
      } else {
        modules.push('<dynamic-module>')
      }
    }
    ts.forEachChild(node, visit)
  }

  visit(sourceFile)
  return modules
}

function isRestrictedModule(specifier: string): boolean {
  const bareSpecifier = specifier.replace(/^node:/, '')
  return (
    specifier === '<dynamic-module>' ||
    specifier.startsWith('node:') ||
    builtinModules.includes(bareSpecifier) ||
    specifier.includes('/security/')
  )
}
