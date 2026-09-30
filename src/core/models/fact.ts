import type { ProtectedSensitiveValue } from '../../security/tokens.js'
import type { FindingConfidence } from './finding.js'
import type { SourceLocation } from './source-location.js'

export type FactContext =
  | 'client'
  | 'server'
  | 'edge'
  | 'config'
  | 'migration'
  | 'test'
  | 'fixture'
  | 'documentation'
  | 'generated'
  | 'unknown'

export type FactSource = Readonly<{
  extractor: string
  context: FactContext
  syntax: 'typescript' | 'javascript' | 'json' | 'toml' | 'dotenv' | 'sql' | 'text'
}>

type BaseFact<Kind extends string> = Readonly<{
  kind: Kind
  location: SourceLocation
  source: FactSource
  confidence: FindingConfidence
}>

export type SecretCandidateFact = BaseFact<'secret.candidate'> &
  Readonly<{
    secretType:
      | 'api_key'
      | 'bearer_token'
      | 'database_url'
      | 'jwt'
      | 'password'
      | 'private_key'
      | 'supabase_key'
      | 'webhook_secret'
      | 'unknown'
    bindingName?: string
    protectedValue: ProtectedSensitiveValue
    isPlaceholder: boolean
  }>

export type EnvironmentBindingFact = BaseFact<'environment.binding'> &
  Readonly<{
    name: string
    exposure: 'private' | 'client' | 'unknown'
    valueKind: 'literal' | 'reference' | 'unknown'
  }>

export type StackFact = BaseFact<'stack.evidence'> &
  Readonly<{
    stack: string
    version?: string
    evidenceType: 'dependency' | 'import' | 'config' | 'directory' | 'generated_asset'
  }>

export type SupabaseTableFact = BaseFact<'supabase.table'> &
  Readonly<{
    schema: string
    table: string
    operation: 'create' | 'alter' | 'reference'
  }>

export type SupabaseRlsFact = BaseFact<'supabase.rls'> &
  Readonly<{
    schema: string
    table: string
    enabled: boolean
  }>

export type SupabasePolicyFact = BaseFact<'supabase.policy'> &
  Readonly<{
    schema: string
    table: string
    policyName: string
    command: 'all' | 'select' | 'insert' | 'update' | 'delete'
    roles: readonly string[]
    hasUsingClause: boolean
    hasCheckClause: boolean
    referencesAuthUid: boolean
    isBroad: boolean
  }>

export type AuthGuardFact = BaseFact<'auth.guard'> &
  Readonly<{
    guardType: 'authentication' | 'role' | 'ownership'
    enforcement: 'client' | 'server' | 'unknown'
    subject?: string
  }>

export type ClientQueryFact = BaseFact<'client.query'> &
  Readonly<{
    provider: 'supabase' | 'unknown'
    resource: string
    operation: 'select' | 'insert' | 'update' | 'delete' | 'rpc'
    hasOwnershipFilter: boolean | 'unknown'
  }>

export type DangerousSinkFact = BaseFact<'dangerous.sink'> &
  Readonly<{
    sink:
      | 'eval'
      | 'new_function'
      | 'dangerously_set_inner_html'
      | 'inner_html'
      | 'document_write'
      | 'shell_exec'
      | 'raw_sql'
    input: 'constant' | 'dynamic' | 'unknown'
    sanitizer?: string
  }>

export type GitFileFact = BaseFact<'git.file'> &
  Readonly<{
    tracking: 'tracked' | 'untracked' | 'ignored' | 'unknown'
  }>

/**
 * Intermediate observations only. Facts deliberately have no severity,
 * remediation, impact, or final evidence status.
 */
export type Fact =
  | SecretCandidateFact
  | EnvironmentBindingFact
  | StackFact
  | SupabaseTableFact
  | SupabaseRlsFact
  | SupabasePolicyFact
  | AuthGuardFact
  | ClientQueryFact
  | DangerousSinkFact
  | GitFileFact

export const FACT_KINDS = [
  'secret.candidate',
  'environment.binding',
  'stack.evidence',
  'supabase.table',
  'supabase.rls',
  'supabase.policy',
  'auth.guard',
  'client.query',
  'dangerous.sink',
  'git.file',
] as const satisfies readonly Fact['kind'][]

export type FactKind = Fact['kind']
