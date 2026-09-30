import type { RedactionBoundary } from '../../security/redaction.js'
import type { PathFlavor } from '../../utils/paths.js'
import {
  FACT_KINDS,
  type Fact,
  type FactContext,
  type FactSource,
} from '../models/fact.js'
import { FINDING_CONFIDENCES } from '../models/finding.js'
import {
  readBoolean,
  readEnum,
  readExactObject,
  readNonEmptyString,
  readOwnDataProperty,
  readStringArray,
} from './primitives.js'
import { validateSourceLocation } from './source-location.js'

declare const validatedFactBrand: unique symbol

export type ValidatedFact = Fact & { readonly [validatedFactBrand]: true }

const BASE_KEYS = ['kind', 'location', 'source', 'confidence'] as const
const SOURCE_CONTEXTS = [
  'client',
  'server',
  'edge',
  'config',
  'migration',
  'test',
  'fixture',
  'documentation',
  'generated',
  'unknown',
] as const satisfies readonly FactContext[]
const SOURCE_SYNTAXES = [
  'typescript',
  'javascript',
  'json',
  'toml',
  'dotenv',
  'sql',
  'text',
] as const satisfies readonly FactSource['syntax'][]

export function validateFact(
  value: unknown,
  boundary: RedactionBoundary,
  flavor: PathFlavor,
): ValidatedFact {
  const kind = readEnum(readOwnDataProperty(value, 'kind'), FACT_KINDS)
  const specificKeys = keysForKind(kind)
  const object = readExactObject(
    value,
    [...BASE_KEYS, ...specificKeys],
    [...BASE_KEYS, ...requiredKeysForKind(kind)],
  )
  const base = {
    location: validateSourceLocation(object['location'], flavor),
    source: validateFactSource(object['source']),
    confidence: readEnum(object['confidence'], FINDING_CONFIDENCES),
  }

  let fact: Fact
  switch (kind) {
    case 'secret.candidate': {
      boundary.assertProtectedValue(object['protectedValue'])
      const bindingName =
        object['bindingName'] === undefined
          ? undefined
          : readNonEmptyString(object['bindingName'])
      fact = {
        ...base,
        kind: 'secret.candidate',
        secretType: readEnum(object['secretType'], [
          'api_key',
          'bearer_token',
          'database_url',
          'jwt',
          'password',
          'private_key',
          'supabase_key',
          'webhook_secret',
          'unknown',
        ] as const),
        ...(bindingName === undefined ? {} : { bindingName }),
        protectedValue: object['protectedValue'],
        isPlaceholder: readBoolean(object['isPlaceholder']),
      }
      break
    }
    case 'environment.binding':
      fact = {
        ...base,
        kind: 'environment.binding',
        name: readNonEmptyString(object['name']),
        exposure: readEnum(object['exposure'], [
          'private',
          'client',
          'unknown',
        ] as const),
        valueKind: readEnum(object['valueKind'], [
          'literal',
          'reference',
          'unknown',
        ] as const),
      }
      break
    case 'stack.evidence': {
      const version =
        object['version'] === undefined
          ? undefined
          : readNonEmptyString(object['version'])
      fact = {
        ...base,
        kind: 'stack.evidence',
        stack: readNonEmptyString(object['stack']),
        ...(version === undefined ? {} : { version }),
        evidenceType: readEnum(object['evidenceType'], [
          'dependency',
          'import',
          'config',
          'directory',
          'generated_asset',
        ] as const),
      }
      break
    }
    case 'supabase.table':
      fact = {
        ...base,
        kind: 'supabase.table',
        schema: readNonEmptyString(object['schema']),
        table: readNonEmptyString(object['table']),
        operation: readEnum(object['operation'], [
          'create',
          'alter',
          'reference',
        ] as const),
      }
      break
    case 'supabase.rls':
      fact = {
        ...base,
        kind: 'supabase.rls',
        schema: readNonEmptyString(object['schema']),
        table: readNonEmptyString(object['table']),
        enabled: readBoolean(object['enabled']),
      }
      break
    case 'supabase.policy':
      fact = {
        ...base,
        kind: 'supabase.policy',
        schema: readNonEmptyString(object['schema']),
        table: readNonEmptyString(object['table']),
        policyName: readNonEmptyString(object['policyName']),
        command: readEnum(object['command'], [
          'all',
          'select',
          'insert',
          'update',
          'delete',
        ] as const),
        roles: readStringArray(object['roles']),
        hasUsingClause: readBoolean(object['hasUsingClause']),
        hasCheckClause: readBoolean(object['hasCheckClause']),
        referencesAuthUid: readBoolean(object['referencesAuthUid']),
        isBroad: readBoolean(object['isBroad']),
      }
      break
    case 'auth.guard': {
      const subject =
        object['subject'] === undefined
          ? undefined
          : readNonEmptyString(object['subject'])
      fact = {
        ...base,
        kind: 'auth.guard',
        guardType: readEnum(object['guardType'], [
          'authentication',
          'role',
          'ownership',
        ] as const),
        enforcement: readEnum(object['enforcement'], [
          'client',
          'server',
          'unknown',
        ] as const),
        ...(subject === undefined ? {} : { subject }),
      }
      break
    }
    case 'client.query':
      fact = {
        ...base,
        kind: 'client.query',
        provider: readEnum(object['provider'], ['supabase', 'unknown'] as const),
        resource: readNonEmptyString(object['resource']),
        operation: readEnum(object['operation'], [
          'select',
          'insert',
          'update',
          'delete',
          'rpc',
        ] as const),
        hasOwnershipFilter:
          typeof object['hasOwnershipFilter'] === 'boolean'
            ? object['hasOwnershipFilter']
            : readEnum(object['hasOwnershipFilter'], ['unknown'] as const),
      }
      break
    case 'dangerous.sink': {
      const sanitizer =
        object['sanitizer'] === undefined
          ? undefined
          : readNonEmptyString(object['sanitizer'])
      fact = {
        ...base,
        kind: 'dangerous.sink',
        sink: readEnum(object['sink'], [
          'eval',
          'new_function',
          'dangerously_set_inner_html',
          'inner_html',
          'document_write',
          'shell_exec',
          'raw_sql',
        ] as const),
        input: readEnum(object['input'], ['constant', 'dynamic', 'unknown'] as const),
        ...(sanitizer === undefined ? {} : { sanitizer }),
      }
      break
    }
    case 'git.file':
      fact = {
        ...base,
        kind: 'git.file',
        tracking: readEnum(object['tracking'], [
          'tracked',
          'untracked',
          'ignored',
          'unknown',
        ] as const),
      }
      break
  }

  const frozen = deepFreezeFact(fact)
  boundary.assertCanonicalValueSafe(frozen)
  return frozen as ValidatedFact
}

function validateFactSource(value: unknown): FactSource {
  const object = readExactObject(
    value,
    ['extractor', 'context', 'syntax'],
    ['extractor', 'context', 'syntax'],
  )
  return Object.freeze({
    extractor: readNonEmptyString(object['extractor']),
    context: readEnum(object['context'], SOURCE_CONTEXTS),
    syntax: readEnum(object['syntax'], SOURCE_SYNTAXES),
  })
}

function keysForKind(kind: Fact['kind']): readonly string[] {
  switch (kind) {
    case 'secret.candidate':
      return ['secretType', 'bindingName', 'protectedValue', 'isPlaceholder']
    case 'environment.binding':
      return ['name', 'exposure', 'valueKind']
    case 'stack.evidence':
      return ['stack', 'version', 'evidenceType']
    case 'supabase.table':
      return ['schema', 'table', 'operation']
    case 'supabase.rls':
      return ['schema', 'table', 'enabled']
    case 'supabase.policy':
      return [
        'schema',
        'table',
        'policyName',
        'command',
        'roles',
        'hasUsingClause',
        'hasCheckClause',
        'referencesAuthUid',
        'isBroad',
      ]
    case 'auth.guard':
      return ['guardType', 'enforcement', 'subject']
    case 'client.query':
      return ['provider', 'resource', 'operation', 'hasOwnershipFilter']
    case 'dangerous.sink':
      return ['sink', 'input', 'sanitizer']
    case 'git.file':
      return ['tracking']
  }
}

function requiredKeysForKind(kind: Fact['kind']): readonly string[] {
  return keysForKind(kind).filter(
    (key) => !['bindingName', 'version', 'subject', 'sanitizer'].includes(key),
  )
}

function deepFreezeFact<Value>(value: Value): Value {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreezeFact(nested)
    Object.freeze(value)
  }
  return value
}
