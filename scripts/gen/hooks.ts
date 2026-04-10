#!/usr/bin/env tsx
/**
 * generate-hooks.ts — TanStack Query hook codegen from ts-codegen contract clients
 *
 * Reads @cosmwasm/ts-codegen .client.ts files, extracts query methods,
 * and generates TanStack Query hooks with indexer-first / chain-fallback.
 *
 * Usage:
 *   pnpm generate-hooks          # generate hooks
 *   pnpm generate-hooks --check  # verify generated files are up-to-date (CI)
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync } from 'node:fs';
import { resolve, dirname, basename } from 'node:path';

// ── Types ──────────────────────────────────────────────────────────

interface ContractManifest {
  outputDir: string;
  typesDir: string;
  contracts: ContractEntry[];
}

interface ContractEntry {
  name: string;
  slug: string;
  source: string;
  typesSource: string;
  contractConfigKey: string;
  indexerBase: string;
  indexerMethods: string[];
}

interface QueryMethod {
  /** camelCase method name from interface (e.g. "infusionById") */
  methodName: string;
  /** Parameter fields: { paramName: typeName } */
  params: { name: string; type: string; optional: boolean }[];
  /** Return type (e.g. "Config", "InfusionsResponse") */
  returnType: string;
  /** snake_case query message key (e.g. "infusion_by_id") */
  queryMsgKey: string;
  /** The inner params object as snake_case fields mapping to camelCase values */
  queryMsgParams: { snakeKey: string; camelValue: string }[];
}

// ── Parsing ────────────────────────────────────────────────────────

/**
 * Extract query methods from a ts-codegen ReadOnlyInterface block.
 * Matches lines like:
 *   config: () => Promise<Config>;
 *   infusion: ({ addr, id }: { addr: Addr; id: number; }) => Promise<Infusion>;
 */
function parseReadOnlyInterface(source: string): Omit<QueryMethod, 'queryMsgKey' | 'queryMsgParams'>[] {
  // Find the ReadOnlyInterface block
  const ifaceMatch = source.match(
    /interface\s+\w+ReadOnlyInterface\s*\{([\s\S]*?)\n\}/
  );
  if (!ifaceMatch) return [];

  const block = ifaceMatch[1];
  const methods: Omit<QueryMethod, 'queryMsgKey' | 'queryMsgParams'>[] = [];

  // Skip contractAddress property, match method signatures
  // Pattern: methodName: (destructured?) => Promise<Type>;
  const methodRegex = /(\w+)\s*:\s*\(([^)]*)\)\s*=>\s*Promise<(\w+)>/g;
  let m: RegExpExecArray | null;

  while ((m = methodRegex.exec(block)) !== null) {
    const methodName = m[1];
    const paramsRaw = m[2].trim();
    const returnType = m[3];

    const params: { name: string; type: string; optional: boolean }[] = [];

    if (paramsRaw) {
      // Parse destructured params like: { addr, id }: { addr: Addr; id: number; }
      // Extract the type definition part (after the colon and opening brace)
      const typeMatch = paramsRaw.match(/\{[^}]*\}\s*:\s*\{([^}]*)\}/);
      if (typeMatch) {
        const typeBlock = typeMatch[1];
        // Parse individual fields: "addr: Addr;" or "burner?: Addr;"
        const fieldRegex = /(\w+)(\?)?:\s*([^;]+)/g;
        let fm: RegExpExecArray | null;
        while ((fm = fieldRegex.exec(typeBlock)) !== null) {
          params.push({
            name: fm[1],
            type: fm[2] ? fm[3].trim() : fm[3].trim(),
            optional: !!fm[2],
          });
        }
      }
    }

    methods.push({ methodName, params, returnType });
  }

  return methods;
}

/**
 * Extract query message shapes from QueryClient class methods.
 * Matches the queryContractSmart call to get snake_case keys and param mapping.
 *
 * Example:
 *   return this.client.queryContractSmart(this.contractAddress, {
 *     infusion_by_id: {
 *       id
 *     }
 *   });
 */
function parseQueryClient(source: string): Map<string, { queryMsgKey: string; queryMsgParams: { snakeKey: string; camelValue: string }[] }> {
  const result = new Map<string, { queryMsgKey: string; queryMsgParams: { snakeKey: string; camelValue: string }[] }>();

  // Find each method in the QueryClient class
  // Pattern: methodName = async (...) => { ... queryContractSmart(this.contractAddress, { msg }) }
  const methodRegex = /(\w+)\s*=\s*async\s*\([^)]*\)[^{]*\{[\s\S]*?queryContractSmart\(this\.contractAddress,\s*\{[\s]*(\w+):\s*\{([^}]*)\}/g;
  let m: RegExpExecArray | null;

  while ((m = methodRegex.exec(source)) !== null) {
    const methodName = m[1];
    const queryMsgKey = m[2];
    const paramsBlock = m[3].trim();

    const queryMsgParams: { snakeKey: string; camelValue: string }[] = [];

    if (paramsBlock) {
      // Parse lines like "addr," or "id" or "collection_addr: collectionAddr,"
      const paramLines = paramsBlock.split(/[,\n]/).map(l => l.trim()).filter(Boolean);
      for (const line of paramLines) {
        const colonMatch = line.match(/^(\w+)\s*:\s*(\w+)$/);
        if (colonMatch) {
          // Explicit mapping: snake_key: camelValue
          queryMsgParams.push({ snakeKey: colonMatch[1], camelValue: colonMatch[2] });
        } else {
          // Shorthand: paramName (same key in both)
          const nameMatch = line.match(/^(\w+)$/);
          if (nameMatch) {
            queryMsgParams.push({ snakeKey: nameMatch[1], camelValue: nameMatch[1] });
          }
        }
      }
    }

    result.set(methodName, { queryMsgKey, queryMsgParams });
  }

  return result;
}

/**
 * Extract type names imported in the client file that are used as return types.
 * Returns the full import line content for reconstruction.
 */
function parseImportedTypes(source: string): string[] {
  const importMatch = source.match(/import\s*\{([^}]+)\}\s*from\s*"\.\/\w+\.types"/);
  if (!importMatch) return [];
  return importMatch[1]
    .split(',')
    .map(t => t.trim())
    .filter(Boolean);
}

/**
 * Combine interface methods with QueryClient message shapes.
 */
function extractQueryMethods(source: string): QueryMethod[] {
  const interfaceMethods = parseReadOnlyInterface(source);
  const clientMethods = parseQueryClient(source);

  return interfaceMethods.map(m => {
    const clientInfo = clientMethods.get(m.methodName);
    return {
      ...m,
      queryMsgKey: clientInfo?.queryMsgKey ?? camelToSnake(m.methodName),
      queryMsgParams: clientInfo?.queryMsgParams ?? m.params.map(p => ({
        snakeKey: camelToSnake(p.name),
        camelValue: p.name,
      })),
    };
  });
}

// ── Code Generation ────────────────────────────────────────────────

function generateHooksFile(contract: ContractEntry, methods: QueryMethod[], allTypes: string[]): string {
  const typesFile = basename(contract.typesSource, '.ts');
  const returnTypes = new Set(methods.map(m => m.returnType));
  const usedTypes = allTypes.filter(t => returnTypes.has(t));

  // Also collect param types that are custom (not primitives)
  const primitives = new Set(['string', 'number', 'boolean', 'undefined', 'null', 'any']);
  for (const m of methods) {
    for (const p of m.params) {
      // Strip null/undefined unions for the base type
      const baseType = p.type.replace(/\s*\|\s*null/, '').replace(/\s*\|\s*undefined/, '').trim();
      if (!primitives.has(baseType.toLowerCase()) && allTypes.includes(baseType)) {
        usedTypes.push(baseType);
      }
    }
  }
  const uniqueTypes = [...new Set(usedTypes)].sort();

  const lines: string[] = [];

  // Header
  lines.push(`// AUTO-GENERATED by scripts/generate-hooks.ts`);
  lines.push(`// Source: ${basename(contract.source)}`);
  lines.push(`// Do not edit — re-run \`pnpm generate-hooks\` to update.`);
  lines.push(`'use client';`);
  lines.push('');
  lines.push(`import { useQuery } from '@tanstack/react-query';`);
  lines.push(`import { queryContractSmart, queryREST } from '@/lib/queries/fetchers';`);
  lines.push(`import { CONTRACTS } from '@/lib/wallet/config';`);

  if (uniqueTypes.length > 0) {
    lines.push(`import type {`);
    for (const t of uniqueTypes) {
      lines.push(`  ${t},`);
    }
    lines.push(`} from '@/lib/types/${typesFile}';`);
  }

  lines.push('');
  lines.push(`const KEY = '${contract.slug}';`);
  lines.push('');

  // indexerWithFallback helper
  lines.push(`async function indexerWithFallback<T>(`);
  lines.push(`  queryMsg: Record<string, unknown>,`);
  lines.push(`  indexerPath?: string,`);
  lines.push(`): Promise<T> {`);
  lines.push(`  if (indexerPath) {`);
  lines.push(`    try { return await queryREST<T>(indexerPath); } catch { /* fall through */ }`);
  lines.push(`  }`);
  lines.push(`  return queryContractSmart<T>(CONTRACTS.${contract.contractConfigKey}, queryMsg);`);
  lines.push(`}`);
  lines.push('');

  // Generate each hook
  for (const method of methods) {
    const hookName = `use${pascal(method.methodName)}`;
    const hasParams = method.params.length > 0;
    const hasIndexer = contract.indexerMethods.includes(method.queryMsgKey);

    // Build the indexer path
    const indexerPath = hasIndexer
      ? `'${contract.indexerBase}/${method.queryMsgKey}'`
      : 'undefined';

    // Determine which params are required (for `enabled` guard)
    const requiredParams = method.params.filter(p => !p.optional);
    const needsEnabled = requiredParams.length > 0;

    if (hasParams) {
      // Build param type inline
      const paramTypeParts = method.params.map(p =>
        `${p.name}${p.optional ? '?' : ''}: ${p.type}`
      );

      lines.push(`export function ${hookName}(params: { ${paramTypeParts.join('; ')} }) {`);
    } else {
      lines.push(`export function ${hookName}() {`);
    }

    // Query key
    const keyParts = [`KEY`, `'${method.queryMsgKey}'`];
    if (hasParams) {
      for (const p of method.params) {
        keyParts.push(`params.${p.name}`);
      }
    }

    lines.push(`  return useQuery({`);
    lines.push(`    queryKey: [${keyParts.join(', ')}],`);

    // Query function
    const queryMsgObj = buildQueryMsgObject(method, hasParams);
    lines.push(`    queryFn: () => indexerWithFallback<${method.returnType}>(`);
    lines.push(`      ${queryMsgObj},`);
    if (hasIndexer) {
      lines.push(`      ${indexerPath},`);
    }
    lines.push(`    ),`);

    // Enabled guard
    if (needsEnabled) {
      const conditions = requiredParams.map(p => `params.${p.name} !== undefined`);
      lines.push(`    enabled: ${conditions.join(' && ')},`);
    }

    lines.push(`  });`);
    lines.push(`}`);
    lines.push('');
  }

  return lines.join('\n');
}

function buildQueryMsgObject(method: QueryMethod, hasParams: boolean): string {
  if (method.queryMsgParams.length === 0) {
    return `{ ${method.queryMsgKey}: {} }`;
  }

  const innerParts = method.queryMsgParams.map(p => {
    const value = hasParams ? `params.${p.camelValue}` : p.camelValue;
    if (p.snakeKey === p.camelValue) {
      // Shorthand only works if key === value identifier
      return `${p.snakeKey}: ${value}`;
    }
    return `${p.snakeKey}: ${value}`;
  });

  return `{ ${method.queryMsgKey}: { ${innerParts.join(', ')} } }`;
}

// ── Utilities ──────────────────────────────────────────────────────

function camelToSnake(s: string): string {
  return s.replace(/([A-Z])/g, '_$1').toLowerCase();
}

function pascal(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// ── Main ───────────────────────────────────────────────────────────

function main() {
  const checkMode = process.argv.includes('--check');
  const scriptDir = dirname(new URL(import.meta.url).pathname);
  const manifestPath = resolve(scriptDir, 'hook-manifest.json');

  if (!existsSync(manifestPath)) {
    console.error(`Manifest not found: ${manifestPath}`);
    process.exit(1);
  }

  const manifest: ContractManifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
  const projectRoot = resolve(scriptDir, '..');
  const outputDir = resolve(projectRoot, manifest.outputDir);
  const typesDir = resolve(projectRoot, manifest.typesDir);

  // Ensure output directories exist
  if (!checkMode) {
    mkdirSync(outputDir, { recursive: true });
    mkdirSync(typesDir, { recursive: true });
  }

  let allUpToDate = true;

  for (const contract of manifest.contracts) {
    const sourcePath = resolve(scriptDir, contract.source);
    const typesSourcePath = resolve(scriptDir, contract.typesSource);

    if (!existsSync(sourcePath)) {
      console.error(`Source not found: ${sourcePath}`);
      console.error(`  Configured in manifest as: ${contract.source}`);
      process.exit(1);
    }

    if (!existsSync(typesSourcePath)) {
      console.error(`Types source not found: ${typesSourcePath}`);
      console.error(`  Configured in manifest as: ${contract.typesSource}`);
      process.exit(1);
    }

    const clientSource = readFileSync(sourcePath, 'utf-8');
    const typesSource = readFileSync(typesSourcePath, 'utf-8');

    // Extract query methods from client file
    const methods = extractQueryMethods(clientSource);
    if (methods.length === 0) {
      console.warn(`No query methods found in ${contract.name} (${sourcePath})`);
      continue;
    }

    // Get all exported types from the types file
    const allTypes = parseImportedTypes(clientSource);

    // Generate hooks file
    const hooksContent = generateHooksFile(contract, methods, allTypes);
    const hooksPath = resolve(outputDir, `use-${contract.slug}.ts`);

    // Copy types file to types dir
    const typesDestPath = resolve(typesDir, basename(contract.typesSource));

    if (checkMode) {
      // Verify files are up-to-date
      if (!existsSync(hooksPath)) {
        console.error(`Missing generated file: ${hooksPath}`);
        allUpToDate = false;
        continue;
      }
      const existing = readFileSync(hooksPath, 'utf-8');
      if (existing !== hooksContent) {
        console.error(`Out of date: ${hooksPath}`);
        allUpToDate = false;
      }
      if (!existsSync(typesDestPath)) {
        console.error(`Missing types file: ${typesDestPath}`);
        allUpToDate = false;
      } else {
        const existingTypes = readFileSync(typesDestPath, 'utf-8');
        if (existingTypes !== typesSource) {
          console.error(`Out of date: ${typesDestPath}`);
          allUpToDate = false;
        }
      }
    } else {
      // Write generated files
      writeFileSync(hooksPath, hooksContent);
      console.log(`Generated: ${hooksPath}`);
      console.log(`  ${methods.length} query hooks from ${contract.name}`);

      copyFileSync(typesSourcePath, typesDestPath);
      console.log(`Copied types: ${typesDestPath}`);
    }

    // Check CONTRACTS config for the key
    const configPath = resolve(projectRoot, 'lib/wallet/config.ts');
    if (existsSync(configPath)) {
      const configSource = readFileSync(configPath, 'utf-8');
      if (!configSource.includes(`${contract.contractConfigKey}:`)) {
        console.warn(`\n  ⚠ Contract key "${contract.contractConfigKey}" not found in CONTRACTS config.`);
        console.warn(`  Add it to lib/wallet/config.ts:`);
        console.warn(`    export const CONTRACTS = {`);
        console.warn(`      ...existing,`);
        console.warn(`      ${contract.contractConfigKey}: '',  // ← add this`);
        console.warn(`    };`);
      }
    }
  }

  if (checkMode) {
    if (allUpToDate) {
      console.log('All generated hooks are up-to-date.');
    } else {
      console.error('\nGenerated hooks are out of date. Run `pnpm generate-hooks` to update.');
      process.exit(1);
    }
  }
}

main();
