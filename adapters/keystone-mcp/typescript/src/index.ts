/**
 * @algovoi/keystone-mcp — the open keystone verification core for MCP.
 *
 * Pure functions that recompute and verify the decision-bound execution_ref. These are what an MCP
 * server (any MCP TypeScript host using @modelcontextprotocol/sdk) exposes as tools. This is the
 * OPEN verifier; it does not run the cross-party composition engine. Byte-identical to
 * algovoi-keystone-mcp (Python). Apache-2.0.
 */
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';

export const SHA256_PREFIX = 'sha256:' as const;

export function executionRef(decisionRef: string, actionType: string, scope: string,
                             outcome: string, executedAtMs: number): string {
  const s = canonicalize({ decision_ref: decisionRef, action_type: actionType, scope,
                           outcome, executed_at_ms: Math.trunc(executedAtMs) });
  if (s === undefined) throw new Error('not JCS-canonicalisable');
  return SHA256_PREFIX + createHash('sha256').update(s).digest('hex');
}

export interface VerifyResult { ok: boolean; computed: string | null; claimed: string; }

export function verifyExecutionRef(decisionRef: string, actionType: string, scope: string,
                                   outcome: string, executedAtMs: number,
                                   claimedExecutionRef: string): VerifyResult {
  try {
    const computed = executionRef(decisionRef, actionType, scope, outcome, executedAtMs);
    return { ok: computed === claimedExecutionRef, computed, claimed: claimedExecutionRef };
  } catch {
    return { ok: false, computed: null, claimed: claimedExecutionRef };
  }
}

/**
 * The two MCP tool descriptors, ready to register on an MCP server
 * (@modelcontextprotocol/sdk): keystone_execution_ref and keystone_verify.
 */
export const KEYSTONE_MCP_TOOLS = [
  { name: 'keystone_execution_ref', description: 'Recompute the decision-bound keystone execution_ref (JCS + SHA-256).' },
  { name: 'keystone_verify', description: 'Recompute the keystone execution_ref and confirm it matches a claimed value.' },
] as const;
