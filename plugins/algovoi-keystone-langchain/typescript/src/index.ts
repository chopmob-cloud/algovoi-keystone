/**
 * @algovoi/keystone-langchain -- carry an AlgoVoi keystone decision into a LangChain run trace.
 *
 * A keystone decision's content-addressed execution_ref is attached to a LangChain run as metadata
 * and a tag, under the vendor namespace `algovoi.keystone.*` (never inside a LangChain reserved
 * field). A consumer recomputes execution_ref from the run metadata alone with only JCS (RFC 8785)
 * + SHA-256, confirming the recorded action is consistent with the decision that authorized it.
 *
 * `keystoneConfig(...)` returns a RunnableConfig (a plain object LangChain accepts) for
 * `chain.invoke(x, keystoneConfig(...))`. The core (`keystoneTraceMetadata` /
 * `verifyTraceExecutionRef`) is framework-neutral. Byte-identical to algovoi-keystone-langchain
 * (Python). Apache-2.0.
 */
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';

export const SHA256_PREFIX = 'sha256:' as const;
export const NAMESPACE = 'algovoi.keystone' as const;
export const OUTCOMES = ['COMMITTED', 'SKIPPED', 'FAILED', 'REVERSED'] as const;

const K_EXEC = `${NAMESPACE}.execution_ref`;
const K_DECISION = `${NAMESPACE}.decision_ref`;
const K_ACTION = `${NAMESPACE}.action_type`;
const K_SCOPE = `${NAMESPACE}.scope`;
const K_OUTCOME = `${NAMESPACE}.outcome`;
const K_TS = `${NAMESPACE}.executed_at_ms`;
const K_AGENT = `${NAMESPACE}.agent_id`;
const K_TQ = `${NAMESPACE}.trust_query_ref`;

export function executionRef(decisionRef: string, actionType: string, scope: string,
                            outcome: string, executedAtMs: number): string {
  const s = canonicalize({
    decision_ref: decisionRef, action_type: actionType, scope,
    outcome, executed_at_ms: Math.trunc(executedAtMs),
  });
  if (s === undefined) throw new Error('not JCS-canonicalisable');
  return SHA256_PREFIX + createHash('sha256').update(s).digest('hex');
}

export interface KeystoneTraceInput {
  decisionRef: string;
  actionType: string;
  scope: string;
  outcome: string;
  executedAtMs: number;
  agentId?: string;
  trustQueryRef?: string;
}

export function keystoneTraceMetadata(o: KeystoneTraceInput): Record<string, unknown> {
  const md: Record<string, unknown> = {
    [K_EXEC]: executionRef(o.decisionRef, o.actionType, o.scope, o.outcome, o.executedAtMs),
    [K_DECISION]: o.decisionRef,
    [K_ACTION]: o.actionType,
    [K_SCOPE]: o.scope,
    [K_OUTCOME]: o.outcome,
    [K_TS]: Math.trunc(o.executedAtMs),
  };
  if (o.agentId !== undefined) md[K_AGENT] = o.agentId;
  if (o.trustQueryRef !== undefined) md[K_TQ] = o.trustQueryRef;
  return md;
}

/** A LangChain RunnableConfig carrying the keystone metadata and an execution_ref tag. */
export function keystoneConfig(o: KeystoneTraceInput): { metadata: Record<string, unknown>; tags: string[] } {
  const md = keystoneTraceMetadata(o);
  return { metadata: md, tags: [`${K_EXEC}=${md[K_EXEC] as string}`] };
}

export function verifyTraceExecutionRef(metadata: Record<string, unknown>): boolean {
  try {
    const r = executionRef(metadata[K_DECISION] as string, metadata[K_ACTION] as string,
                           metadata[K_SCOPE] as string, metadata[K_OUTCOME] as string,
                           Number(metadata[K_TS]));
    return r === metadata[K_EXEC];
  } catch {
    return false;
  }
}
