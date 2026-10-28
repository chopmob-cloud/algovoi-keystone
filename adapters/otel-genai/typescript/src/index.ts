/**
 * @algovoi/otel-genai — map an AlgoVoi keystone decision to OpenTelemetry gen_ai.agent.*
 * attributes, carrying execution_ref as an open, recomputable cross-producer key.
 *
 * The standard gen_ai.agent.* attributes are producer-emitted and opaque. This adapter emits them
 * from a keystone decision and attaches our own vendor-namespaced refs under algovoi.keystone.*
 * (never inside the controlled gen_ai.agent.* namespace, which the OpenTelemetry GenAI SIG governs).
 * A consumer recomputes execution_ref from the span alone with only JCS (RFC 8785) + SHA-256.
 *
 * Byte-identical to algovoi-otel-genai (Python). Apache-2.0.
 */
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';

export const SHA256_PREFIX = 'sha256:' as const;

export function executionRef(decisionRef: string, actionType: string, scope: string,
                             outcome: string, executedAtMs: number): string {
  const s = canonicalize({
    decision_ref: decisionRef, action_type: actionType, scope,
    outcome, executed_at_ms: Math.trunc(executedAtMs),
  });
  if (s === undefined) throw new Error('not JCS-canonicalisable');
  return SHA256_PREFIX + createHash('sha256').update(s).digest('hex');
}

export interface Signal { score: number; method?: string; }
export interface ScanSignal { verdict: string; method?: string; }

export interface ToGenAiOpts {
  decisionRef: string; actionType: string; scope: string; outcome: string; executedAtMs: number;
  agentId?: string; publicKeyAlgorithm?: string; trust?: Signal; drift?: Signal; scan?: ScanSignal;
  trustQueryRef?: string;
}

export function toGenAiAttributes(o: ToGenAiOpts): Record<string, unknown> {
  const a: Record<string, unknown> = {};
  if (o.agentId !== undefined) a['gen_ai.agent.id'] = o.agentId;
  if (o.publicKeyAlgorithm !== undefined) a['gen_ai.agent.public_key.algorithm'] = o.publicKeyAlgorithm;
  a['gen_ai.agent.capability'] = o.scope;
  if (o.trust) { a['gen_ai.agent.trust.score'] = o.trust.score; if (o.trust.method) a['gen_ai.agent.trust.method'] = o.trust.method; }
  if (o.drift) { a['gen_ai.agent.drift.score'] = o.drift.score; if (o.drift.method) a['gen_ai.agent.drift.method'] = o.drift.method; }
  if (o.scan) { a['gen_ai.agent.scan.verdict'] = o.scan.verdict; if (o.scan.method) a['gen_ai.agent.scan.method'] = o.scan.method; }
  // our own namespace, never gen_ai.agent.*
  a['algovoi.keystone.execution_ref'] = executionRef(o.decisionRef, o.actionType, o.scope, o.outcome, o.executedAtMs);
  a['algovoi.keystone.decision_ref'] = o.decisionRef;
  a['algovoi.keystone.action_type'] = o.actionType;
  a['algovoi.keystone.scope'] = o.scope;
  a['algovoi.keystone.outcome'] = o.outcome;
  a['algovoi.keystone.executed_at_ms'] = Math.trunc(o.executedAtMs);
  if (o.trustQueryRef !== undefined) a['algovoi.keystone.trust_query_ref'] = o.trustQueryRef;
  return a;
}

export function verifyGenAiExecutionRef(attrs: Record<string, unknown>): boolean {
  try {
    const r = executionRef(attrs['algovoi.keystone.decision_ref'] as string,
                           attrs['algovoi.keystone.action_type'] as string,
                           attrs['algovoi.keystone.scope'] as string,
                           attrs['algovoi.keystone.outcome'] as string,
                           Number(attrs['algovoi.keystone.executed_at_ms']));
    return r === attrs['algovoi.keystone.execution_ref'];
  } catch { return false; }
}
