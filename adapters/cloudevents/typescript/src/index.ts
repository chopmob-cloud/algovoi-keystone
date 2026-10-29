/**
 * @algovoi/cloudevents — emit an AlgoVoi keystone decision as a CloudEvents 1.0 event.
 *
 * The content-addressed execution_ref is the CloudEvents `id`; the keystone references live in the
 * event `data` and the standard `id`/`subject` attributes (no invented context extension
 * attributes, so the event stays spec-conformant). A consumer recomputes execution_ref from `data`
 * with only JCS (RFC 8785) + SHA-256. Byte-identical to algovoi-cloudevents (Python). Apache-2.0.
 */
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';

export const SHA256_PREFIX = 'sha256:' as const;
export const SPEC_VERSION = '1.0' as const;
export const TYPE_PREFIX = 'co.algovoi.keystone' as const;

export function executionRef(decisionRef: string, actionType: string, scope: string,
                             outcome: string, executedAtMs: number): string {
  // canonicalize() DROPS keys whose value is `undefined`, so an absent binding field used to
  // produce a digest over a reduced payload — and a verifier comparing that digest to an equally
  // reduced claim returned true for a document that never carried the field. Validate first.
  const fields: Array<[string, unknown]> = [
    ['decision_ref', decisionRef], ['action_type', actionType],
    ['scope', scope], ['outcome', outcome],
  ];
  for (const [name, value] of fields) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(`execution_ref: ${name} must be a non-empty string`);
    }
  }
  if (typeof executedAtMs !== 'number' || !Number.isFinite(executedAtMs)) {
    throw new Error('execution_ref: executed_at_ms must be a finite number');
  }
  const s = canonicalize({ decision_ref: decisionRef, action_type: actionType, scope,
                           outcome, executed_at_ms: Math.trunc(executedAtMs) });
  if (s === undefined) throw new Error('not JCS-canonicalisable');
  return SHA256_PREFIX + createHash('sha256').update(s).digest('hex');
}

function rfc3339(ms: number): string {
  return new Date(Math.trunc(ms)).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export interface Signal { score: number; method?: string; }
export interface ScanSignal { verdict: string; method?: string; }
export interface ToCloudEventOpts {
  decisionRef: string; actionType: string; scope: string; outcome: string; executedAtMs: number;
  source: string; stage?: string; eventId?: string; agentId?: string; publicKeyAlgorithm?: string;
  trust?: Signal; drift?: Signal; scan?: ScanSignal; trustQueryRef?: string; settlementRef?: string;
}

export function toCloudEvent(o: ToCloudEventOpts): Record<string, unknown> {
  const er = executionRef(o.decisionRef, o.actionType, o.scope, o.outcome, o.executedAtMs);
  const data: Record<string, unknown> = {
    execution_ref: er, decision_ref: o.decisionRef, action_type: o.actionType,
    scope: o.scope, outcome: o.outcome, executed_at_ms: Math.trunc(o.executedAtMs),
  };
  if (o.agentId !== undefined) data.agent_id = o.agentId;
  if (o.publicKeyAlgorithm !== undefined) data.public_key_algorithm = o.publicKeyAlgorithm;
  if (o.trust) data.trust = o.trust;
  if (o.drift) data.drift = o.drift;
  if (o.scan) data.scan = o.scan;
  if (o.trustQueryRef !== undefined) data.trust_query_ref = o.trustQueryRef;
  if (o.settlementRef !== undefined) data.settlement_ref = o.settlementRef;
  return {
    specversion: SPEC_VERSION,
    type: `${TYPE_PREFIX}.${o.stage ?? 'execution'}.v1`,
    source: o.source,
    id: o.eventId ?? er,
    subject: o.decisionRef,
    time: rfc3339(o.executedAtMs),
    datacontenttype: 'application/json',
    data,
  };
}

export function verifyCloudEventExecutionRef(event: Record<string, unknown>): boolean {
  try {
    const d = event?.data as Record<string, unknown> | undefined;
    if (!d || typeof d !== 'object') return false;
    if (typeof d.execution_ref !== 'string') return false;
    const r = executionRef(d.decision_ref as string, d.action_type as string, d.scope as string,
                           d.outcome as string, d.executed_at_ms as number);
    return r === d.execution_ref;
  } catch { return false; }
}
