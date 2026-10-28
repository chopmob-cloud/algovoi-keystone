/**
 * @algovoi/keystone-vc — emit an AlgoVoi keystone decision as a W3C Verifiable Credential
 * (Data Model 2.0). Uses our own KeystoneExecutionCredential type and @context; the content-
 * addressed executionRef is the credentialSubject id. A consumer recomputes it from the subject
 * with JCS (RFC 8785) + SHA-256. Byte-identical to algovoi-keystone-vc (Python). Apache-2.0.
 */
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';

export const SHA256_PREFIX = 'sha256:' as const;
export const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2' as const;
export const KEYSTONE_CONTEXT = 'https://docs.algovoi.co.uk/contexts/keystone/v1' as const;
export const CREDENTIAL_TYPE = 'KeystoneExecutionCredential' as const;

export function executionRef(decisionRef: string, actionType: string, scope: string,
                             outcome: string, executedAtMs: number): string {
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
export interface ToVcOpts {
  decisionRef: string; actionType: string; scope: string; outcome: string; executedAtMs: number;
  issuer: string; credentialId?: string; agentId?: string; publicKeyAlgorithm?: string;
  trust?: Signal; drift?: Signal; scan?: ScanSignal; trustQueryRef?: string; settlementRef?: string;
}

export function toVerifiableCredential(o: ToVcOpts): Record<string, unknown> {
  const er = executionRef(o.decisionRef, o.actionType, o.scope, o.outcome, o.executedAtMs);
  const subject: Record<string, unknown> = {
    id: er, executionRef: er, decisionRef: o.decisionRef, actionType: o.actionType,
    scope: o.scope, outcome: o.outcome, executedAtMs: Math.trunc(o.executedAtMs),
  };
  if (o.agentId !== undefined) subject.agentId = o.agentId;
  if (o.publicKeyAlgorithm !== undefined) subject.publicKeyAlgorithm = o.publicKeyAlgorithm;
  if (o.trust) { subject.trustScore = o.trust.score; if (o.trust.method) subject.trustMethod = o.trust.method; }
  if (o.drift) { subject.driftScore = o.drift.score; if (o.drift.method) subject.driftMethod = o.drift.method; }
  if (o.scan) { subject.scanVerdict = o.scan.verdict; if (o.scan.method) subject.scanMethod = o.scan.method; }
  if (o.trustQueryRef !== undefined) subject.trustQueryRef = o.trustQueryRef;
  if (o.settlementRef !== undefined) subject.settlementRef = o.settlementRef;
  const vc: Record<string, unknown> = {
    '@context': [VC_CONTEXT, KEYSTONE_CONTEXT],
    type: ['VerifiableCredential', CREDENTIAL_TYPE],
    issuer: o.issuer,
    validFrom: rfc3339(o.executedAtMs),
    credentialSubject: subject,
  };
  if (o.credentialId !== undefined) vc.id = o.credentialId;
  return vc;
}

export function verifyVcExecutionRef(vc: Record<string, unknown>): boolean {
  try {
    const s = vc.credentialSubject as Record<string, unknown>;
    const r = executionRef(s.decisionRef as string, s.actionType as string, s.scope as string,
                           s.outcome as string, Number(s.executedAtMs));
    return r === s.executionRef && r === s.id;
  } catch { return false; }
}
