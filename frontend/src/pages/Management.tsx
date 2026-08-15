import { useState } from 'react';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import {
  managementApi,
  type ManagementHypothesis,
} from '@/api/client';

const DEFAULT_THREAT_ID = 'TL-2026-1693';

const TENANTS = [
  { id: 'finance', label: 'Finance' },
  { id: 'energy', label: 'Energy' },
  { id: 'critical_infrastructure', label: 'Critical Infrastructure' },
];

export function Management() {
  const [searchParams, setSearchParams] = useSearchParams();
  const threatId = searchParams.get('threat_id')?.trim() || DEFAULT_THREAT_ID;
  const tenantId = searchParams.get('tenant')?.trim() || TENANTS[0].id;

  const updateParams = (key: 'tenant' | 'threat_id', value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value && value !== DEFAULT_THREAT_ID && key === 'threat_id') next.set(key, value);
    else if (key === 'threat_id') next.delete('threat_id');
    else if (value) next.set(key, value);
    else next.delete(key);
    setSearchParams(next, { replace: true });
  };

  const query = useQuery({
    queryKey: ['management-summary', threatId, tenantId],
    queryFn: () => managementApi.summary({ threat_id: threatId, tenant_id: tenantId }),
    retry: false,
  });

  const data = query.data;
  const error = query.error instanceof Error ? query.error.message : null;

  return (
    <div className="flex min-h-full flex-col">
      <Header title="Management" />
      <div className="flex-1 overflow-y-auto px-6 py-6">
        <div className="mx-auto max-w-7xl space-y-6">
          <section className="rounded-lg border border-sky-500/40 bg-sky-950/20 p-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h2 className="text-lg font-semibold text-white">Management summary and hunt hypotheses</h2>
                <p className="mt-2 max-w-4xl text-sm leading-6 text-sky-100/80">
                  Deterministic, offline-first summary of threat relevance, detection coverage, and the
                  highest-priority hunt hypotheses with per-rule Admiralty verdicts.
                </p>
              </div>
              <div className="flex flex-wrap items-end gap-4">
                <label className="block text-xs text-gray-400">
                  Threat
                  <input
                    type="text"
                    value={threatId}
                    onChange={event => updateParams('threat_id', event.target.value.trim())}
                    className="field mt-1 w-44"
                    placeholder={DEFAULT_THREAT_ID}
                  />
                </label>
                <label className="block text-xs text-gray-400">
                  Tenant
                  <select value={tenantId} onChange={event => updateParams('tenant', event.target.value)} className="field mt-1 w-44">
                    {TENANTS.map(tenant => <option key={tenant.id} value={tenant.id}>{tenant.label}</option>)}
                  </select>
                </label>
                <button
                  type="button"
                  onClick={() => query.refetch()}
                  disabled={query.isFetching}
                  className="primary-action disabled:opacity-40"
                >
                  {query.isFetching ? 'Refreshing...' : 'Refresh summary'}
                </button>
              </div>
            </div>
          </section>

          {error && (
            <section className="rounded-lg border border-red-500/50 bg-red-950/30 p-4 text-sm text-red-100">
              Management summary failed: {error}
            </section>
          )}

          {query.isLoading && (
            <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-8 text-sm text-gray-400">
              Computing management summary…
            </section>
          )}

          {data && (
            <>
              <section className="grid gap-4">
                <Panel title="Сводка">
                  <div className="space-y-3 p-4">
                    <p className="text-sm leading-6 text-gray-200">{data.bluf_ru}</p>
                    <div className="flex flex-wrap gap-x-8 gap-y-2 text-xs text-gray-500">
                      <span>Threat: <b className="text-gray-200">{data.title}{data.actor ? ` / ${data.actor}` : ''}</b></span>
                      <span>Relevance: <b className="font-mono text-mitre-accent">{Math.round(data.score)}% ({data.zone})</b></span>
                      <span>Tenant: <b className="text-gray-200">{data.tenant_name || data.tenant_id}</b></span>
                      <span>Hypotheses: <b className="text-gray-200">{data.hypotheses.length}</b></span>
                    </div>
                  </div>
                </Panel>

                <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  {Object.entries(data.status_counts).map(([status, count]) => (
                    <div key={status} className="rounded-lg border border-gray-800 bg-gray-950 p-4">
                      <div className="font-mono text-2xl font-semibold text-white">{count}</div>
                      <div className="mt-1 text-xs text-gray-500">{status}</div>
                    </div>
                  ))}
                  {Object.keys(data.status_counts).length === 0 && (
                    <div className="rounded-lg border border-gray-800 bg-gray-950 p-4 text-xs text-gray-500">No coverage counts.</div>
                  )}
                </section>

                <Panel title="Coverage by tactic">
                  <div className="grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-3">
                    {Object.entries(data.tactic_coverage).map(([tactic, ratio]) => (
                      <div key={tactic}>
                        <div className="mb-1 flex items-center justify-between text-xs">
                          <span className="text-gray-300">{tactic}</span>
                          <span className="font-mono text-gray-400">{Math.round(ratio * 100)}%</span>
                        </div>
                        <div className="h-2 w-full overflow-hidden rounded bg-gray-800">
                          <div className="h-full rounded bg-mitre-accent" style={{ width: `${Math.min(100, Math.max(0, ratio * 100))}%` }} />
                        </div>
                      </div>
                    ))}
                    {Object.keys(data.tactic_coverage).length === 0 && (
                      <p className="text-sm text-gray-500">No tactic coverage data.</p>
                    )}
                  </div>
                </Panel>

                <Panel title="Hunt hypotheses" badge={`${data.hypotheses.length} top`}>
                  {data.hypotheses.length === 0
                    ? <p className="p-4 text-sm text-gray-500">No hypotheses.</p>
                    : (
                      <div className="divide-y divide-gray-800">
                        {data.hypotheses.map(hypothesis => <HypothesisRow key={hypothesis.technique_id} hypothesis={hypothesis} />)}
                      </div>
                    )}
                </Panel>
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function HypothesisRow({ hypothesis }: { hypothesis: ManagementHypothesis }) {
  const [copied, setCopied] = useState(false);
  const { admiralty } = hypothesis;
  const aql = hypothesis.copy_ready_aql;

  return (
    <div className="p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded bg-mitre-accent/20 px-2 py-0.5 font-mono text-xs font-semibold text-mitre-accent">
          {hypothesis.technique_id}
        </span>
        {hypothesis.technique_name && <span className="text-xs font-medium text-sky-100/90">{hypothesis.technique_name}</span>}
        {hypothesis.tactic && <span className="text-xs text-gray-500">{hypothesis.tactic}</span>}
        <span className="text-xs text-gray-400">Admiralty: <b className="font-mono text-gray-200">{admiralty.letter}-{admiralty.digit}</b></span>
        <span className="rounded border border-gray-700 bg-gray-950 px-2 py-0.5 text-[10px] uppercase text-gray-500">
          {hypothesis.coverage_status}
        </span>
        {hypothesis.is_chokepoint && (
          <span className="rounded border border-amber-500/40 bg-amber-950/30 px-2 py-0.5 text-[10px] uppercase text-amber-200">
            Chokepoint
          </span>
        )}
      </div>

      <p className="mt-2 text-sm leading-6 text-gray-300">{hypothesis.text_ru}</p>
      <p className="mt-1 text-xs leading-5 text-gray-500">Статус: {hypothesis.coverage_status_ru}</p>

      {hypothesis.gap_marker_ru && (
        <p className="mt-1 text-xs font-semibold text-amber-300">{hypothesis.gap_marker_ru}</p>
      )}

      {hypothesis.expected_evidence_ru && (
        <p className="mt-1 text-xs leading-5 text-gray-500">{hypothesis.expected_evidence_ru}</p>
      )}

      {hypothesis.actor && (
        <p className="mt-1 text-xs text-gray-500">Actor: <span className="font-mono text-gray-300">{hypothesis.actor}</span></p>
      )}
      {hypothesis.threat_summary && (
        <p className="mt-1 text-xs leading-5 text-gray-500">Threat: {hypothesis.threat_summary}</p>
      )}

      <div className="mt-2 text-xs text-gray-500">
        Priority: <b className="font-mono text-gray-300">{hypothesis.priority.toFixed(3)}</b>
        {hypothesis.covering_rule_ids.length > 0 && (
          <> · Rules: <span className="font-mono">{hypothesis.covering_rule_ids.join(', ')}</span></>
        )}
        {hypothesis.secondary_blind_flags.length > 0 && (
          <> · Flags: <span className="font-mono">{hypothesis.secondary_blind_flags.join(', ')}</span></>
        )}
      </div>

      {hypothesis.data_sources.length > 0 && (
        <div className="mt-2 space-y-1">
          <span className="text-[10px] uppercase tracking-wide text-gray-500">Data sources</span>
          <div className="flex flex-wrap gap-1">
            {hypothesis.data_sources.map(source => (
              <span key={source} className="rounded border border-gray-800 bg-gray-950 px-1.5 py-0.5 font-mono text-[10px] text-gray-400">{source}</span>
            ))}
          </div>
        </div>
      )}

      {hypothesis.candidate_chokepoints.length > 0 && (
        <div className="mt-2 space-y-1">
          <span className="text-[10px] uppercase tracking-wide text-amber-300/80">Candidate chokepoints</span>
          {hypothesis.candidate_chokepoints.map(point => (
            <p key={point.field} className="rounded border border-amber-500/20 bg-amber-950/10 px-2 py-1 text-xs text-amber-100/80">
              <span className="font-mono">{point.field}</span> — {point.note_ru}
            </p>
          ))}
        </div>
      )}

      {hypothesis.iocs.length > 0 && (
        <div className="mt-2 space-y-1">
          <span className="text-[10px] uppercase tracking-wide text-sky-300">IOCs</span>
          {hypothesis.iocs.map((ioc, index) => (
            <p key={`${ioc.ioc_type}-${ioc.value}-${index}`} className="rounded border border-sky-500/20 bg-sky-950/10 px-2 py-1 text-xs text-sky-100/80">
              <span className="font-mono">{ioc.value}</span> <span className="text-sky-300/70">[{ioc.ioc_type}]</span> — {ioc.note_ru}
            </p>
          ))}
        </div>
      )}

      {admiralty.rationale_ru && (
        <p className="mt-2 rounded border border-gray-800 bg-gray-950/50 p-2 text-xs leading-5 text-gray-500">
          {admiralty.rationale_ru}
        </p>
      )}

      {aql && (
        <div className="mt-3">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold text-gray-300">Copy-ready AQL: {aql.rule_id}</span>
            <div className="flex items-center gap-2">
              <span className={aql.copy_ready
                ? 'rounded border border-emerald-500/40 bg-emerald-950/30 px-2 py-0.5 text-[10px] uppercase text-emerald-200'
                : 'rounded border border-amber-500/40 bg-amber-950/30 px-2 py-0.5 text-[10px] uppercase text-amber-200'}>
                {aql.copy_ready ? 'Copy-ready' : 'Not copy-ready'}
              </span>
              <span className="text-[10px] text-gray-600">{aql.log_source}</span>
              <button
                type="button"
                className="secondary-action !py-1"
                disabled={!aql.copy_ready || !aql.aql}
                onClick={async () => {
                  if (!aql.aql) return;
                  await navigator.clipboard.writeText(aql.aql);
                  setCopied(true);
                  window.setTimeout(() => setCopied(false), 1500);
                }}
              >
                {copied ? 'Copied' : 'Copy AQL'}
              </button>
            </div>
          </div>
          {aql.warnings.length > 0 && (
            <ul className="mt-2 space-y-1">
              {aql.warnings.map(warning => (
                <li key={warning.code} className="rounded border border-amber-500/30 bg-amber-950/20 px-2 py-1 text-xs text-amber-200">
                  {warning.message}
                </li>
              ))}
            </ul>
          )}
          {aql.sufficiency && aql.sufficiency.blind_fields.length > 0 && (
            <p className="mt-2 text-xs text-gray-500">
              Blind fields: <span className="font-mono">{aql.sufficiency.blind_fields.join(', ')}</span>
            </p>
          )}
          <pre className="mt-2 max-h-48 overflow-y-auto rounded border border-gray-800 bg-black/40 p-3 font-mono text-[11px] leading-5 text-emerald-200">
            {aql.aql || '(no AQL text)'}
          </pre>
        </div>
      )}
    </div>
  );
}

function Panel({ title, badge, children }: { title: string; badge?: string; children: ReactNode }) {
  return (
    <section className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="flex items-center justify-between gap-3 border-b border-gray-800 px-4 py-3">
        <h2 className="text-sm font-semibold text-white">{title}</h2>
        {badge && <span className="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-[10px] uppercase text-gray-500">{badge}</span>}
      </div>
      {children}
    </section>
  );
}