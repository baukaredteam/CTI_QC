import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { hypothesesApi, type Hypothesis } from '@/api/client';
import clsx from 'clsx';

const TENANTS = [
  { id: '', label: 'All tenants' },
  { id: 'finance', label: 'Finance' },
  { id: 'energy', label: 'Energy' },
  { id: 'critical_infrastructure', label: 'Critical Infrastructure' },
];

const STATUSES: Array<{ value: string; label: string }> = [
  { value: '', label: 'All statuses' },
  { value: 'proposed', label: 'Proposed' },
  { value: 'validated', label: 'Validated' },
  { value: 'rejected', label: 'Rejected' },
];

const STATUS_STYLE: Record<string, string> = {
  proposed: 'border-sky-500/40 bg-sky-950/30 text-sky-200',
  validated: 'border-emerald-500/40 bg-emerald-950/30 text-emerald-200',
  rejected: 'border-red-500/40 bg-red-950/30 text-red-200',
};

export function Hypotheses() {
  const qc = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const tenantId = searchParams.get('tenant')?.trim() || '';
  const status = searchParams.get('status')?.trim() || '';

  const updateParams = (key: 'tenant' | 'status', value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    setSearchParams(next, { replace: true });
  };

  const query = useQuery({
    queryKey: ['hypotheses', tenantId, status],
    queryFn: () => hypothesesApi.list({ tenant_id: tenantId || undefined, status: status || undefined }),
    retry: false,
  });

  const updateStatus = useMutation({
    mutationFn: ({ id, next }: { id: string; next: 'validated' | 'rejected' }) =>
      hypothesesApi.updateStatus(id, next),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hypotheses'] }),
  });

  const error = query.error instanceof Error ? query.error.message : null;

  return (
    <div className="flex min-h-full flex-col">
      <Header title="Hypothesis Scanner" />
      <div className="flex-1 overflow-y-auto px-6 py-6">
        <div className="mx-auto max-w-7xl space-y-6">
          <section className="rounded-lg border border-sky-500/40 bg-sky-950/20 p-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h2 className="text-lg font-semibold text-white">Persisted hunt hypotheses</h2>
                <p className="mt-2 max-w-4xl text-sm leading-6 text-sky-100/80">
                  Hypothesis feed scanner output. Each row is one falsifiable hunt hypothesis derived
                  from the top-priority coverage blind spots of a scanned threat — review, validate,
                  or reject to route it into the hunt workflow.
                </p>
              </div>
              <div className="flex flex-wrap items-end gap-4">
                <label className="block text-xs text-gray-400">
                  Tenant
                  <select value={tenantId} onChange={event => updateParams('tenant', event.target.value)} className="field mt-1 w-44">
                    {TENANTS.map(tenant => <option key={tenant.id} value={tenant.id}>{tenant.label}</option>)}
                  </select>
                </label>
                <label className="block text-xs text-gray-400">
                  Status
                  <select value={status} onChange={event => updateParams('status', event.target.value)} className="field mt-1 w-44">
                    {STATUSES.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}
                  </select>
                </label>
                <button
                  type="button"
                  onClick={() => query.refetch()}
                  disabled={query.isFetching}
                  className="primary-action disabled:opacity-40"
                >
                  {query.isFetching ? 'Refreshing...' : 'Refresh'}
                </button>
              </div>
            </div>
          </section>

          {error && (
            <section className="rounded-lg border border-red-500/50 bg-red-950/30 p-4 text-sm text-red-100">
              Hypothesis list failed: {error}
            </section>
          )}

          {query.isLoading && (
            <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-8 text-sm text-gray-400">
              Loading hypotheses…
            </section>
          )}

          {query.isSuccess && (
            <section className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900/60">
              <div className="flex items-center justify-between gap-3 border-b border-gray-800 px-4 py-3">
                <h2 className="text-sm font-semibold text-white">Scan results</h2>
                <span className="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-[10px] uppercase text-gray-500">{query.data.length} suggested</span>
              </div>
              {query.data.length === 0
                ? <p className="p-6 text-sm text-gray-500">No hypotheses match the filters.</p>
                : (
                  <div className="divide-y divide-gray-800">
                    {query.data.map(row => <HypothesisRow key={row.id} row={row} onUpdate={(next) => updateStatus.mutate({ id: row.id, next })} />)}
                  </div>
                )}
            </section>
          )}
        </div>
      </div>
    </div>
  );
}

function HypothesisRow({ row, onUpdate }: { row: Hypothesis; onUpdate: (next: 'validated' | 'rejected') => void }) {
  const hypothesis = row;
  const { admiralty } = hypothesis;
  const canReview = hypothesis.status === 'proposed';

  return (
    <div className="p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded bg-mitre-accent/20 px-2 py-0.5 font-mono text-xs font-semibold text-mitre-accent">
          {hypothesis.technique_id}
        </span>
        {hypothesis.technique_name && <span className="text-xs font-medium text-sky-100/90">{hypothesis.technique_name}</span>}
        {hypothesis.tactic && <span className="text-xs text-gray-500">{hypothesis.tactic}</span>}
        <span className={clsx('rounded border px-2 py-0.5 text-[10px] uppercase', STATUS_STYLE[hypothesis.status] ?? 'border-gray-700 bg-gray-950 text-gray-400')}>
          {hypothesis.status}
        </span>
        <span className="rounded border border-gray-700 bg-gray-950 px-2 py-0.5 text-[10px] uppercase text-gray-500">
          {hypothesis.coverage_status}
        </span>
        <span className="text-xs text-gray-400">Admiralty: <b className="font-mono text-gray-200">{admiralty.letter}-{admiralty.digit}</b></span>
        <span className="text-xs text-gray-500">Priority: <b className="font-mono text-gray-300">{hypothesis.priority.toFixed(3)}</b></span>
      </div>

      <p className="mt-2 text-sm leading-6 text-gray-300">{hypothesis.text_ru}</p>
      {hypothesis.threat_summary && (
        <p className="mt-1 text-xs leading-5 text-gray-500">Threat: {hypothesis.threat_summary}</p>
      )}
      {hypothesis.expected_evidence_ru && (
        <p className="mt-1 text-xs leading-5 text-gray-500">{hypothesis.expected_evidence_ru}</p>
      )}

      {hypothesis.actor && (
        <p className="mt-1 text-xs text-gray-500">Actor: <span className="font-mono text-gray-300">{hypothesis.actor}</span></p>
      )}
      {hypothesis.sectors.length > 0 && (
        <p className="mt-1 text-xs text-gray-500">Sectors: {hypothesis.sectors.join(', ')}</p>
      )}
      {hypothesis.data_sources.length > 0 && (
        <div className="mt-1 space-y-1">
          <span className="text-[10px] uppercase tracking-wide text-gray-500">Data sources</span>
          <div className="flex flex-wrap gap-1">
            {hypothesis.data_sources.map(source => (
              <span key={source} className="rounded border border-gray-800 bg-gray-950 px-1.5 py-0.5 font-mono text-[10px] text-gray-400">{source}</span>
            ))}
          </div>
        </div>
      )}

      {hypothesis.covering_rule_ids.length > 0 && (
        <p className="mt-1 text-xs text-gray-500">Rules: <span className="font-mono">{hypothesis.covering_rule_ids.join(', ')}</span></p>
      )}

      {hypothesis.chokepoints.length > 0 && (
        <div className="mt-2 space-y-1">
          <span className="text-[10px] uppercase tracking-wide text-amber-300">Chokepoints</span>
          {hypothesis.chokepoints.map(point => (
            <p key={point.field} className="rounded border border-amber-500/30 bg-amber-950/20 px-2 py-1 text-xs text-amber-100">
              <span className="font-mono">{point.field}</span> — {point.note_ru}
            </p>
          ))}
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

      <div className="mt-3 flex items-center gap-2 text-xs text-gray-600">
        <span>Threat: <b className="font-mono text-gray-400">{hypothesis.threat_id}</b></span>
        <span>· Tenant: <b className="text-gray-400">{hypothesis.tenant_id}</b></span>
      </div>

{canReview && (
        <div className="mt-3 flex gap-2">
          <button type="button" onClick={() => onUpdate('validated')} className="secondary-action !border-emerald-500/50 !text-emerald-200">
            Validate
          </button>
          <button type="button" onClick={() => onUpdate('rejected')} className="secondary-action !border-red-500/50 !text-red-300">
            Reject
          </button>
        </div>
      )}
    </div>
  );
}