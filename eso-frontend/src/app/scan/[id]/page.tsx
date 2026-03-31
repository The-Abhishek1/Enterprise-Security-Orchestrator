// src/app/scan/[id]/page.tsx
'use client';
import { useParams } from 'next/navigation';
import { useEffect, useState, useCallback } from 'react';
import { scans } from '@/lib/api';
import { useScanWS } from '@/hooks/use-scan-ws';
import { usePoll } from '@/hooks/use-poll';
import WorkflowTimeline from '@/components/scan/workflow-timeline';
import ProposalPanel from '@/components/scan/proposal-panel';
import ReportViewer from '@/components/scan/report-viewer';
import LiveTerminal from '@/components/scan/live-terminal';

export default function ScanDetailPage() {
  const { id } = useParams() as { id: string };
  const [scan, setScan] = useState<any>(null);

  // WebSocket for real-time events
  const { events, latest, state: wsState, isTerminal, lastOf } = useScanWS(id);

  // Polling fallback — only active if WS not connected
  const usePolling = wsState !== 'connected';
  const isActive = !scan || !['completed', 'failed', 'timeout'].includes(scan?.status);
  const fetcher = useCallback(() => scans.status(id), [id]);
  const { data: pollData } = usePoll(fetcher, usePolling && isActive ? 5000 : 0, usePolling && isActive);

  // Merge poll data into scan state
  useEffect(() => { if (pollData) setScan(pollData); }, [pollData]);

  // Also fetch full status periodically for fields WebSocket doesn't carry (report, etc.)
  useEffect(() => {
    const load = () => scans.status(id).then(setScan).catch(() => {});
    load();
    // Refresh on terminal events
    if (isTerminal) { setTimeout(load, 1000); }
  }, [id, isTerminal]);

  // Refresh when level completes (to get updated findings count)
  useEffect(() => {
    if (latest?.type === 'level_complete' || latest?.type === 'analysis_done' || latest?.type === 'report_done') {
      scans.status(id).then(setScan).catch(() => {});
    }
  }, [latest, id]);

  if (!scan) return <div className="text-gray-500 py-20 text-center">Loading scan...</div>;

  const risk = scan.risk_summary || {};
  const dur = scan.duration ? `${(scan.duration / 60).toFixed(1)}m` : (scan.started_at ? 'Running...' : '—');
  const progress = scan.progress || 0;

  // Derive workflow step from WS events
  const wsStep = deriveStep(events);

  return (
    <div>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-6">
        <div>
          <h2 className="text-xl font-bold">{scan.target || 'Scan'}</h2>
          <p className="text-xs text-gray-500 font-mono mt-1">{id}</p>
        </div>
        <div className="flex items-center gap-3 self-start">
          <span className={`w-2 h-2 rounded-full ${wsState === 'connected' ? 'bg-green-500' : wsState === 'connecting' ? 'bg-yellow-500 animate-pulse' : 'bg-gray-600'}`}
            title={`WS: ${wsState}`} />
          <span className={`badge badge-${scan.status}`}>{scan.status}</span>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-5">
        {[
          { label: 'Progress', val: `${progress.toFixed(0)}%`, color: 'text-indigo-400' },
          { label: 'Tasks', val: `${scan.completed_tasks || 0}/${scan.total_tasks || 0}`, color: 'text-white' },
          { label: 'Findings', val: scan.findings_count || 0, color: 'text-cyan-400' },
          { label: 'Risk', val: (risk.overall_risk || '—').toUpperCase(), color: riskColor(risk.overall_risk) },
          { label: 'Duration', val: dur, color: 'text-gray-300' },
        ].map((s, i) => (
          <div key={i} className="glass p-3 sm:p-4 text-center">
            <p className={`text-lg sm:text-xl font-extrabold font-mono ${s.color}`}>{s.val}</p>
            <p className="text-[9px] sm:text-[10px] text-gray-500 uppercase tracking-widest mt-1">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-white/[0.04] rounded-full overflow-hidden mb-6">
        <div className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-cyan-400 transition-all duration-700" style={{ width: `${progress}%` }} />
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left — Workflow + Proposals */}
        <div className="space-y-5">
          <WorkflowTimeline scan={scan} wsStep={wsStep} />
          {scan.awaiting_approval && <ProposalPanel processId={id} onApproved={() => scans.status(id).then(setScan)} />}
        </div>

        {/* Right — Terminal + Report */}
        <div className="lg:col-span-2 space-y-5">
          <LiveTerminal events={events} />
          {scan.report && <ReportViewer report={scan.report} processId={id} />}
        </div>
      </div>
    </div>
  );
}

function riskColor(r: string) {
  return { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-cyan-400' }[r] || 'text-gray-500';
}

function deriveStep(events: any[]): number {
  // Map event types to workflow steps
  for (let i = events.length - 1; i >= 0; i--) {
    const t = events[i].type;
    if (t === 'complete') return 6;
    if (t === 'report_done' || t === 'report_start') return 5;
    if (t === 'proposal' || t === 'approval_needed') return 4;
    if (t === 'analysis_done' || t === 'risk_update') return 3;
    if (t === 'task_complete' || t === 'task_output' || t === 'task_start') return 2;
    if (t === 'level_start' || t === 'execution_start') return 2;
  }
  return 0;
}
