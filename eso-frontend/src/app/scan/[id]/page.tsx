// src/app/scan/[id]/page.tsx
'use client';
import { useParams } from 'next/navigation';
import { useEffect, useState, useCallback } from 'react';
import { scans, api } from '@/lib/api';
import { useScanWS } from '@/hooks/use-scan-ws';
import { usePoll } from '@/hooks/use-poll';
import WorkflowTimeline from '@/components/scan/workflow-timeline';
import ProposalPanel from '@/components/scan/proposal-panel';
import ReportViewer from '@/components/scan/report-viewer';
import LiveTerminal from '@/components/scan/live-terminal';

export default function ScanDetailPage() {
  const { id } = useParams() as { id: string };
  const [scan, setScan] = useState<any>(null);
  const [fromDb, setFromDb] = useState(false);

  // Try in-memory status first, fall back to DB
  const fetchScan = useCallback(async () => {
    try {
      const s = await scans.status(id);
      if (s && s.status) return s;
    } catch {}
    // Fallback: try DB history
    try {
      const s = await api.get(`/auth/scans/${id}`);
      if (s) { setFromDb(true); return s; }
    } catch {}
    return null;
  }, [id]);

  // WebSocket for live events
  const { events, latest, state: wsState, isTerminal } = useScanWS(id);

  // Polling — active if scan is running and WS is not connected
  const isActive = !scan || !['completed', 'failed', 'timeout'].includes(scan?.status);
  const usePolling = wsState !== 'connected';
  const { data: pollData } = usePoll(fetchScan, usePolling && isActive ? 5000 : 0, usePolling && isActive);

  useEffect(() => { if (pollData) setScan(pollData); }, [pollData]);

  // Initial load
  useEffect(() => { fetchScan().then(s => { if (s) setScan(s); }); }, [fetchScan]);

  // Refresh on key WS events
  useEffect(() => {
    if (latest?.type === 'level_complete' || latest?.type === 'analysis_done' || latest?.type === 'report_done' || latest?.type === 'complete') {
      fetchScan().then(s => { if (s) setScan(s); });
    }
  }, [latest, fetchScan]);

  if (!scan) return (
    <div className="text-center py-20">
      <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
      <p className="text-gray-500">Loading scan...</p>
    </div>
  );

  const risk = scan.risk_summary || {};
  const riskLevel = risk.overall_risk || scan.risk_level || '—';
  const riskScore = risk.overall_score || scan.risk_score || 0;
  const findingsCount = scan.findings_count || 0;
  const completedTasks = scan.completed_tasks || 0;
  const totalTasks = scan.total_tasks || 0;
  const progress = scan.progress || (totalTasks > 0 ? (completedTasks / totalTasks * 100) : 0);
  const dur = scan.duration ? `${(scan.duration / 60).toFixed(1)}m`
    : scan.duration_seconds ? `${(scan.duration_seconds / 60).toFixed(1)}m`
    : '—';

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
          {!fromDb && (
            <span className={`w-2 h-2 rounded-full ${wsState === 'connected' ? 'bg-green-500' : wsState === 'connecting' ? 'bg-yellow-500 animate-pulse' : 'bg-gray-600'}`}
              title={`WS: ${wsState}`} />
          )}
          <span className={`badge badge-${scan.status}`}>{scan.status}</span>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-5">
        {[
          { label: 'Progress', val: `${progress.toFixed(0)}%`, color: 'text-indigo-400' },
          { label: 'Tasks', val: `${completedTasks}/${totalTasks}`, color: 'text-white' },
          { label: 'Findings', val: findingsCount, color: 'text-cyan-400' },
          { label: 'Risk', val: String(riskLevel).toUpperCase(), color: riskColor(riskLevel) },
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
        <div className="space-y-5">
          <WorkflowTimeline scan={scan} wsStep={wsStep > 0 ? wsStep : undefined} />
          {scan.awaiting_approval && <ProposalPanel processId={id} onApproved={() => fetchScan().then(s => { if (s) setScan(s); })} />}
        </div>
        <div className="lg:col-span-2 space-y-5">
          {events.length > 0 ? (
            <LiveTerminal events={events} />
          ) : (
            <div className="glass p-5">
              <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-3 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-green-500" /> Scan Info
              </h3>
              <div className="font-mono text-[11px] text-gray-400 bg-black/30 rounded-lg p-4 border border-white/[0.04] space-y-1">
                <p><span className="text-indigo-400">[{scan.status}]</span> {scan.target} — {completedTasks}/{totalTasks} tasks</p>
                <p><span className="text-cyan-400">Risk:</span> {String(riskLevel).toUpperCase()} ({Number(riskScore).toFixed(1)})</p>
                {findingsCount > 0 && <p><span className="text-green-400">Findings:</span> {findingsCount}</p>}
                {scan.goal && <p><span className="text-gray-500">Goal:</span> {scan.goal}</p>}
                {fromDb && <p className="text-gray-600">Loaded from scan history (server was restarted)</p>}
              </div>
            </div>
          )}
          {(scan.report) && <ReportViewer report={scan.report} processId={id} />}
        </div>
      </div>
    </div>
  );
}

function riskColor(r: string) {
  return { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-cyan-400' }[r] || 'text-gray-500';
}

function deriveStep(events: any[]): number {
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
