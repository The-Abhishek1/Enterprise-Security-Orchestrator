// src/app/scan/[id]/page.tsx
'use client';
import { useParams } from 'next/navigation';
import { useEffect, useState, useCallback } from 'react';
import { scans } from '@/lib/api';
import { usePoll } from '@/hooks/use-poll';
import { useScanWS } from '@/hooks/use-scan-ws';
import WorkflowTimeline from '@/components/scan/workflow-timeline';
import ProposalPanel from '@/components/scan/proposal-panel';
import ReportViewer from '@/components/scan/report-viewer';
import LiveTerminal from '@/components/scan/live-terminal';

export default function ScanDetailPage() {
  const { id } = useParams() as { id: string };
  const [scan, setScan] = useState<any>(null);

  // WebSocket for real-time events
  const ws = useScanWS(id);

  // Polling fallback — runs alongside WS, less frequent
  const isActive = !scan || !['completed', 'failed', 'timeout'].includes(scan?.status);
  const fetcher = useCallback(() => scans.status(id), [id]);
  const { data: pollData } = usePoll(fetcher, isActive ? 5000 : 0, isActive);

  // Update scan state from polling
  useEffect(() => { if (pollData) setScan(pollData); }, [pollData]);

  if (!scan) return (
    <div className="flex items-center justify-center py-20">
      <div className="text-center">
        <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
        <p className="text-sm text-gray-500">Connecting to scan...</p>
      </div>
    </div>
  );

  const risk = scan.risk_summary || {};
  const dur = scan.duration ? `${(scan.duration / 60).toFixed(1)}m` : (scan.started_at ? 'Running...' : '—');
  const progress = scan.progress || 0;

  return (
    <div>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-6">
        <div>
          <h2 className="text-xl font-bold">{scan.target || 'Scan'}</h2>
          <p className="text-xs text-gray-500 font-mono mt-1">{id}</p>
        </div>
        <div className="flex items-center gap-2 self-start">
          <span className={`badge badge-${scan.status}`}>{scan.status}</span>
          <span className={`w-2 h-2 rounded-full ${ws.status === 'connected' ? 'bg-green-500' : ws.status === 'connecting' ? 'bg-yellow-500 animate-pulse' : 'bg-gray-600'}`}
            title={`WS: ${ws.status}`} />
        </div>
      </div>

      {/* Stats */}
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

      {/* Main content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left — Workflow + Proposals */}
        <div className="space-y-5">
          <WorkflowTimeline scan={scan} events={ws.events} />
          {(scan.awaiting_approval || ws.proposals) && (
            <ProposalPanel processId={id} onApproved={() => {}} />
          )}
        </div>

        {/* Right — Live Terminal + Report */}
        <div className="lg:col-span-2 space-y-5">
          <LiveTerminal events={ws.events} outputLines={ws.outputLines} />
          {scan.report && <ReportViewer report={scan.report} processId={id} />}
        </div>
      </div>
    </div>
  );
}

function riskColor(r: string) {
  return { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-cyan-400', none: 'text-gray-500' }[r] || 'text-gray-500';
}
