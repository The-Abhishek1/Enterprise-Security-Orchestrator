// src/components/scan/live-terminal.tsx
'use client';
import { useEffect, useRef } from 'react';
import { ScanEvent } from '@/hooks/use-scan-ws';

type OutputLine = { tool: string; line: string; task: string };

const TOOL_COLORS: Record<string, string> = {
  nmap: 'text-cyan-400',
  nuclei: 'text-purple-400',
  gobuster: 'text-green-400',
  nikto: 'text-orange-400',
  ffuf: 'text-yellow-400',
  whatweb: 'text-blue-400',
  sqlmap: 'text-red-400',
};

export default function LiveTerminal({
  events,
  outputLines,
}: {
  events: ScanEvent[];
  outputLines: OutputLine[];
}) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events.length, outputLines.length]);

  return (
    <div className="glass p-5">
      <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-3 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" /> Live Terminal
      </h3>
      <div className="font-mono text-[11px] leading-relaxed bg-black/40 rounded-lg p-4 max-h-[400px] overflow-y-auto border border-white/[0.04]">
        {/* System events */}
        {events.map((e, i) => {
          switch (e.type) {
            case 'execution_start':
              return <Line key={i} c="text-indigo-400" t={`▶ Scan started: ${e.data.target} (${e.data.total_tasks} tasks, ${e.data.levels} levels)`} />;
            case 'level_start':
              return <Line key={i} c="text-indigo-300" t={`━━ Level ${e.data.level}/${e.data.total_levels}: ${e.data.tasks?.join(', ')}`} />;
            case 'task_start':
              return <Line key={i} c={TOOL_COLORS[e.data.tool] || 'text-gray-400'} t={`🐳 ${e.data.tool} → ${e.data.task_name}`} />;
            case 'task_complete':
              return <Line key={i} c="text-green-400" t={`✓ ${e.data.tool} done — ${e.data.findings_count} findings (${(e.data.duration || 0).toFixed(1)}s)`} />;
            case 'analysis_start':
              return <Line key={i} c="text-purple-400" t={`🧠 AI analyzing ${e.data.findings_count} findings...`} />;
            case 'analysis_done':
              return <Line key={i} c="text-purple-300" t={`🧠 Analysis: ${e.data.validated} valid, ${e.data.removed} false positives removed`} />;
            case 'risk_update':
              return <Line key={i} c="text-yellow-400" t={`⚖ Risk: ${e.data.risk?.toUpperCase()} (${(e.data.score || 0).toFixed(1)}) C:${e.data.critical} H:${e.data.high} M:${e.data.medium}`} />;
            case 'proposal':
              return <Line key={i} c="text-yellow-300" t={`💡 AI proposes: ${e.data.proposals?.map((p: any) => `${p.task_name} (${p.tool})`).join(', ')}`} />;
            case 'approval_needed':
              return <Line key={i} c="text-yellow-500" t={`⏸ Waiting for your approval...`} />;
            case 'approval_done':
              return <Line key={i} c="text-green-400" t={`✓ Approved: ${e.data.approved?.join(', ') || 'none'}`} />;
            case 'report_start':
              return <Line key={i} c="text-indigo-400" t={`📝 Generating pentest report...`} />;
            case 'report_done':
              return <Line key={i} c="text-green-400" t={`📄 Report ready (${e.data.length} chars)`} />;
            case 'complete':
              return <Line key={i} c="text-green-500" t={`🎉 Scan complete — ${e.data.findings} findings, risk: ${e.data.risk?.toUpperCase()}, ${(e.data.duration || 0).toFixed(0)}s`} />;
            case 'level_complete':
              return <Line key={i} c="text-gray-500" t={`  Level done: ${e.data.findings_count} findings, progress ${e.data.progress}%`} />;
            case 'task_output':
              // Rendered separately below
              return null;
            default:
              return null;
          }
        })}

        {/* Tool output lines (interleaved) */}
        {outputLines.length > 0 && (
          <div className="mt-2 pt-2 border-t border-white/[0.04]">
            <p className="text-gray-600 text-[10px] mb-1">TOOL OUTPUT</p>
            {outputLines.slice(-50).map((l, i) => (
              <div key={i} className="flex gap-2 py-px">
                <span className={`shrink-0 ${TOOL_COLORS[l.tool] || 'text-gray-500'}`}>[{l.tool}]</span>
                <span className="text-gray-400 break-all">{l.line}</span>
              </div>
            ))}
          </div>
        )}

        <div ref={bottomRef} />
      </div>
    </div>
  );
}

function Line({ c, t }: { c: string; t: string }) {
  return <p className={`${c} py-0.5`}>{t}</p>;
}
