// src/components/scan/live-terminal.tsx
'use client';
import { useEffect, useRef } from 'react';
import { ScanEvent } from '@/hooks/use-scan-ws';

const TYPE_COLORS: Record<string, string> = {
  execution_start: 'text-indigo-400',
  level_start: 'text-cyan-400',
  task_start: 'text-yellow-400',
  task_output: 'text-gray-400',
  task_complete: 'text-green-400',
  analysis_start: 'text-purple-400',
  analysis_done: 'text-purple-300',
  risk_update: 'text-orange-400',
  proposal: 'text-yellow-300',
  approval_needed: 'text-yellow-500',
  approval_done: 'text-green-300',
  report_start: 'text-blue-400',
  report_done: 'text-green-400',
  complete: 'text-green-500',
  error: 'text-red-500',
};

const TYPE_ICONS: Record<string, string> = {
  execution_start: '🟢',
  level_start: '▶',
  task_start: '🐳',
  task_output: '  ',
  task_complete: '✅',
  analysis_start: '🧠',
  analysis_done: '📊',
  risk_update: '⚖️',
  proposal: '💡',
  approval_needed: '⏸️',
  approval_done: '✓',
  report_start: '📝',
  report_done: '📄',
  complete: '🎉',
  error: '❌',
};

function formatEvent(ev: ScanEvent): string {
  const d = ev.data;
  switch (ev.type) {
    case 'execution_start': return `Starting scan on ${d.target} (${d.total_tasks} tasks, ${d.levels} levels)`;
    case 'level_start': return `Level ${d.level}/${d.total_levels}: ${(d.tools || []).join(', ')} → ${(d.tasks || []).join(', ')}`;
    case 'task_start': return `Running ${d.tool}: ${d.task_name}`;
    case 'task_output': return `${d.line}`;
    case 'task_complete': return `${d.tool} done — ${d.findings_count} findings (${(d.duration || 0).toFixed(1)}s)`;
    case 'analysis_start': return `AI analyzing ${d.findings_count} findings...`;
    case 'analysis_done': return `Validated: ${d.validated}, removed: ${d.removed} false positives${d.summary ? ' — ' + d.summary : ''}`;
    case 'risk_update': return `Risk: ${(d.risk || '—').toUpperCase()} (${(d.score || 0).toFixed(1)}) C:${d.critical} H:${d.high} M:${d.medium}`;
    case 'proposal': return `AI proposes: ${(d.proposals || []).map((p: any) => `${p.task_name} (${p.tool})`).join(', ')}`;
    case 'approval_needed': return `⏸ Waiting for your approval...`;
    case 'approval_done': return `User approved tasks`;
    case 'report_start': return `Generating pentest report...`;
    case 'report_done': return `Report generated (${d.length} chars)`;
    case 'complete': return `Scan complete — ${d.findings} findings, risk: ${(d.risk || '—').toUpperCase()}, ${(d.duration || 0).toFixed(0)}s, ${d.llm_calls} LLM calls`;
    case 'error': return `Error: ${d.message || 'Unknown'}`;
    default: return JSON.stringify(d).slice(0, 120);
  }
}

export default function LiveTerminal({ events }: { events: ScanEvent[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events.length]);

  return (
    <div className="glass p-5">
      <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-3 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-green-500" /> Live Terminal
        <span className="text-[10px] font-normal text-gray-600 ml-auto">{events.length} events</span>
      </h3>
      <div className="font-mono text-[11px] bg-black/40 rounded-lg p-4 max-h-[350px] overflow-y-auto border border-white/[0.04] space-y-px">
        {events.length === 0 ? (
          <p className="text-gray-600">Waiting for events...</p>
        ) : (
          events.map((ev, i) => {
            const color = TYPE_COLORS[ev.type] || 'text-gray-500';
            const icon = TYPE_ICONS[ev.type] || '•';
            const isOutput = ev.type === 'task_output';
            return (
              <div key={i} className={`${isOutput ? 'pl-6 text-gray-500' : ''} leading-relaxed`}>
                {!isOutput && <span className="mr-1">{icon}</span>}
                <span className={color}>{formatEvent(ev)}</span>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
