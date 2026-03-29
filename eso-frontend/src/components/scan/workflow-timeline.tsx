// src/components/scan/workflow-timeline.tsx
'use client';
import { ScanEvent } from '@/hooks/use-scan-ws';

const STEPS = [
  { key: 'planning', label: 'AI Planning', icon: '🧠', desc: 'LLM creates task DAG' },
  { key: 'validating', label: 'Validation', icon: '✅', desc: 'DAG structure verified' },
  { key: 'executing', label: 'Tool Execution', icon: '🐳', desc: 'Running in Docker containers' },
  { key: 'analysis', label: 'AI Analysis', icon: '📊', desc: 'Validating findings, scoring risk' },
  { key: 'proposals', label: 'Task Proposals', icon: '💡', desc: 'AI suggests next steps' },
  { key: 'report', label: 'Report Generation', icon: '📄', desc: 'Generating pentest report' },
];

export default function WorkflowTimeline({ scan, events = [] }: { scan: any; events?: ScanEvent[] }) {
  const currentStep = getStepFromEvents(events, scan);

  // Extract active tools from events
  const activeTools = events
    .filter(e => e.type === 'task_start')
    .map(e => e.data.tool)
    .filter((v, i, a) => a.indexOf(v) === i);

  const completedTools = events
    .filter(e => e.type === 'task_complete')
    .map(e => `${e.data.tool}: ${e.data.findings_count} findings`);

  return (
    <div className="glass p-5">
      <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-indigo-500" /> Execution Workflow
      </h3>
      <div className="space-y-0.5">
        {STEPS.map((step, i) => {
          const state = i < currentStep ? 'done' : i === currentStep ? 'active' : 'pending';
          const detail = getStepDetail(step.key, events, scan);

          return (
            <div key={step.key} className="flex items-start gap-3 py-2">
              <div className="flex flex-col items-center">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm border transition-all ${
                  state === 'done' ? 'bg-green-500/15 border-green-500/30 text-green-400' :
                  state === 'active' ? 'bg-indigo-500/15 border-indigo-500/30 text-indigo-400 animate-pulse' :
                  'bg-white/[0.03] border-white/[0.06] text-gray-600'
                }`}>
                  {state === 'done' ? '✓' : step.icon}
                </div>
                {i < STEPS.length - 1 && (
                  <div className={`w-px h-4 mt-1 ${state === 'done' ? 'bg-green-500/30' : 'bg-white/[0.06]'}`} />
                )}
              </div>
              <div className="pt-1 flex-1 min-w-0">
                <p className={`text-sm font-semibold ${
                  state === 'active' ? 'text-indigo-400' : state === 'done' ? 'text-gray-300' : 'text-gray-600'
                }`}>
                  {step.label}
                </p>
                <p className="text-[10px] text-gray-600">{step.desc}</p>
                {detail && <p className="text-[10px] text-gray-500 mt-0.5">{detail}</p>}
              </div>
            </div>
          );
        })}
      </div>

      {/* Active tools indicator */}
      {activeTools.length > 0 && (
        <div className="mt-4 pt-3 border-t border-white/[0.04]">
          <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Tools Used</p>
          <div className="flex flex-wrap gap-1.5">
            {activeTools.map(t => (
              <span key={t} className="text-[10px] px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono">{t}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function getStepFromEvents(events: ScanEvent[], scan: any): number {
  const types = new Set(events.map(e => e.type));

  if (types.has('complete') || types.has('error')) return 6;
  if (types.has('report_done')) return 6;
  if (types.has('report_start')) return 5;
  if (types.has('approval_needed') || types.has('proposal')) return 4;
  if (types.has('risk_update') || types.has('analysis_done')) return 3;
  if (types.has('task_complete') || types.has('task_output')) return 2;
  if (types.has('task_start') || types.has('level_start')) return 2;
  if (types.has('execution_start')) return 1;

  // Fallback to scan status
  const status = scan?.status;
  if (status === 'completed') return 6;
  if (status === 'running') return 2;
  if (status === 'validating') return 1;
  if (status === 'planning') return 0;
  return 0;
}

function getStepDetail(stepKey: string, events: ScanEvent[], scan: any): string | null {
  switch (stepKey) {
    case 'executing': {
      const starts = events.filter(e => e.type === 'task_start');
      const completes = events.filter(e => e.type === 'task_complete');
      if (starts.length) return `${completes.length}/${starts.length} tools finished`;
      return null;
    }
    case 'analysis': {
      const done = events.filter(e => e.type === 'analysis_done').at(-1);
      if (done) return `${done.data.validated} valid, ${done.data.removed} false positives`;
      return null;
    }
    case 'proposals': {
      const prop = events.filter(e => e.type === 'proposal').at(-1);
      if (prop) return prop.data.proposals?.map((p: any) => p.task_name).join(', ');
      return null;
    }
    case 'report': {
      const done = events.find(e => e.type === 'report_done');
      if (done) return `${done.data.length} characters`;
      return null;
    }
    default:
      return null;
  }
}
