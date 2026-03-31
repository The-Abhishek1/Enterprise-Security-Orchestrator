// src/components/scan/workflow-timeline.tsx
'use client';

const STEPS = [
  { key: 'planning', label: 'AI Planning', icon: '🧠', desc: 'LLM creates task DAG' },
  { key: 'validating', label: 'Validation', icon: '✅', desc: 'DAG structure verified' },
  { key: 'executing', label: 'Tool Execution', icon: '🐳', desc: 'Running in Docker' },
  { key: 'analysis', label: 'AI Analysis', icon: '📊', desc: 'Validating findings' },
  { key: 'proposals', label: 'Task Proposals', icon: '💡', desc: 'AI suggests next steps' },
  { key: 'report', label: 'Report', icon: '📄', desc: 'Generating report' },
];

export default function WorkflowTimeline({ scan, wsStep }: { scan: any; wsStep?: number }) {
  const currentStep = wsStep ?? getStepFromStatus(scan);

  return (
    <div className="glass p-5">
      <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-indigo-500" /> Execution Workflow
      </h3>
      <div className="space-y-1">
        {STEPS.map((step, i) => {
          const state = i < currentStep ? 'done' : i === currentStep ? 'active' : 'pending';
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
                  <div className={`w-px h-5 mt-1 ${state === 'done' ? 'bg-green-500/30' : 'bg-white/[0.06]'}`} />
                )}
              </div>
              <div className="pt-1">
                <p className={`text-sm font-semibold ${
                  state === 'active' ? 'text-indigo-400' : state === 'done' ? 'text-gray-300' : 'text-gray-600'
                }`}>{step.label}</p>
                <p className="text-[10px] text-gray-600">{step.desc}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function getStepFromStatus(scan: any): number {
  const s = scan.status;
  if (s === 'completed') return 6;
  if (s === 'failed' || s === 'timeout') return 6;
  if (scan.report) return 5;
  if (scan.awaiting_approval) return 4;
  if (scan.findings_count > 0) return 3;
  if ((scan.completed_tasks || 0) > 0) return 2;
  if (s === 'running') return 2;
  if (s === 'validating') return 1;
  return 0;
}
