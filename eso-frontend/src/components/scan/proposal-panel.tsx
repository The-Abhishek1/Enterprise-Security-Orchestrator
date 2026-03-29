// src/components/scan/proposal-panel.tsx
'use client';
import { useEffect, useState } from 'react';
import { scans } from '@/lib/api';

export default function ProposalPanel({ processId, onApproved }: { processId: string; onApproved: () => void }) {
  const [proposals, setProposals] = useState<any[]>([]);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    scans.proposals(processId).then(r => {
      if (r.awaiting_approval && r.proposals?.length) {
        setProposals(r.proposals);
        setChecked(new Set(r.proposals.map((p: any) => p.task_name)));
      }
    }).catch(() => {});
  }, [processId]);

  const toggle = (name: string) => {
    const next = new Set(checked);
    next.has(name) ? next.delete(name) : next.add(name);
    setChecked(next);
  };

  const approve = async () => {
    setLoading(true);
    try {
      await scans.approve(processId, Array.from(checked));
      setProposals([]);
      onApproved();
    } catch (e) {}
    setLoading(false);
  };

  const reject = async () => {
    setLoading(true);
    try {
      await scans.approve(processId, []);
      setProposals([]);
      onApproved();
    } catch (e) {}
    setLoading(false);
  };

  if (!proposals.length) return null;

  return (
    <div className="glass p-5 border-yellow-500/20">
      <h3 className="text-sm font-bold uppercase tracking-wide text-yellow-400 mb-4 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-yellow-500 animate-pulse" /> AI Proposals — Your Approval Needed
      </h3>
      <div className="space-y-2">
        {proposals.map((p, i) => (
          <div key={i} onClick={() => toggle(p.task_name)}
            className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
              checked.has(p.task_name)
                ? 'bg-indigo-500/[0.06] border-indigo-500/20'
                : 'bg-white/[0.01] border-white/[0.04] opacity-50'
            }`}>
            <input type="checkbox" checked={checked.has(p.task_name)} readOnly
              className="accent-indigo-500 w-4 h-4 pointer-events-none" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold truncate">{p.task_name}</p>
              <p className="text-[11px] text-gray-500 mt-0.5">🔧 {p.tool} • Priority {p.priority} • {p.reason}</p>
            </div>
          </div>
        ))}
      </div>
      <div className="flex gap-2 mt-4">
        <button onClick={approve} disabled={loading || checked.size === 0} className="btn-success text-xs">
          ✓ Approve {checked.size > 0 ? `(${checked.size})` : ''}
        </button>
        <button onClick={reject} disabled={loading} className="btn-danger text-xs">✗ Skip All</button>
      </div>
    </div>
  );
}
