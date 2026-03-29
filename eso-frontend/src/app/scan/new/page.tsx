// src/app/scan/new/page.tsx
'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { scans } from '@/lib/api';

const TOOLS = [
  { name: 'nmap', desc: 'Port & service scanning', cat: 'Recon' },
  { name: 'nuclei', desc: 'Vulnerability scanner (CVEs)', cat: 'Vuln' },
  { name: 'gobuster', desc: 'Directory brute-force', cat: 'Web' },
  { name: 'nikto', desc: 'Web server vuln scanner', cat: 'Web' },
  { name: 'ffuf', desc: 'Fast web fuzzer', cat: 'Web' },
  { name: 'whatweb', desc: 'Technology fingerprinting', cat: 'Recon' },
  { name: 'sqlmap', desc: 'SQL injection testing', cat: 'Exploit' },
];

export default function NewScanPage() {
  const [target, setTarget] = useState('');
  const [goal, setGoal] = useState('Scan for open ports and vulnerabilities');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const router = useRouter();

  const launch = async () => {
    if (!target.trim()) { setError('Enter a target'); return; }
    setError(''); setLoading(true);
    try {
      const r = await scans.execute(goal || `Scan ${target} for open ports and vulnerabilities`, target.trim());
      router.push(`/scan/${r.process_id}`);
    } catch (e: any) { setError(e.message); setLoading(false); }
  };

  return (
    <div>
      <h2 className="text-xl font-bold mb-6">New Scan</h2>
      <div className="grid lg:grid-cols-2 gap-5">
        <div className="glass p-6">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-5 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-500" /> Target Configuration
          </h3>
          <div className="space-y-4">
            <div>
              <label className="block text-[11px] text-gray-400 uppercase tracking-wide font-semibold mb-1.5">Target Host / IP</label>
              <input className="input-field" value={target} onChange={e => setTarget(e.target.value)} placeholder="scanme.nmap.org" />
            </div>
            <div>
              <label className="block text-[11px] text-gray-400 uppercase tracking-wide font-semibold mb-1.5">Scan Goal</label>
              <textarea className="input-field min-h-[80px]" value={goal} onChange={e => setGoal(e.target.value)} />
            </div>
            {error && <p className="text-red-400 text-sm p-3 rounded-lg bg-red-500/10 border border-red-500/20">{error}</p>}
            <button onClick={launch} disabled={loading} className="btn-primary">
              {loading ? '⏳ Launching...' : '⚡ Launch Scan'}
            </button>
          </div>
        </div>

        <div className="glass p-6">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-5 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-500" /> Available Tools
          </h3>
          <div className="grid grid-cols-2 gap-2">
            {TOOLS.map(t => (
              <div key={t.name} className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-sm font-mono">{t.name}</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-white/[0.05] text-gray-500 font-medium">{t.cat}</span>
                </div>
                <p className="text-[11px] text-gray-500 mt-1">{t.desc}</p>
              </div>
            ))}
          </div>
          <p className="text-[11px] text-gray-600 mt-4">AI selects tools based on your goal. You approve before execution.</p>
        </div>
      </div>
    </div>
  );
}
