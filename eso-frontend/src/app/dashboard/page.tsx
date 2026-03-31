// src/app/dashboard/page.tsx
'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { scans, history, system } from '@/lib/api';

export default function DashboardPage() {
  const [dbScans, setDbScans] = useState<any[]>([]);
  const [activeScans, setActiveScans] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);

  const load = () => {
    // DB history (persisted scans)
    history.list(20, 0).then(r => setDbScans(r.scans || [])).catch(() => {});
    // In-memory active scans
    scans.list().then(r => {
      const all = r.executions || [];
      setActiveScans(all.filter((e: any) => ['running', 'planning', 'queued', 'validating', 'pending'].includes(e.status)));
    }).catch(() => {});
    // Health
    system.health().then(setHealth).catch(() => {});
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
  }, []);

  const totalScans = dbScans.length;
  const completedScans = dbScans.filter(s => s.status === 'completed').length;
  const failedScans = dbScans.filter(s => ['failed', 'timeout'].includes(s.status)).length;
  const runningCount = activeScans.length;

  return (
    <div>
      <h2 className="text-xl font-bold mb-6">Dashboard</h2>

      {/* Active scans banner */}
      {activeScans.length > 0 && (
        <div className="mb-5 p-4 rounded-2xl border border-indigo-500/20 bg-indigo-500/[0.06]">
          <h3 className="text-sm font-bold text-indigo-400 mb-3 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse" /> {activeScans.length} Active Scan{activeScans.length > 1 ? 's' : ''}
          </h3>
          <div className="space-y-2">
            {activeScans.map((s: any) => (
              <Link key={s.process_id} href={`/scan/${s.process_id}`}
                className="flex items-center justify-between p-3 rounded-lg bg-white/[0.03] border border-indigo-500/15 hover:border-indigo-500/30 transition cursor-pointer">
                <div>
                  <p className="text-sm font-semibold">{s.target || '—'}</p>
                  <p className="text-[11px] text-gray-500 font-mono">{s.process_id}</p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="badge badge-running">{s.status}</span>
                  <span className="text-xs text-indigo-400">View →</span>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Total Scans', val: totalScans, color: 'text-indigo-400' },
          { label: 'Completed', val: completedScans, color: 'text-green-400' },
          { label: 'Running', val: runningCount, color: 'text-cyan-400' },
          { label: 'Failed', val: failedScans, color: 'text-red-400' },
        ].map((s, i) => (
          <div key={i} className="glass p-5 relative overflow-hidden group">
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-indigo-500 to-transparent opacity-0 group-hover:opacity-100 transition" />
            <p className="text-[11px] text-gray-500 uppercase tracking-widest font-semibold">{s.label}</p>
            <p className={`text-3xl font-extrabold font-mono mt-2 tracking-tight ${s.color}`}>{s.val}</p>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        {/* Recent scans from DB */}
        <div className="lg:col-span-2 glass p-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-500" /> Recent Scans
          </h3>
          {dbScans.length === 0 && activeScans.length === 0 ? (
            <div className="text-center py-10 text-gray-600">
              <p className="text-3xl mb-2 opacity-40">🔍</p>
              <p className="text-sm">No scans yet — <Link href="/scan/new" className="text-indigo-400 hover:underline">launch one</Link></p>
            </div>
          ) : (
            <div className="space-y-2">
              {dbScans.slice(0, 10).map((s: any) => (
                <Link key={s.process_id} href={`/scan/${s.process_id}`}
                  className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04] hover:border-indigo-500/30 hover:bg-indigo-500/[0.04] transition cursor-pointer">
                  <div>
                    <p className="text-sm font-semibold">{s.target || '—'}</p>
                    <p className="text-[11px] text-gray-500 font-mono mt-0.5">{s.process_id}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    {s.findings_count > 0 && <span className="text-[10px] text-cyan-400 font-mono">{s.findings_count} findings</span>}
                    <span className={`badge badge-${s.status}`}>{s.status}</span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* System Health */}
        <div className="glass p-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-green-500" /> System Health
          </h3>
          {health ? (
            <div className="space-y-3">
              {Object.entries(health.services || {}).map(([name, status]: [string, any]) => (
                <div key={name} className="flex items-center justify-between py-2 border-b border-white/[0.04] last:border-0">
                  <span className="text-sm capitalize">{name}</span>
                  <span className={`text-xs font-semibold ${String(status).includes('healthy') || String(status).includes('connect') ? 'text-green-400' : 'text-red-400'}`}>
                    {String(status).includes('healthy') || String(status).includes('connect') ? '● Online' : '○ Offline'}
                  </span>
                </div>
              ))}
              <div className="flex items-center justify-between py-2">
                <span className="text-sm">Tools</span>
                <span className="text-xs font-semibold text-indigo-400">7 Available</span>
              </div>
            </div>
          ) : (
            <p className="text-sm text-gray-500">Loading...</p>
          )}
        </div>
      </div>
    </div>
  );
}
