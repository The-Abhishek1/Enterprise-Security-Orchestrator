// src/app/dashboard/page.tsx
'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { scans, system } from '@/lib/api';

export default function DashboardPage() {
  const [stats, setStats] = useState({ total: 0, completed: 0, running: 0, failed: 0, recent: [] as any[] });
  const [health, setHealth] = useState<any>(null);

  useEffect(() => {
    scans.list().then(r => {
      const all = r.executions || [];
      setStats({
        total: all.length,
        completed: all.filter((e: any) => e.status === 'completed').length,
        running: all.filter((e: any) => ['running', 'planning', 'queued'].includes(e.status)).length,
        failed: all.filter((e: any) => ['failed', 'timeout'].includes(e.status)).length,
        recent: all.slice(0, 8),
      });
    }).catch(() => {});
    system.health().then(setHealth).catch(() => {});
  }, []);

  return (
    <div>
      <h2 className="text-xl font-bold mb-6">Dashboard</h2>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Total Scans', val: stats.total, color: 'text-indigo-400' },
          { label: 'Completed', val: stats.completed, color: 'text-green-400' },
          { label: 'Running', val: stats.running, color: 'text-cyan-400' },
          { label: 'Failed', val: stats.failed, color: 'text-red-400' },
        ].map((s, i) => (
          <div key={i} className="glass p-5 relative overflow-hidden group">
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-indigo-500 to-transparent opacity-0 group-hover:opacity-100 transition" />
            <p className="text-[11px] text-gray-500 uppercase tracking-widest font-semibold">{s.label}</p>
            <p className={`text-3xl font-extrabold font-mono mt-2 tracking-tight ${s.color}`}>{s.val}</p>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        {/* Recent */}
        <div className="lg:col-span-2 glass p-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-500" /> Recent Scans
          </h3>
          {stats.recent.length === 0 ? (
            <div className="text-center py-10 text-gray-600">
              <p className="text-3xl mb-2 opacity-40">🔍</p>
              <p className="text-sm">No scans yet — <Link href="/scan/new" className="text-indigo-400 hover:underline">launch one</Link></p>
            </div>
          ) : (
            <div className="space-y-2">
              {stats.recent.map((s: any) => (
                <Link key={s.process_id} href={`/scan/${s.process_id}`}
                  className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04] hover:border-indigo-500/30 hover:bg-indigo-500/[0.04] transition cursor-pointer">
                  <div>
                    <p className="text-sm font-semibold">{s.target || '—'}</p>
                    <p className="text-[11px] text-gray-500 font-mono mt-0.5">{s.process_id}</p>
                  </div>
                  <span className={`badge badge-${s.status}`}>{s.status}</span>
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
                  <span className={`text-xs font-semibold ${String(status).includes('healthy') ? 'text-green-400' : 'text-red-400'}`}>
                    {String(status).includes('healthy') ? '● Online' : '○ Offline'}
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
