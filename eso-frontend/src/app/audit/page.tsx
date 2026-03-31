// src/app/audit/page.tsx
'use client';
import { useEffect, useState } from 'react';
import { system } from '@/lib/api';

export default function AuditPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const params = filter ? `?action=${encodeURIComponent(filter)}&limit=100` : '?limit=100';
      const r = await system.audit(params);
      setLogs(r.logs || []);
      setTotal(r.total || 0);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, [filter]);

  const statusColor = (s: string) =>
    s === 'success' ? 'text-green-400' : s === 'denied' ? 'text-red-400' : 'text-yellow-400';

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold">Audit Log</h2>
        <span className="text-xs text-gray-500">{total} events</span>
      </div>

      <div className="glass p-3 mb-5">
        <input className="input-field" placeholder="Filter by action (e.g. scan, login, POST)..."
          value={filter} onChange={e => setFilter(e.target.value)} />
      </div>

      <div className="glass overflow-hidden">
        {loading ? (
          <div className="p-10 text-center text-gray-500">Loading...</div>
        ) : logs.length === 0 ? (
          <div className="p-10 text-center text-gray-600">No audit events</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/[0.06]">
                {['Time', 'User', 'Action', 'Status', 'IP', 'Details'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] text-gray-500 uppercase tracking-widest font-bold">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {logs.map((log, i) => (
                <tr key={i} className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                  <td className="px-4 py-2 text-[11px] text-gray-500 font-mono whitespace-nowrap">
                    {log.timestamp ? new Date(log.timestamp).toLocaleString() : '—'}
                  </td>
                  <td className="px-4 py-2 text-xs font-mono">{log.user_id}</td>
                  <td className="px-4 py-2 text-xs">{log.action}</td>
                  <td className={`px-4 py-2 text-xs font-semibold ${statusColor(log.status)}`}>{log.status}</td>
                  <td className="px-4 py-2 text-[11px] text-gray-500">{log.ip_address || '—'}</td>
                  <td className="px-4 py-2 text-[11px] text-gray-600 max-w-[200px] truncate">
                    {log.details?.path || log.details?.method || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
