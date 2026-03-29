// src/app/history/page.tsx
'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { history } from '@/lib/api';

export default function HistoryPage() {
  const [data, setData] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    history.list(50, 0).then(r => {
      setData(r.scans || []);
      setTotal(r.total || 0);
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  const riskColor = (r: string) =>
    ({ critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-cyan-400' }[r] || 'text-gray-500');

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold">Scan History</h2>
        <span className="text-xs text-gray-500">{total} total scans</span>
      </div>

      <div className="glass overflow-hidden">
        {loading ? (
          <div className="p-10 text-center text-gray-500">Loading...</div>
        ) : data.length === 0 ? (
          <div className="p-10 text-center text-gray-600">
            <p className="text-3xl mb-2 opacity-40">📋</p>
            <p className="text-sm">No scan history — <Link href="/scan/new" className="text-indigo-400 hover:underline">run a scan</Link></p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/[0.06]">
                {['Target', 'Status', 'Risk', 'Findings', 'Duration', 'Date'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] text-gray-500 uppercase tracking-widest font-bold">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.map(s => (
                <tr key={s.process_id} className="border-b border-white/[0.03] hover:bg-white/[0.02] transition">
                  <td className="px-4 py-3">
                    <Link href={`/scan/${s.process_id}`} className="font-semibold hover:text-indigo-400 transition">
                      {s.target || '—'}
                    </Link>
                    <p className="text-[10px] text-gray-600 font-mono mt-0.5">{s.process_id}</p>
                  </td>
                  <td className="px-4 py-3"><span className={`badge badge-${s.status}`}>{s.status}</span></td>
                  <td className={`px-4 py-3 font-bold font-mono ${riskColor(s.risk_level)}`}>
                    {(s.risk_level || '—').toUpperCase()}
                    <span className="text-gray-600 font-normal ml-1">({(s.risk_score || 0).toFixed(1)})</span>
                  </td>
                  <td className="px-4 py-3 font-mono">{s.findings_count || 0}</td>
                  <td className="px-4 py-3 text-gray-400">{s.duration_seconds ? `${(s.duration_seconds / 60).toFixed(1)}m` : '—'}</td>
                  <td className="px-4 py-3 text-gray-500">{new Date(s.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
