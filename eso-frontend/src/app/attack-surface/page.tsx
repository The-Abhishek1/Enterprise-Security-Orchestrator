// src/app/attack-surface/page.tsx
'use client';
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-cyan-400', info: 'text-gray-400',
};
const SEV_BG: Record<string, string> = {
  critical: 'bg-red-500/10 border-red-500/20', high: 'bg-orange-500/10 border-orange-500/20',
  medium: 'bg-yellow-500/10 border-yellow-500/20', low: 'bg-cyan-500/10 border-cyan-500/20', info: 'bg-gray-500/10 border-gray-500/20',
};

export default function AttackSurfacePage() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get('/attack-surface/').then(setData).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-gray-500 py-20 text-center">Loading attack surface...</div>;
  if (!data) return <div className="text-gray-500 py-20 text-center">No data available</div>;

  const s = data.summary || {};
  const sev = s.severity_breakdown || {};

  return (
    <div>
      <h2 className="text-xl font-bold mb-6">Attack Surface</h2>

      {/* Top stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        {[
          { label: 'Assets', val: s.total_assets || 0, color: 'text-indigo-400' },
          { label: 'Total Scans', val: s.total_scans || 0, color: 'text-cyan-400' },
          { label: 'Total Findings', val: s.total_findings || 0, color: 'text-yellow-400' },
          { label: 'High Risk', val: (sev.critical || 0) + (sev.high || 0), color: 'text-red-400' },
        ].map((st, i) => (
          <div key={i} className="glass p-4 text-center">
            <p className={`text-2xl font-extrabold font-mono ${st.color}`}>{st.val}</p>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest mt-1">{st.label}</p>
          </div>
        ))}
      </div>

      {/* Severity breakdown bar */}
      <div className="glass p-5 mb-5">
        <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-3 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-red-500" /> Severity Distribution
        </h3>
        <div className="flex gap-1 h-8 rounded-lg overflow-hidden mb-3">
          {['critical', 'high', 'medium', 'low', 'info'].map(sv => {
            const count = sev[sv] || 0;
            const pct = s.total_findings > 0 ? (count / s.total_findings * 100) : 0;
            if (pct === 0) return null;
            const colors: Record<string,string> = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-cyan-500', info: 'bg-gray-500' };
            return <div key={sv} className={`${colors[sv]} transition-all`} style={{ width: `${Math.max(pct, 2)}%` }} title={`${sv}: ${count}`} />;
          })}
        </div>
        <div className="flex flex-wrap gap-4 text-xs">
          {['critical', 'high', 'medium', 'low', 'info'].map(sv => (
            <span key={sv} className="flex items-center gap-1.5">
              <span className={`w-2.5 h-2.5 rounded-sm ${sv === 'critical' ? 'bg-red-500' : sv === 'high' ? 'bg-orange-500' : sv === 'medium' ? 'bg-yellow-500' : sv === 'low' ? 'bg-cyan-500' : 'bg-gray-500'}`} />
              <span className="text-gray-400 capitalize">{sv}</span>
              <span className="text-gray-300 font-mono font-bold">{sev[sv] || 0}</span>
            </span>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Open Ports */}
        <div className="glass p-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-500" /> Open Ports
          </h3>
          {(data.open_ports || []).length === 0 ? (
            <p className="text-sm text-gray-600 py-4 text-center">No open ports discovered</p>
          ) : (
            <div className="space-y-1">
              {data.open_ports.map((p: any, i: number) => (
                <div key={i} className="flex items-center justify-between py-2 px-3 rounded-lg bg-white/[0.02]">
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-sm font-bold text-cyan-400">{p.port}</span>
                    <span className="text-xs text-gray-400">/{p.protocol}</span>
                    <span className="text-xs text-gray-300">{p.service}</span>
                  </div>
                  <span className="text-xs text-gray-500 font-mono">{p.count}x</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Vulnerabilities */}
        <div className="glass p-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-500" /> Top Vulnerabilities
          </h3>
          {(data.top_vulnerabilities || []).length === 0 ? (
            <p className="text-sm text-gray-600 py-4 text-center">No vulnerabilities found</p>
          ) : (
            <div className="space-y-2">
              {data.top_vulnerabilities.map((v: any, i: number) => (
                <div key={i} className={`p-3 rounded-lg border ${SEV_BG[v.severity] || SEV_BG.info}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`badge border ${SEV_BG[v.severity]} ${SEV_COLORS[v.severity]}`}>{v.severity}</span>
                    <span className="text-[10px] text-gray-500">{v.source}</span>
                  </div>
                  <p className="text-sm truncate">{v.finding || v.type}</p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Assets (targets) */}
        <div className="glass p-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-500" /> Assets
          </h3>
          {(data.risk_by_target || []).length === 0 ? (
            <p className="text-sm text-gray-600 py-4 text-center">No assets scanned</p>
          ) : (
            <div className="space-y-2">
              {data.risk_by_target.map((t: any, i: number) => (
                <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                  <div>
                    <p className="text-sm font-semibold">{t.target}</p>
                    <p className="text-[10px] text-gray-500">{t.findings_count} findings</p>
                  </div>
                  <span className={`text-sm font-bold font-mono ${SEV_COLORS[t.risk_level] || 'text-gray-500'}`}>
                    {(t.risk_level || '—').toUpperCase()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Scan Trends */}
        <div className="glass p-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-green-500" /> Recent Scan Trend
          </h3>
          {(data.scan_trends || []).length === 0 ? (
            <p className="text-sm text-gray-600 py-4 text-center">No scan history</p>
          ) : (
            <div className="space-y-1">
              {data.scan_trends.slice(0, 10).map((t: any, i: number) => (
                <div key={i} className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-white/[0.02]">
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-gray-500 font-mono w-20">{t.scan_date}</span>
                    <span className="text-sm">{t.target}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-gray-400 font-mono">{t.findings_count}f</span>
                    <span className={`text-xs font-bold ${SEV_COLORS[t.risk_level] || 'text-gray-500'}`}>
                      {(t.risk_level || '—').toUpperCase()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
