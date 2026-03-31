// src/app/findings/page.tsx
'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '@/lib/api';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/20', high: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20', low: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
  info: 'text-gray-400 bg-gray-500/10 border-gray-500/20',
};

export default function FindingsPage() {
  const [findings, setFindings] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [total, setTotal] = useState(0);
  const [filters, setFilters] = useState({ severity: '', source: '', search: '', port: '' });
  const [loading, setLoading] = useState(true);
  // AI Chat
  const [selected, setSelected] = useState<any>(null);
  const [aiResponse, setAiResponse] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [chatHistory, setChatHistory] = useState<any[]>([]);

  const loadFindings = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filters.severity) params.set('severity', filters.severity);
      if (filters.source) params.set('source', filters.source);
      if (filters.search) params.set('search', filters.search);
      if (filters.port) params.set('port', filters.port);
      params.set('limit', '100');
      const r = await api.get(`/auth/findings?${params}`);
      setFindings(r.findings || []); setTotal(r.total || 0);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { loadFindings(); }, [filters]);
  useEffect(() => { api.get('/auth/findings/stats').then(setStats).catch(() => {}); }, []);

  const askAI = async (chatType: string, question?: string) => {
    if (!selected) return;
    setAiLoading(true); setAiResponse('');
    try {
      const r = await api.post('/ai/chat', {
        finding_id: selected.finding_id,
        process_id: selected.process_id,
        chat_type: chatType,
        question,
        finding_data: selected,
      });
      setAiResponse(r.answer || 'No response');
      setChatHistory(prev => [{ type: chatType, answer: r.answer, ts: new Date().toISOString() }, ...prev]);
    } catch (e: any) {
      setAiResponse(`Error: ${e.message}`);
    }
    setAiLoading(false);
  };

  return (
    <div>
      <h2 className="text-xl font-bold mb-6">Findings Explorer</h2>

      {/* Stats */}
      <div className="grid grid-cols-3 sm:grid-cols-5 gap-2 sm:gap-3 mb-5">
        {SEVERITIES.map(s => (
          <div key={s} className={`glass p-2 sm:p-3 text-center cursor-pointer transition ${filters.severity === s ? 'border-indigo-500/30' : ''}`}
            onClick={() => setFilters(f => ({ ...f, severity: f.severity === s ? '' : s }))}>
            <p className={`text-lg sm:text-xl font-extrabold font-mono ${SEV_COLORS[s]?.split(' ')[0]}`}>{stats?.by_severity?.[s] || 0}</p>
            <p className="text-[9px] sm:text-[10px] text-gray-500 uppercase tracking-widest mt-1">{s}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="glass p-3 sm:p-4 mb-5">
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 sm:gap-3">
          <input className="input-field" placeholder="Search findings..." value={filters.search}
            onChange={e => setFilters(f => ({ ...f, search: e.target.value }))} />
          <select className="input-field" value={filters.severity}
            onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}>
            <option value="">All Severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
          </select>
          <select className="input-field" value={filters.source}
            onChange={e => setFilters(f => ({ ...f, source: e.target.value }))}>
            <option value="">All Tools</option>
            {Object.keys(stats?.by_source || {}).map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <input className="input-field" placeholder="Port..." value={filters.port} type="number"
            onChange={e => setFilters(f => ({ ...f, port: e.target.value }))} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Findings list */}
        <div className="lg:col-span-2 glass overflow-hidden">
          <div className="px-4 py-3 border-b border-white/[0.06] flex items-center justify-between">
            <span className="text-xs text-gray-500">{total} finding{total !== 1 ? 's' : ''}</span>
            {(filters.severity || filters.source || filters.search || filters.port) && (
              <button className="text-xs text-indigo-400 hover:underline" onClick={() => setFilters({ severity: '', source: '', search: '', port: '' })}>Clear</button>
            )}
          </div>
          {loading ? (
            <div className="p-10 text-center text-gray-500">Loading...</div>
          ) : findings.length === 0 ? (
            <div className="p-10 text-center text-gray-600">
              <p className="text-2xl mb-2 opacity-30">🔍</p>
              <p className="text-sm">{total === 0 ? 'No findings yet — run a scan' : 'No matches'}</p>
            </div>
          ) : (
            <div className="divide-y divide-white/[0.03]">
              {findings.map((f, i) => (
                <div key={i} onClick={() => { setSelected(f); setAiResponse(''); setChatHistory([]); }}
                  className={`px-3 sm:px-4 py-3 cursor-pointer transition ${selected?.finding_id === f.finding_id ? 'bg-indigo-500/[0.06]' : 'hover:bg-white/[0.02]'}`}>
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-1">
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span className={`badge border ${SEV_COLORS[f.severity] || SEV_COLORS.info}`}>{f.severity}</span>
                        <span className="text-[10px] text-gray-500 font-mono">{f.source}</span>
                        {f.port && <span className="text-[10px] text-gray-500">:{f.port}</span>}
                      </div>
                      <p className="text-sm truncate">{f.finding || f.type}</p>
                      {f.service && <p className="text-[11px] text-gray-500 mt-0.5">{f.service} {f.version || ''}</p>}
                    </div>
                    <Link href={`/scan/${f.process_id}`} onClick={e => e.stopPropagation()} className="text-[10px] text-indigo-400 hover:underline shrink-0">
                      {f.target || f.process_id?.slice(0, 16)}
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* AI Chat Panel */}
        <div className="glass p-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-purple-500" /> AI Assistant
          </h3>
          {!selected ? (
            <div className="text-center py-8 text-gray-600">
              <p className="text-2xl mb-2 opacity-30">🤖</p>
              <p className="text-sm">Click a finding to ask AI</p>
            </div>
          ) : (
            <div>
              <div className="p-3 rounded-lg bg-white/[0.03] border border-white/[0.04] mb-4">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`badge border ${SEV_COLORS[selected.severity] || SEV_COLORS.info}`}>{selected.severity}</span>
                  <span className="text-[10px] text-gray-500">{selected.source}</span>
                </div>
                <p className="text-sm">{selected.finding || selected.type}</p>
              </div>

              {/* Action buttons */}
              <div className="grid grid-cols-2 gap-2 mb-4">
                {[
                  { type: 'explain', label: '🧠 Explain', desc: 'What is this?' },
                  { type: 'remediate', label: '🔧 Fix', desc: 'How to fix?' },
                  { type: 'poc', label: '💥 PoC', desc: 'Prove it' },
                  { type: 'general', label: '💬 Ask', desc: 'Custom Q' },
                ].map(btn => (
                  <button key={btn.type} onClick={() => askAI(btn.type)} disabled={aiLoading}
                    className="p-3 rounded-lg bg-white/[0.03] border border-white/[0.06] hover:border-indigo-500/30 hover:bg-indigo-500/[0.04] transition text-left">
                    <p className="text-sm font-semibold">{btn.label}</p>
                    <p className="text-[10px] text-gray-500">{btn.desc}</p>
                  </button>
                ))}
              </div>

              {/* Response */}
              {aiLoading && (
                <div className="flex items-center gap-2 p-4 text-sm text-indigo-400">
                  <div className="w-4 h-4 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
                  AI is analyzing...
                </div>
              )}
              {aiResponse && (
                <div className="p-4 rounded-lg bg-black/30 border border-white/[0.04] max-h-[400px] overflow-y-auto">
                  <pre className="text-sm text-gray-300 whitespace-pre-wrap font-sans leading-relaxed">{aiResponse}</pre>
                </div>
              )}

              {/* History */}
              {chatHistory.length > 1 && (
                <div className="mt-4">
                  <p className="text-[10px] text-gray-500 uppercase mb-2">Previous</p>
                  {chatHistory.slice(1, 4).map((h, i) => (
                    <div key={i} className="text-[11px] text-gray-600 py-1 border-b border-white/[0.03]">
                      [{h.type}] {h.answer?.slice(0, 80)}...
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
