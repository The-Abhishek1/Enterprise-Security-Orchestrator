// src/app/settings/page.tsx
'use client';
import { useEffect, useState } from 'react';
import { useAuth } from '@/lib/auth-context';
import { auth, system } from '@/lib/api';

export default function SettingsPage() {
  const { user } = useAuth();
  const [keys, setKeys] = useState<any[]>([]);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKey, setNewKey] = useState('');
  const [creating, setCreating] = useState(false);

  // LLM state
  const [sysInfo, setSysInfo] = useState<any>(null);
  const [switching, setSwitching] = useState(false);
  const [testResult, setTestResult] = useState<any>(null);

  useEffect(() => {
    loadKeys();
    system.info().then(setSysInfo).catch(() => {});
  }, []);

  const loadKeys = () => auth.listApiKeys().then(r => setKeys(r.api_keys || [])).catch(() => {});

  const createKey = async () => {
    if (!newKeyName.trim()) return;
    setCreating(true);
    try {
      const r = await auth.createApiKey(newKeyName.trim());
      setNewKey(r.api_key);
      setNewKeyName('');
      loadKeys();
    } catch (e) {}
    setCreating(false);
  };

  const revokeKey = async (keyId: string) => {
    if (!confirm('Revoke this API key?')) return;
    await auth.revokeApiKey(keyId);
    loadKeys();
  };

  const switchLLM = async (provider: string) => {
    setSwitching(true); setTestResult(null);
    try {
      const r = await system.switchLLM(provider);
      setSysInfo((prev: any) => ({ ...prev, llm_provider: r.current, llm_model: r.model }));
      setTestResult({ status: 'ok', message: r.message });
    } catch (e: any) {
      setTestResult({ status: 'error', message: e.message });
    }
    setSwitching(false);
  };

  const testLLM = async () => {
    setTestResult(null);
    try {
      const r = await system.testLLM();
      setTestResult(r);
    } catch (e: any) {
      setTestResult({ status: 'error', error: e.message });
    }
  };

  return (
    <div>
      <h2 className="text-xl font-bold mb-6">Settings</h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

        {/* LLM Provider */}
        <div className="glass p-6">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-500" /> LLM Provider
          </h3>
          <div className="space-y-3 mb-4">
            {[
              { id: 'openai', name: 'OpenAI', desc: 'GPT-4 • Cloud API • Best quality', icon: '🌐' },
              { id: 'local', name: 'Ollama (Local)', desc: 'Free • Runs locally • No API key needed', icon: '🏠' },
            ].map(p => (
              <button key={p.id} onClick={() => switchLLM(p.id)} disabled={switching}
                className={`w-full flex items-center gap-3 p-4 rounded-xl border transition-all text-left ${
                  sysInfo?.llm_provider === p.id
                    ? 'bg-indigo-500/10 border-indigo-500/30 text-white'
                    : 'bg-white/[0.02] border-white/[0.06] text-gray-400 hover:border-indigo-500/20 hover:bg-indigo-500/[0.04]'
                }`}>
                <span className="text-2xl">{p.icon}</span>
                <div className="flex-1">
                  <p className="font-semibold text-sm">{p.name}</p>
                  <p className="text-[11px] text-gray-500">{p.desc}</p>
                </div>
                {sysInfo?.llm_provider === p.id && (
                  <span className="text-xs font-bold text-indigo-400 bg-indigo-500/15 px-2 py-1 rounded">ACTIVE</span>
                )}
              </button>
            ))}
          </div>

          {sysInfo && (
            <div className="text-xs text-gray-500 space-y-1 mb-3 p-3 rounded-lg bg-white/[0.02]">
              <p>Provider: <span className="text-gray-300 font-mono">{sysInfo.llm_provider}</span></p>
              <p>Model: <span className="text-gray-300 font-mono">{sysInfo.llm_model}</span></p>
            </div>
          )}

          <button onClick={testLLM} className="btn-ghost text-xs">🧪 Test Connection</button>

          {testResult && (
            <div className={`mt-3 p-3 rounded-lg text-xs ${
              testResult.status === 'ok' ? 'bg-green-500/10 border border-green-500/20 text-green-400'
              : 'bg-red-500/10 border border-red-500/20 text-red-400'
            }`}>
              {testResult.status === 'ok' ? '✓ ' : '✗ '}{testResult.message || testResult.error || testResult.status}
            </div>
          )}
        </div>

        {/* Profile */}
        <div className="glass p-6">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-green-500" /> Profile
          </h3>
          <div className="space-y-3 text-sm">
            {[
              { label: 'User ID', val: user?.user_id || 'dev_user', mono: true },
              { label: 'Email', val: user?.email || 'dev@example.com' },
              { label: 'Username', val: user?.username || 'dev' },
              { label: 'Role', val: user?.role || 'admin', badge: true },
            ].map((r, i) => (
              <div key={i} className="flex justify-between py-2 border-b border-white/[0.04] last:border-0">
                <span className="text-gray-500">{r.label}</span>
                {r.badge ? <span className="badge badge-completed">{r.val}</span>
                  : <span className={r.mono ? 'font-mono text-xs' : ''}>{r.val}</span>}
              </div>
            ))}
          </div>

          {/* System Health */}
          {sysInfo?.services && (
            <div className="mt-6">
              <h4 className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-3">Infrastructure</h4>
              <div className="space-y-2">
                {Object.entries(sysInfo.services).map(([name, status]: [string, any]) => (
                  <div key={name} className="flex items-center justify-between py-1.5">
                    <span className="text-sm capitalize">{name}</span>
                    <span className={`text-xs font-semibold ${String(status).includes('connect') ? 'text-green-400' : 'text-red-400'}`}>
                      {String(status).includes('connect') ? '● Online' : '○ Offline'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* API Keys — full width */}
        <div className="glass p-6 lg:col-span-2">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-yellow-500" /> API Keys
          </h3>

          <div className="flex gap-2 mb-4 max-w-lg">
            <input className="input-field flex-1" value={newKeyName} onChange={e => setNewKeyName(e.target.value)}
              placeholder="Key name (e.g. ci-scanner)" onKeyDown={e => e.key === 'Enter' && createKey()} />
            <button onClick={createKey} disabled={creating} className="btn-primary shrink-0 text-xs">Create Key</button>
          </div>

          {newKey && (
            <div className="p-3 mb-4 rounded-lg bg-green-500/10 border border-green-500/20 text-green-400 max-w-lg">
              <p className="text-xs font-bold mb-1">🔑 Save this key — it won't be shown again:</p>
              <p className="font-mono text-xs break-all select-all">{newKey}</p>
            </div>
          )}

          {keys.length === 0 ? (
            <p className="text-sm text-gray-600 py-4">No API keys created yet</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {keys.map(k => (
                <div key={k.key_id} className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                  <div>
                    <p className="text-sm font-semibold">{k.name}</p>
                    <p className="text-[10px] text-gray-500 font-mono">{k.key_prefix}... • {k.is_active ? 'Active' : 'Revoked'}</p>
                  </div>
                  {k.is_active && (
                    <button onClick={() => revokeKey(k.key_id)} className="text-[10px] text-red-400 hover:text-red-300 transition">Revoke</button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
