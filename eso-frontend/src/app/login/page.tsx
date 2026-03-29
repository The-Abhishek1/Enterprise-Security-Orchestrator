// src/app/login/page.tsx
'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';

export default function LoginPage() {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, register } = useAuth();
  const router = useRouter();

  const submit = async () => {
    setError(''); setLoading(true);
    try {
      if (mode === 'login') await login(email, password);
      else await register(email, username, password);
      router.push('/dashboard');
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4" style={{ background: 'var(--bg)' }}>
      <div className="glass p-8 w-full max-w-md animate-fade-up">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold tracking-tight">ESO <span className="text-indigo-400 font-normal">Platform</span></h1>
          <p className="text-xs text-gray-500 uppercase tracking-[2px] mt-2">Security Orchestrator</p>
        </div>

        <div className="flex gap-1 mb-6 p-1 rounded-lg bg-white/[0.03]">
          {(['login', 'register'] as const).map(m => (
            <button key={m} onClick={() => setMode(m)}
              className={`flex-1 py-2 rounded-md text-sm font-medium transition-all ${mode === m ? 'bg-indigo-500/15 text-indigo-400' : 'text-gray-500 hover:text-gray-300'}`}>
              {m === 'login' ? 'Sign In' : 'Create Account'}
            </button>
          ))}
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-[11px] text-gray-400 uppercase tracking-wide font-semibold mb-1.5">Email</label>
            <input className="input-field" type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" />
          </div>
          {mode === 'register' && (
            <div>
              <label className="block text-[11px] text-gray-400 uppercase tracking-wide font-semibold mb-1.5">Username</label>
              <input className="input-field" value={username} onChange={e => setUsername(e.target.value)} placeholder="hacker" />
            </div>
          )}
          <div>
            <label className="block text-[11px] text-gray-400 uppercase tracking-wide font-semibold mb-1.5">Password</label>
            <input className="input-field" type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••"
              onKeyDown={e => e.key === 'Enter' && submit()} />
          </div>
        </div>

        {error && <p className="text-red-400 text-sm mt-4 p-3 rounded-lg bg-red-500/10 border border-red-500/20">{error}</p>}

        <button onClick={submit} disabled={loading} className="btn-primary w-full justify-center mt-6">
          {loading ? '...' : mode === 'login' ? 'Sign In' : 'Create Account'}
        </button>

        <p className="text-center text-xs text-gray-600 mt-6">
          Dev mode: Auth is optional — you can skip login
          <button onClick={() => router.push('/dashboard')} className="block mx-auto mt-2 text-indigo-400 hover:text-indigo-300 transition">
            → Skip to Dashboard
          </button>
        </p>
      </div>
    </div>
  );
}
