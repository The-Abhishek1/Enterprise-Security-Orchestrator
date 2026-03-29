// src/components/layout/sidebar.tsx
'use client';
import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import clsx from 'clsx';

const NAV = [
  { href: '/dashboard', icon: '◉', label: 'Dashboard' },
  { href: '/scan/new', icon: '⚡', label: 'New Scan' },
  { href: '/history', icon: '☰', label: 'History' },
  { href: '/settings', icon: '⚙', label: 'Settings' },
];

export default function Sidebar() {
  const path = usePathname();
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);

  if (path === '/login') return null;

  const navContent = (
    <>
      <div className="px-5 pt-5 pb-4 border-b border-white/[0.06] mb-3">
        <h1 className="text-lg font-bold tracking-tight">ESO <span className="text-indigo-400 font-normal">Platform</span></h1>
        <p className="text-[10px] text-gray-500 uppercase tracking-[2px] mt-1">Security Orchestrator</p>
      </div>
      <nav className="flex-1 px-3">
        {NAV.map(n => {
          const active = path === n.href || (n.href !== '/dashboard' && path.startsWith(n.href));
          return (
            <Link key={n.href} href={n.href} onClick={() => setOpen(false)}
              className={clsx(
                'flex items-center gap-3 px-3 py-2.5 my-0.5 rounded-lg text-sm font-medium transition-all border border-transparent',
                active ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/15' : 'text-gray-400 hover:bg-white/[0.04] hover:text-gray-200'
              )}>
              <span className="text-base w-5 text-center">{n.icon}</span>{n.label}
            </Link>
          );
        })}
      </nav>
      <div className="px-5 py-4 border-t border-white/[0.06]">
        {user && (
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-gray-400 truncate">{user.username || user.email}</span>
            <button onClick={() => { logout(); setOpen(false); }} className="text-[10px] text-gray-500 hover:text-red-400 transition">Logout</button>
          </div>
        )}
        <p className="text-[10px] text-gray-600">v1.0 • 7 Tools • AI Engine</p>
      </div>
    </>
  );

  return (
    <>
      {/* Mobile topbar */}
      <div className="lg:hidden fixed top-0 left-0 right-0 z-30 flex items-center justify-between px-4 py-3 bg-[rgba(8,8,20,0.95)] backdrop-blur-xl border-b border-white/[0.06]">
        <h1 className="text-sm font-bold">ESO <span className="text-indigo-400 font-normal">Platform</span></h1>
        <button onClick={() => setOpen(!open)} className="text-gray-400 hover:text-white text-xl">{open ? '✕' : '☰'}</button>
      </div>
      {/* Mobile spacer */}
      <div className="lg:hidden h-12" />

      {/* Mobile overlay */}
      {open && <div className="lg:hidden fixed inset-0 z-40 bg-black/60" onClick={() => setOpen(false)} />}

      {/* Mobile drawer */}
      <aside className={clsx(
        'lg:hidden fixed top-0 left-0 bottom-0 z-50 w-56 flex flex-col bg-[rgba(8,8,20,0.98)] backdrop-blur-xl transition-transform duration-300',
        open ? 'translate-x-0' : '-translate-x-full'
      )}>
        {navContent}
      </aside>

      {/* Desktop sidebar */}
      <aside className="hidden lg:flex w-56 shrink-0 border-r border-white/[0.06] flex-col bg-[rgba(8,8,20,0.95)] backdrop-blur-xl z-10">
        {navContent}
      </aside>
    </>
  );
}
