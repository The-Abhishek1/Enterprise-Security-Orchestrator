// src/app/teams/page.tsx
'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '@/lib/api';

export default function TeamsPage() {
  const [teams, setTeams] = useState<any[]>([]);
  const [selectedTeam, setSelectedTeam] = useState<string | null>(null);
  const [members, setMembers] = useState<any[]>([]);
  const [teamScans, setTeamScans] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', description: '' });
  const [inviteEmail, setInviteEmail] = useState('');

  const load = () => api.get('/collab/teams').then(r => setTeams(r.teams || [])).catch(() => {});
  useEffect(() => { load(); }, []);

  const selectTeam = async (teamId: string) => {
    setSelectedTeam(teamId);
    api.get(`/collab/teams/${teamId}/members`).then(r => setMembers(r.members || [])).catch(() => {});
    api.get(`/collab/teams/${teamId}/scans`).then(r => setTeamScans(r.scans || [])).catch(() => {});
  };

  const createTeam = async () => {
    if (!form.name) return;
    await api.post('/collab/teams', form).catch(() => {});
    setForm({ name: '', description: '' }); setShowCreate(false); load();
  };

  const invite = async () => {
    if (!inviteEmail || !selectedTeam) return;
    try {
      await api.post(`/collab/teams/${selectedTeam}/invite`, { email: inviteEmail });
      setInviteEmail('');
      selectTeam(selectedTeam);
    } catch (e: any) { alert(e.message); }
  };

  const removeMember = async (userId: string) => {
    if (!selectedTeam || !confirm('Remove this member?')) return;
    await api.del(`/collab/teams/${selectedTeam}/members/${userId}`).catch(() => {});
    selectTeam(selectedTeam);
  };

  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
        <h2 className="text-xl font-bold">Teams</h2>
        <button onClick={() => setShowCreate(!showCreate)} className="btn-primary text-xs self-start">+ New Team</button>
      </div>

      {showCreate && (
        <div className="glass p-5 mb-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-3">Create Team</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
            <input className="input-field" placeholder="Team name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            <input className="input-field" placeholder="Description (optional)" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          </div>
          <div className="flex gap-2">
            <button onClick={createTeam} className="btn-primary text-xs">Create</button>
            <button onClick={() => setShowCreate(false)} className="btn-ghost text-xs">Cancel</button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Team list */}
        <div className="glass p-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-500" /> Your Teams
          </h3>
          {teams.length === 0 ? (
            <p className="text-sm text-gray-600 py-6 text-center">No teams yet</p>
          ) : (
            <div className="space-y-2">
              {teams.map(t => (
                <div key={t.team_id} onClick={() => selectTeam(t.team_id)}
                  className={`p-3 rounded-lg border cursor-pointer transition ${selectedTeam === t.team_id ? 'bg-indigo-500/10 border-indigo-500/20' : 'bg-white/[0.02] border-white/[0.04] hover:border-white/[0.1]'}`}>
                  <p className="text-sm font-semibold">{t.name}</p>
                  <p className="text-[10px] text-gray-500">{t.member_count} member{t.member_count !== 1 ? 's' : ''} • {t.role}</p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Team detail */}
        <div className="lg:col-span-2 space-y-5">
          {selectedTeam ? (
            <>
              {/* Members */}
              <div className="glass p-5">
                <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-green-500" /> Members
                </h3>
                <div className="flex gap-2 mb-4">
                  <input className="input-field flex-1" placeholder="Invite by email..." value={inviteEmail}
                    onChange={e => setInviteEmail(e.target.value)} onKeyDown={e => e.key === 'Enter' && invite()} />
                  <button onClick={invite} className="btn-primary text-xs shrink-0">Invite</button>
                </div>
                <div className="space-y-2">
                  {members.map(m => (
                    <div key={m.user_id} className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                      <div>
                        <p className="text-sm font-semibold">{m.username}</p>
                        <p className="text-[10px] text-gray-500">{m.email} • {m.role}</p>
                      </div>
                      {m.role !== 'admin' && m.role !== 'owner' && (
                        <button onClick={() => removeMember(m.user_id)} className="text-[10px] text-red-400 hover:text-red-300">Remove</button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Team scans */}
              <div className="glass p-5">
                <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-500" /> Shared Scans
                </h3>
                {teamScans.length === 0 ? (
                  <p className="text-sm text-gray-600 py-4 text-center">No scans from team members yet</p>
                ) : (
                  <div className="space-y-2">
                    {teamScans.map(s => (
                      <Link key={s.process_id} href={`/scan/${s.process_id}`}
                        className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.04] hover:border-indigo-500/20 transition">
                        <div>
                          <p className="text-sm font-semibold">{s.target}</p>
                          <p className="text-[10px] text-gray-500">{s.username} • {s.findings_count} findings</p>
                        </div>
                        <span className={`badge badge-${s.status}`}>{s.status}</span>
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="glass p-10 text-center text-gray-600">
              <p className="text-2xl mb-2 opacity-30">👥</p>
              <p className="text-sm">Select a team to view members and shared scans</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
