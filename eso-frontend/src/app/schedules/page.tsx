// src/app/schedules/page.tsx
'use client';
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

export default function SchedulesPage() {
  const [templates, setTemplates] = useState<any[]>([]);
  const [schedules, setSchedules] = useState<any[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [showSchedForm, setShowSchedForm] = useState<string | null>(null);
  const [form, setForm] = useState({ name: '', target: '', goal: 'Scan for open ports and vulnerabilities', description: '' });
  const [cronExpr, setCronExpr] = useState('daily');
  const [maxRuns, setMaxRuns] = useState('');

  const load = async () => {
    api.get('/schedules/templates').then(r => setTemplates(r.templates || [])).catch(() => {});
    api.get('/schedules/').then(r => setSchedules(r.schedules || [])).catch(() => {});
  };
  useEffect(() => { load(); }, []);

  const createTemplate = async () => {
    if (!form.name || !form.target) return;
    try {
      await api.post('/schedules/templates', form);
      setForm({ name: '', target: '', goal: 'Scan for open ports and vulnerabilities', description: '' });
      setShowForm(false);
      load();
    } catch {}
  };

  const deleteTemplate = async (id: string) => {
    if (!confirm('Delete this template?')) return;
    await api.del(`/schedules/templates/${id}`).catch(() => {});
    load();
  };

  const createSchedule = async (templateId: string) => {
    try {
      await api.post('/schedules/', {
        template_id: templateId,
        cron_expression: cronExpr,
        max_runs: maxRuns ? parseInt(maxRuns) : null
      });
      setShowSchedForm(null);
      setCronExpr('daily');
      setMaxRuns('');
      load();
    } catch {}
  };

  const toggleSchedule = async (id: string, active: boolean) => {
    await api.put(`/schedules/${id}/toggle?active=${active}`, {}).catch(() => {});
    load();
  };

  const deleteSchedule = async (id: string) => {
    if (!confirm('Delete this schedule?')) return;
    await api.del(`/schedules/${id}`).catch(() => {});
    load();
  };

  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
        <h2 className="text-xl font-bold">Scheduled Scans</h2>
        <button onClick={() => setShowForm(!showForm)} className="btn-primary text-xs self-start">+ New Template</button>
      </div>

      {/* Create template form */}
      {showForm && (
        <div className="glass p-5 mb-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4">New Scan Template</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
            <div>
              <label className="block text-[11px] text-gray-400 uppercase tracking-wide font-semibold mb-1.5">Template Name</label>
              <input className="input-field" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Weekly Perimeter Scan" />
            </div>
            <div>
              <label className="block text-[11px] text-gray-400 uppercase tracking-wide font-semibold mb-1.5">Target</label>
              <input className="input-field" value={form.target} onChange={e => setForm(f => ({ ...f, target: e.target.value }))} placeholder="scanme.nmap.org" />
            </div>
            <div className="sm:col-span-2">
              <label className="block text-[11px] text-gray-400 uppercase tracking-wide font-semibold mb-1.5">Goal</label>
              <input className="input-field" value={form.goal} onChange={e => setForm(f => ({ ...f, goal: e.target.value }))} />
            </div>
            <div className="sm:col-span-2">
              <label className="block text-[11px] text-gray-400 uppercase tracking-wide font-semibold mb-1.5">Description (optional)</label>
              <input className="input-field" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="Runs against the external perimeter" />
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={createTemplate} className="btn-primary text-xs">Create Template</button>
            <button onClick={() => setShowForm(false)} className="btn-ghost text-xs">Cancel</button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Templates */}
        <div className="glass p-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-500" /> Templates
          </h3>
          {templates.length === 0 ? (
            <div className="text-center py-8 text-gray-600 text-sm">No templates — create one above</div>
          ) : (
            <div className="space-y-2">
              {templates.map(t => (
                <div key={t.template_id} className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-sm font-semibold truncate">{t.name}</p>
                      <p className="text-[11px] text-gray-500 mt-0.5 truncate">{t.target} • {t.goal?.slice(0, 50)}</p>
                    </div>
                    <div className="flex gap-3 shrink-0">
                      <button onClick={() => setShowSchedForm(showSchedForm === t.template_id ? null : t.template_id)}
                        className="text-[11px] text-indigo-400 hover:text-indigo-300">⏰ Schedule</button>
                      <button onClick={() => deleteTemplate(t.template_id)}
                        className="text-[11px] text-red-400 hover:text-red-300">Delete</button>
                    </div>
                  </div>
                  {showSchedForm === t.template_id && (
                    <div className="mt-3 p-3 rounded-lg bg-white/[0.02] border border-indigo-500/20">
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-2">
                        <div>
                          <label className="block text-[10px] text-gray-400 mb-1">Frequency</label>
                          <select className="input-field text-xs" value={cronExpr} onChange={e => setCronExpr(e.target.value)}>
                            <option value="30m">Every 30 min</option>
                            <option value="hourly">Hourly</option>
                            <option value="4h">Every 4 hours</option>
                            <option value="12h">Every 12 hours</option>
                            <option value="daily">Daily</option>
                            <option value="weekly">Weekly</option>
                            <option value="monthly">Monthly</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-[10px] text-gray-400 mb-1">Max runs (optional)</label>
                          <input className="input-field text-xs" type="number" value={maxRuns} onChange={e => setMaxRuns(e.target.value)} placeholder="∞" />
                        </div>
                      </div>
                      <button onClick={() => createSchedule(t.template_id)} className="btn-success text-xs w-full">Create Schedule</button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Active Schedules */}
        <div className="glass p-5">
          <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-green-500" /> Active Schedules
          </h3>
          {schedules.length === 0 ? (
            <div className="text-center py-8 text-gray-600 text-sm">No schedules — pick a template and schedule it</div>
          ) : (
            <div className="space-y-2">
              {schedules.map(s => (
                <div key={s.schedule_id} className={`p-3 rounded-lg border ${s.is_active ? 'bg-white/[0.02] border-white/[0.04]' : 'bg-white/[0.01] border-white/[0.03] opacity-50'}`}>
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-sm font-semibold truncate">{s.template_name || s.template_id}</p>
                      <p className="text-[11px] text-gray-500 truncate">{s.target} • <span className="text-indigo-400">{s.cron_expression}</span></p>
                      <div className="flex flex-wrap gap-3 mt-1 text-[10px] text-gray-600">
                        <span>Runs: {s.run_count}{s.max_runs ? `/${s.max_runs}` : ''}</span>
                        {s.next_run_at && <span>Next: {new Date(s.next_run_at).toLocaleString()}</span>}
                        {s.last_run_at && <span>Last: {new Date(s.last_run_at).toLocaleString()}</span>}
                      </div>
                    </div>
                    <div className="flex gap-3 shrink-0">
                      <button onClick={() => toggleSchedule(s.schedule_id, !s.is_active)}
                        className={`text-[11px] ${s.is_active ? 'text-yellow-400' : 'text-green-400'}`}>
                        {s.is_active ? '⏸ Pause' : '▶ Resume'}
                      </button>
                      <button onClick={() => deleteSchedule(s.schedule_id)} className="text-[11px] text-red-400">Delete</button>
                    </div>
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
