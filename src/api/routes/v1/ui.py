# src/api/routes/v1/ui.py
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/ui", tags=["ui"])

@router.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(HTML)

HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESO — Security Orchestrator</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
--bg:#050510;--bg2:#0a0a1f;--surface:rgba(15,15,35,0.7);--surface2:rgba(20,20,45,0.6);
--glass:rgba(255,255,255,0.03);--glass-h:rgba(255,255,255,0.06);
--border:rgba(255,255,255,0.06);--border-h:rgba(255,255,255,0.12);
--text:#e8eaf0;--text2:#8b92a8;--text3:#565c72;
--accent:#6366f1;--accent2:#818cf8;--accent-g:rgba(99,102,241,0.12);
--green:#22c55e;--red:#ef4444;--yellow:#eab308;--orange:#f97316;--cyan:#06b6d4;
--f:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono',monospace;
--r:14px;--r-sm:8px;--r-lg:20px;
}
html{height:100%;font-family:var(--f);background:var(--bg);color:var(--text)}
body{min-height:100vh;overflow-x:hidden;
background:var(--bg);
background-image:
  radial-gradient(ellipse 80% 50% at 50% -20%,rgba(99,102,241,0.12),transparent 70%),
  radial-gradient(ellipse 60% 40% at 100% 100%,rgba(139,92,246,0.06),transparent 60%);
}

/* Glass */
.g{background:var(--glass);backdrop-filter:blur(24px) saturate(1.3);-webkit-backdrop-filter:blur(24px) saturate(1.3);
border:1px solid var(--border);border-radius:var(--r);transition:all .25s ease}
.g:hover{border-color:var(--border-h)}
.g2{background:var(--surface);border:1px solid var(--border);border-radius:var(--r)}

/* Layout */
.app{display:flex;height:100vh}
.sidebar{width:240px;border-right:1px solid var(--border);padding:20px 0;display:flex;flex-direction:column;
background:rgba(8,8,20,0.95);backdrop-filter:blur(20px);flex-shrink:0;z-index:10}
.main{flex:1;overflow-y:auto;padding:24px 32px}
@media(max-width:768px){.sidebar{display:none}.main{padding:16px}}

/* Sidebar */
.brand{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.brand h1{font-size:18px;font-weight:700;letter-spacing:-0.5px}
.brand h1 span{color:var(--accent);font-weight:400}
.brand p{font-size:10px;color:var(--text3);margin-top:4px;text-transform:uppercase;letter-spacing:1.5px}

.nav{flex:1;padding:0 10px}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 14px;margin:2px 0;border-radius:var(--r-sm);
cursor:pointer;font-size:13px;font-weight:500;color:var(--text2);transition:all .2s;border:1px solid transparent}
.nav-item:hover{background:var(--glass-h);color:var(--text)}
.nav-item.active{background:var(--accent-g);color:var(--accent);border-color:rgba(99,102,241,0.15)}
.nav-item .icon{font-size:16px;width:20px;text-align:center}
.nav-item .badge-count{margin-left:auto;background:var(--accent);color:white;font-size:10px;
padding:2px 7px;border-radius:10px;font-weight:600}

.sidebar-footer{padding:16px 20px;border-top:1px solid var(--border);font-size:11px;color:var(--text3)}

/* Top bar */
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
.topbar h2{font-size:20px;font-weight:700;letter-spacing:-0.3px}
.topbar-actions{display:flex;gap:8px}

/* Cards */
.card-grid{display:grid;gap:16px;margin-bottom:24px}
.card-grid-4{grid-template-columns:repeat(4,1fr)}
.card-grid-3{grid-template-columns:repeat(3,1fr)}
.card-grid-2{grid-template-columns:1fr 1fr}
.card-grid-main{grid-template-columns:400px 1fr}
@media(max-width:1100px){.card-grid-4{grid-template-columns:repeat(2,1fr)}.card-grid-main{grid-template-columns:1fr}}
@media(max-width:600px){.card-grid-4,.card-grid-3,.card-grid-2{grid-template-columns:1fr}}

.stat-card{padding:20px;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:0;transition:opacity .3s}
.stat-card:hover::before{opacity:1}
.stat-label{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;font-weight:600}
.stat-val{font-size:32px;font-weight:800;font-family:var(--mono);margin:8px 0 2px;letter-spacing:-1px}
.stat-sub{font-size:11px;color:var(--text3)}

/* Buttons */
.btn{padding:8px 18px;border:none;border-radius:var(--r-sm);cursor:pointer;font-family:var(--f);font-size:12px;
font-weight:600;transition:all .2s;display:inline-flex;align-items:center;gap:6px;text-decoration:none}
.btn-primary{background:var(--accent);color:white;box-shadow:0 0 20px rgba(99,102,241,0.2)}
.btn-primary:hover{background:var(--accent2);box-shadow:0 0 30px rgba(99,102,241,0.35);transform:translateY(-1px)}
.btn-ghost{background:transparent;color:var(--text2);border:1px solid var(--border)}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.btn-success{background:rgba(34,197,94,0.12);color:var(--green);border:1px solid rgba(34,197,94,0.2)}
.btn-success:hover{background:rgba(34,197,94,0.2)}
.btn-danger{background:rgba(239,68,68,0.12);color:var(--red);border:1px solid rgba(239,68,68,0.2)}
.btn-danger:hover{background:rgba(239,68,68,0.2)}
.btn-sm{padding:5px 12px;font-size:11px}
.btn:disabled{opacity:0.35;cursor:not-allowed;transform:none!important}

/* Inputs */
input,textarea,select{background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:var(--r-sm);
padding:10px 14px;color:var(--text);font-family:var(--f);font-size:13px;width:100%;transition:all .25s;outline:none}
input:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-g)}
label{display:block;font-size:11px;color:var(--text2);margin-bottom:6px;text-transform:uppercase;letter-spacing:.8px;font-weight:600}

/* Badge */
.badge{display:inline-flex;padding:3px 9px;border-radius:20px;font-size:10px;font-weight:700;
text-transform:uppercase;letter-spacing:.5px}
.b-running{background:rgba(99,102,241,0.12);color:var(--accent);border:1px solid rgba(99,102,241,0.25)}
.b-completed{background:rgba(34,197,94,0.12);color:var(--green);border:1px solid rgba(34,197,94,0.25)}
.b-failed,.b-timeout{background:rgba(239,68,68,0.12);color:var(--red);border:1px solid rgba(239,68,68,0.25)}
.b-planning,.b-pending,.b-queued,.b-validating{background:rgba(234,179,8,0.12);color:var(--yellow);border:1px solid rgba(234,179,8,0.25)}

/* Progress */
.pbar{height:4px;background:rgba(255,255,255,0.04);border-radius:2px;overflow:hidden}
.pfill{height:100%;background:linear-gradient(90deg,var(--accent),var(--cyan));border-radius:2px;transition:width .6s ease}

/* Table */
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;padding:10px 14px;color:var(--text3);font-size:10px;text-transform:uppercase;
letter-spacing:1px;font-weight:700;border-bottom:1px solid var(--border)}
.tbl td{padding:12px 14px;border-bottom:1px solid rgba(255,255,255,0.03)}
.tbl tr{cursor:pointer;transition:background .15s}
.tbl tr:hover td{background:rgba(255,255,255,0.02)}

/* Proposal */
.prop{padding:14px 16px;margin-bottom:8px;border-radius:var(--r-sm);background:rgba(255,255,255,0.02);
border:1px solid var(--border);display:flex;align-items:center;gap:12px;transition:all .25s}
.prop:hover{border-color:var(--accent);background:var(--accent-g)}
.prop input[type=checkbox]{accent-color:var(--accent);width:16px;height:16px;cursor:pointer}
.prop-name{font-weight:600;font-size:13px}
.prop-meta{font-size:11px;color:var(--text3);margin-top:2px}

/* Log */
.log-box{font-family:var(--mono);font-size:11px;color:var(--text2);background:rgba(0,0,0,0.35);
border-radius:var(--r-sm);padding:14px;max-height:250px;overflow-y:auto;line-height:1.9;border:1px solid var(--border)}
.log-line{padding:1px 0}

/* Report */
.report-box{font-size:13px;line-height:1.8;padding:20px;color:var(--text)}
.report-box h1{font-size:18px;color:var(--accent);margin:20px 0 8px;font-weight:700}
.report-box h2{font-size:15px;color:var(--accent2);margin:18px 0 6px;font-weight:600;padding-bottom:4px;border-bottom:1px solid var(--border)}
.report-box table{width:100%;border-collapse:collapse;margin:12px 0;font-size:12px;font-family:var(--mono)}
.report-box th{background:rgba(99,102,241,0.1);padding:8px 10px;text-align:left;color:var(--accent)}
.report-box td{padding:8px 10px;border-bottom:1px solid rgba(255,255,255,0.04)}
.report-box strong{color:var(--accent2)}

/* Animations */
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes glow{0%,100%{box-shadow:0 0 5px var(--accent-g)}50%{box-shadow:0 0 20px var(--accent-g)}}
.anim{animation:fadeUp .35s ease both}
.pulse{animation:pulse 1.5s infinite}
.anim-d1{animation-delay:.05s}.anim-d2{animation-delay:.1s}.anim-d3{animation-delay:.15s}.anim-d4{animation-delay:.2s}

/* Empty */
.empty{text-align:center;padding:48px 20px;color:var(--text3)}
.empty-icon{font-size:36px;margin-bottom:10px;opacity:.5}
.empty-text{font-size:13px}

/* Toast */
#toasts{position:fixed;bottom:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px}
.toast{padding:10px 18px;border-radius:var(--r-sm);font-size:12px;font-weight:500;animation:fadeUp .3s;backdrop-filter:blur(10px)}
.t-ok{background:rgba(34,197,94,0.15);border:1px solid rgba(34,197,94,0.3);color:var(--green)}
.t-err{background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);color:var(--red)}
.t-info{background:rgba(99,102,241,0.15);border:1px solid rgba(99,102,241,0.3);color:var(--accent)}

/* Section */
.sec{padding:20px}
.sec-title{font-size:13px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;text-transform:uppercase;letter-spacing:.5px}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block}
</style>
</head>
<body>
<div class="app">

<!-- Sidebar -->
<div class="sidebar">
  <div class="brand"><h1>ESO <span>Platform</span></h1><p>Security Orchestrator</p></div>
  <nav class="nav">
    <div class="nav-item active" onclick="go('dashboard')" id="nav-dashboard"><span class="icon">◉</span> Dashboard</div>
    <div class="nav-item" onclick="go('scan')" id="nav-scan"><span class="icon">⚡</span> New Scan</div>
    <div class="nav-item" onclick="go('active')" id="nav-active"><span class="icon">◎</span> Active Scan <span class="badge-count" id="activeBadge" hidden>1</span></div>
    <div class="nav-item" onclick="go('history')" id="nav-history"><span class="icon">☰</span> History</div>
  </nav>
  <div class="sidebar-footer">v1.0 • 7 Tools Available<br>AI-Powered Pentest Engine</div>
</div>

<!-- Main Content -->
<div class="main" id="main">

<!-- PAGE: Dashboard -->
<div id="pg-dashboard">
  <div class="topbar"><h2>Dashboard</h2></div>
  <div class="card-grid card-grid-4" style="margin-bottom:24px">
    <div class="g stat-card anim"><div class="stat-label">Total Scans</div><div class="stat-val" style="color:var(--accent)" id="dTotal">0</div><div class="stat-sub">All time</div></div>
    <div class="g stat-card anim anim-d1"><div class="stat-label">Completed</div><div class="stat-val" style="color:var(--green)" id="dComp">0</div><div class="stat-sub">Successful</div></div>
    <div class="g stat-card anim anim-d2"><div class="stat-label">Running</div><div class="stat-val" style="color:var(--cyan)" id="dRun">0</div><div class="stat-sub">In progress</div></div>
    <div class="g stat-card anim anim-d3"><div class="stat-label">Tools</div><div class="stat-val" style="color:var(--yellow)" id="dTools">7</div><div class="stat-sub">Available</div></div>
  </div>
  <div class="g sec anim anim-d4">
    <div class="sec-title"><span class="dot" style="background:var(--accent)"></span> Recent Activity</div>
    <div id="recentList"><div class="empty"><div class="empty-icon">🔍</div><div class="empty-text">No scans yet — launch one!</div></div></div>
  </div>
</div>

<!-- PAGE: New Scan -->
<div id="pg-scan" hidden>
  <div class="topbar"><h2>Launch Scan</h2></div>
  <div class="card-grid card-grid-2">
    <div class="g sec anim">
      <div class="sec-title"><span class="dot" style="background:var(--accent)"></span> Target Configuration</div>
      <div style="margin-bottom:16px"><label>Target Host / IP</label><input id="inTarget" placeholder="scanme.nmap.org"></div>
      <div style="margin-bottom:16px"><label>Scan Goal</label><textarea id="inGoal" rows="3" placeholder="Scan for open ports and vulnerabilities">Scan for open ports and vulnerabilities</textarea></div>
      <button class="btn btn-primary" onclick="startScan()" id="btnScan">⚡ Launch Scan</button>
    </div>
    <div class="g sec anim anim-d1">
      <div class="sec-title"><span class="dot" style="background:var(--cyan)"></span> Available Tools</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
        <div class="prop" style="cursor:default"><div><div class="prop-name">nmap</div><div class="prop-meta">Port & service scanning</div></div></div>
        <div class="prop" style="cursor:default"><div><div class="prop-name">nuclei</div><div class="prop-meta">Vulnerability scanner</div></div></div>
        <div class="prop" style="cursor:default"><div><div class="prop-name">gobuster</div><div class="prop-meta">Directory brute-force</div></div></div>
        <div class="prop" style="cursor:default"><div><div class="prop-name">nikto</div><div class="prop-meta">Web vuln scanner</div></div></div>
        <div class="prop" style="cursor:default"><div><div class="prop-name">ffuf</div><div class="prop-meta">Fast web fuzzer</div></div></div>
        <div class="prop" style="cursor:default"><div><div class="prop-name">whatweb</div><div class="prop-meta">Tech fingerprinting</div></div></div>
        <div class="prop" style="cursor:default"><div><div class="prop-name">sqlmap</div><div class="prop-meta">SQL injection testing</div></div></div>
      </div>
    </div>
  </div>
</div>

<!-- PAGE: Active Scan -->
<div id="pg-active" hidden>
  <div class="topbar"><h2>Active Scan</h2><div class="topbar-actions" id="activeActions"></div></div>
  <div id="activeContent"><div class="empty" style="padding:80px"><div class="empty-icon">◎</div><div class="empty-text">No active scan — <span style="color:var(--accent);cursor:pointer" onclick="go('scan')">launch one</span></div></div></div>
</div>

<!-- PAGE: History -->
<div id="pg-history" hidden>
  <div class="topbar"><h2>Scan History</h2></div>
  <div class="g sec anim" id="historyContent"><div class="empty"><div class="empty-icon">☰</div><div class="empty-text">No scan history</div></div></div>
</div>

</div></div>
<div id="toasts"></div>

<script>
const A='/api/v1';
let proc=null,poll=null;

async function f(m,p,b){
  const o={method:m,headers:{'Content-Type':'application/json'}};
  if(b)o.body=JSON.stringify(b);
  const r=await fetch(A+p,o);
  if(!r.ok){const e=await r.json().catch(()=>({}));throw new Error(e.detail||e.error||r.statusText)}
  return r.json();
}
function toast(m,t='ok'){const e=document.createElement('div');e.className=`toast t-${t}`;e.textContent=m;document.getElementById('toasts').appendChild(e);setTimeout(()=>e.remove(),4000)}
function $(id){return document.getElementById(id)}
function riskC(r){return{critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--cyan)',none:'var(--text3)',info:'var(--text3)'}[r]||'var(--text3)'}
function badgeC(s){return{running:'b-running',completed:'b-completed',failed:'b-failed',timeout:'b-failed',planning:'b-planning',pending:'b-pending',queued:'b-planning',validating:'b-planning'}[s]||'b-planning'}

// Navigation
function go(pg){
  document.querySelectorAll('[id^="pg-"]').forEach(e=>e.hidden=true);
  $('pg-'+pg).hidden=false;
  document.querySelectorAll('.nav-item').forEach(e=>e.classList.remove('active'));
  $('nav-'+pg)?.classList.add('active');
  if(pg==='history')loadHistory();
  if(pg==='dashboard')loadStats();
  if(pg==='active'&&proc)startPoll();
}

// Start Scan
async function startScan(){
  const t=$('inTarget').value.trim(),g=$('inGoal').value.trim();
  if(!t){toast('Enter a target','err');return}
  $('btnScan').disabled=true;$('btnScan').textContent='Starting...';
  try{
    const r=await f('POST','/hybrid/execute',{goal:g||'Scan '+t+' for open ports and vulnerabilities',target:t});
    proc=r.process_id;toast('Scan launched: '+proc,'info');
    go('active');startPoll();
  }catch(e){toast(e.message,'err')}
  finally{$('btnScan').disabled=false;$('btnScan').textContent='⚡ Launch Scan'}
}

// Polling
function startPoll(){stopPoll();upd();poll=setInterval(upd,4000)}
function stopPoll(){if(poll){clearInterval(poll);poll=null}}

async function upd(){
  if(!proc)return;
  try{
    const s=await f('GET','/hybrid/status/'+proc);
    renderActive(s);
    if(s.awaiting_approval)checkProps();
    if(['completed','failed','timeout'].includes(s.status)){stopPoll();if(s.status==='completed')toast('Scan complete!');loadStats();$('activeBadge').hidden=true}
    else{$('activeBadge').hidden=false}
  }catch(e){console.warn(e)}
}

function renderActive(s){
  const p=s.progress||0,r=s.risk_summary||{},dur=s.duration?(s.duration/60).toFixed(1)+'m':'—';
  let h=`<div class="card-grid card-grid-main"><div>`;
  // Status card
  h+=`<div class="g sec anim"><div class="sec-title"><span class="dot" style="background:var(--accent)"></span> Status</div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <div style="font-size:16px;font-weight:700">${s.target||'—'}</div>
      <span class="badge ${badgeC(s.status)}">${s.status}</span>
    </div>
    <div style="font-size:12px;color:var(--text3);margin-bottom:12px">${s.goal||''}</div>
    <div class="pbar"><div class="pfill" style="width:${p}%"></div></div>
    <div style="font-size:11px;color:var(--text3);margin-top:6px">${p.toFixed(0)}% complete — ${s.completed_tasks||0}/${s.total_tasks||0} tasks</div>
    <div class="card-grid card-grid-3" style="margin-top:16px;gap:10px">
      <div style="text-align:center;padding:10px;background:rgba(255,255,255,0.02);border-radius:var(--r-sm)"><div style="font-size:22px;font-weight:800;font-family:var(--mono);color:var(--accent)">${s.findings_count||0}</div><div style="font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px">Findings</div></div>
      <div style="text-align:center;padding:10px;background:rgba(255,255,255,0.02);border-radius:var(--r-sm)"><div style="font-size:22px;font-weight:800;font-family:var(--mono);color:${riskC(r.overall_risk)}">${(r.overall_risk||'—').toUpperCase()}</div><div style="font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px">Risk</div></div>
      <div style="text-align:center;padding:10px;background:rgba(255,255,255,0.02);border-radius:var(--r-sm)"><div style="font-size:22px;font-weight:800;font-family:var(--mono);color:var(--text2)">${dur}</div><div style="font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px">Duration</div></div>
    </div>
    <div style="font-size:10px;color:var(--text3);margin-top:12px;font-family:var(--mono)">ID: ${s.process_id}</div>
  </div>`;
  // Proposals
  h+=`<div id="propArea" ${s.awaiting_approval?'':'hidden'}></div>`;
  h+=`</div><div>`;
  // Log
  h+=`<div class="g sec"><div class="sec-title"><span class="dot" style="background:var(--green)"></span> Live Progress</div>
    <div class="log-box">${buildLog(s)}</div></div>`;
  // Report
  if(s.report){
    h+=`<div class="g sec" style="margin-top:16px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <div class="sec-title" style="margin:0"><span class="dot" style="background:var(--green)"></span> Report</div>
      <button class="btn btn-ghost btn-sm" onclick="window.open('${A}/hybrid/report/${proc}/pdf','_blank')">📥 Download PDF</button>
    </div><div class="report-box">${renderMD(s.report)}</div></div>`;
  }
  h+=`</div></div>`;
  $('activeContent').innerHTML=h;
}

function buildLog(s){
  let l=[];
  l.push(`<span style="color:var(--accent)">[${s.status}]</span> ${s.target} — ${s.completed_tasks||0}/${s.total_tasks||0} tasks`);
  if(s.risk_summary){const r=s.risk_summary;l.push(`<span style="color:var(--cyan)">Risk:</span> ${(r.overall_risk||'—').toUpperCase()} (${(r.overall_score||0).toFixed(1)}) C:${r.critical_count||0} H:${r.high_count||0} M:${r.medium_count||0}`)}
  if(s.awaiting_approval)l.push('<span style="color:var(--yellow)" class="pulse">⏸ Waiting for approval...</span>');
  if(s.findings_count)l.push(`<span style="color:var(--green)">Findings:</span> ${s.findings_count}`);
  if(s.dynamic_tasks)l.push(`<span style="color:var(--accent)">AI tasks:</span> ${s.dynamic_tasks}`);
  if(s.llm_calls)l.push(`LLM calls: ${s.llm_calls}`);
  return l.map(x=>`<div class="log-line">${x}</div>`).join('');
}

function renderMD(md){
  return md
    .replace(/^## (.+)$/gm,'<h2>$1</h2>')
    .replace(/^# (.+)$/gm,'<h1>$1</h1>')
    .replace(/^\d+\.\s(.+)$/gm,'<div style="padding-left:16px;margin:3px 0">• $1</div>')
    .replace(/^- (.+)$/gm,'<div style="padding-left:16px;margin:3px 0">• $1</div>')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/\|(.+)\|/g,m=>{
      const c=m.split('|').filter(x=>x.trim());
      if(c.every(x=>/^[-\s]+$/.test(x)))return '';
      return '<tr>'+c.map(x=>'<td>'+x.trim()+'</td>').join('')+'</tr>'})
    .replace(/(<tr>.*?<\/tr>\s*)+/gs,'<table>$&</table>')
    .replace(/\n\n/g,'<br>');
}

// Proposals
async function checkProps(){
  try{
    const r=await f('GET','/hybrid/proposals/'+proc);
    if(r.awaiting_approval&&r.proposals?.length){
      let h=`<div class="g sec" style="margin-top:16px;border-color:rgba(234,179,8,0.2)">
        <div class="sec-title"><span class="dot" style="background:var(--yellow)"></span> AI Proposals — Approve to Continue</div>`;
      r.proposals.forEach((p,i)=>{
        h+=`<div class="prop anim"><input type="checkbox" checked data-n="${p.task_name}" id="ck${i}">
          <div style="flex:1"><div class="prop-name">${p.task_name}</div>
          <div class="prop-meta">🔧 ${p.tool} • Priority ${p.priority} • ${p.reason}</div></div></div>`;
      });
      h+=`<div style="display:flex;gap:8px;margin-top:12px">
        <button class="btn btn-success btn-sm" onclick="approveChecked()">✓ Approve Selected</button>
        <button class="btn btn-danger btn-sm" onclick="rejectAll()">✗ Skip All</button>
      </div></div>`;
      const area=$('propArea');if(area){area.hidden=false;area.innerHTML=h}
    }
  }catch(e){}
}
async function approveChecked(){
  const names=[...document.querySelectorAll('#propArea input:checked')].map(c=>c.dataset.n);
  if(!names.length){toast('Select tasks','err');return}
  try{await f('POST','/hybrid/approve/'+proc,{approved:names});toast('Approved '+names.length+' task(s)','info')}catch(e){toast(e.message,'err')}
}
async function rejectAll(){
  try{await f('POST','/hybrid/approve/'+proc,{approved:[]});toast('Proposals skipped')}catch(e){toast(e.message,'err')}
}

// History
async function loadHistory(){
  try{
    const r=await f('GET','/auth/scans');
    if(!r.scans?.length){$('historyContent').innerHTML='<div class="empty"><div class="empty-icon">☰</div><div class="empty-text">No scan history</div></div>';return}
    let h=`<table class="tbl"><thead><tr><th>Target</th><th>Status</th><th>Risk</th><th>Findings</th><th>Duration</th><th>Date</th></tr></thead><tbody>`;
    r.scans.forEach(s=>{
      h+=`<tr onclick="proc='${s.process_id}';go('active');upd()">
        <td style="font-weight:600">${s.target||'—'}</td>
        <td><span class="badge ${badgeC(s.status)}">${s.status}</span></td>
        <td style="color:${riskC(s.risk_level)};font-weight:600">${(s.risk_level||'—').toUpperCase()}</td>
        <td style="font-family:var(--mono)">${s.findings_count||0}</td>
        <td>${s.duration_seconds?(s.duration_seconds/60).toFixed(1)+'m':'—'}</td>
        <td style="color:var(--text3)">${new Date(s.created_at).toLocaleDateString()}</td></tr>`;
    });
    h+='</tbody></table>';
    $('historyContent').innerHTML=h;
  }catch(e){}
}

// Stats
async function loadStats(){
  try{
    const r=await f('GET','/hybrid/list');
    const a=r.executions||[];
    $('dTotal').textContent=a.length;
    $('dComp').textContent=a.filter(e=>e.status==='completed').length;
    $('dRun').textContent=a.filter(e=>['running','planning','queued'].includes(e.status)).length;
    const recent=a.slice(0,6);
    if(recent.length){
      $('recentList').innerHTML=recent.map(s=>`
        <div class="prop" onclick="proc='${s.process_id}';go('active');upd()" style="cursor:pointer;margin-bottom:6px">
          <div style="flex:1"><div class="prop-name">${s.target||'—'}</div><div class="prop-meta">${s.process_id}</div></div>
          <span class="badge ${badgeC(s.status)}">${s.status}</span>
        </div>`).join('');
    }
  }catch(e){}
}

loadStats();
</script>
</body></html>"""
