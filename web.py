import gzip, hashlib, json, os, sqlite3, subprocess, threading, time, uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import parse
from urllib import request

from analyze import matches, template_family_candidates
from export_opsgenie import collect_alerts, fetch_activity
from features import History, features, label, parse_ts
from score import decide, normalize, make_laya

DB = os.environ.get("ALERTS_ML_DB", "alerts.db")
KEY = os.environ.get("OPSGENIE_API_KEY")
JOBS = {}

HTML = r"""
<!doctype html>
<meta charset="utf-8">
<title>alerts-ml</title>
<style>
:root{color-scheme:dark;--bg:#08111f;--card:#101b2d;--card2:#0c1626;--line:#26364d;--text:#e8eef8;--muted:#91a0b8;--blue:#60a5fa;--green:#22c55e}*{box-sizing:border-box}body{font-family:system-ui,sans-serif;margin:0;padding:28px;background:radial-gradient(circle at top left,#18345f,#08111f 520px);color:var(--text)}h1{margin:0 0 6px;font-size:34px;letter-spacing:-.04em}input,button,select{font:inherit}input,select{display:block;margin-top:6px;padding:10px;background:#07101f;color:var(--text);border:1px solid #30435f;border-radius:10px;color-scheme:dark}button{cursor:pointer;margin:4px;padding:10px 13px;background:#172947;color:var(--text);border:1px solid #2f4f7e;border-radius:10px;font-weight:700}button:hover{border-color:var(--blue);background:#20375d}table{border-collapse:separate;border-spacing:0;width:100%;margin-top:12px;min-width:900px}td,th{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:top}th{position:sticky;top:0;background:#0d1a2c;color:#bfdbfe;z-index:1}tr:hover td{background:#0d1829}.tabs{display:flex;gap:8px;margin-top:16px}.tabs button{background:#0c1626;border-color:var(--line)}.tabs button.active{background:#123d2a;border-color:var(--green);color:#dcfce7}pre{white-space:pre-wrap;background:#050b14;padding:12px;border-radius:12px;overflow:auto;border:1px solid var(--line)}.muted{color:var(--muted)}.pill{display:inline-flex;padding:3px 8px;border-radius:999px;background:#334155;font-size:12px;font-weight:800}.noise{background:#7f1d1d}.useful{background:#14532d}.unknown{background:#374151}.row{display:flex;gap:12px;align-items:end;flex-wrap:wrap}.card{background:linear-gradient(180deg,var(--card),var(--card2));border:1px solid var(--line);border-radius:18px;padding:16px;margin:14px 0;box-shadow:0 18px 50px #0006}#status,#mlstatus{margin:10px 0}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:16px;background:#07101f}.empty{text-align:center;padding:36px;color:var(--muted)}a{color:#93c5fd}@media(max-width:800px){body{padding:16px}.card{border-radius:14px}input{width:100%}}
/* spinner for job status */
.spinner{display:inline-block;width:12px;height:12px;border:2px solid #93c5fd;border-top-color:transparent;border-radius:50%;animation:spin .8s linear infinite;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
<h1>alerts-ml</h1>
<div class="muted">Prioritize useful alerts, find noisy templates, generate explainable rules.</div>
<div class="card row">
  <label>From<br><input id="from" type="date" title="Start date (inclusive)"><button type="button" onclick="pick('from')" title="Open date picker">Pick</button></label>
  <label>To<br><input id="to" type="date" title="End date (inclusive)"><button type="button" onclick="pick('to')" title="Open date picker">Pick</button></label>
  <label>Rules<br><input id="rules" value="out_3d/rules.json" size="28" title="Path to rules.json used for scoring"></label>
  <label>Workers<br><input id="workers" type="number" value="4" min="1" max="16" style="width:70px" title="Parallel workers for fetching activity (logs/notes)"></label>
  <label>ML<br><input id="useML" type="checkbox" onchange="updateMLBanner()" title="Enable experimental ML (Laya) for leftover alerts; shadow mode recommended"></label>
  <label>Threshold<br><input id="mlThreshold" type="number" step="0.05" value="0.5" style="width:80px" oninput="updateMLBanner()" title="ML threshold for useful (higher = stricter)"></label>
  <button onclick="fetchRange(false)" title="Fetch activity only for alerts missing it">Fetch missing activity</button>
  <button onclick="fetchRange(true)" title="Refetch activity for all alerts in range">Refresh activity</button>
  <button onclick="loadAlerts()" title="Load alerts table for the selected date range">Load table</button>
</div>
<div class="card row">
  <label>Test days<br><input id="testDays" type="number" value="1" min="0" style="width:80px" title="Hold out the last N days to test rules"></label>
  <label>Min support<br><input id="minSupport" type="number" value="5" min="1" style="width:80px" title="Minimum number of alerts for a rule to be proposed"></label>
  <button onclick="runAnalysis()" title="Analyze this date range and generate rules">Run analysis for range</button>
  <button onclick="loadAnalyses()" title="Reload latest analyses list">Refresh analyses</button>
</div>
<div id="status" class="muted"></div>
<div id="mlstatus" class="muted"></div>
<div class="tabs">
  <button id="tabPrio" class="active" onclick="tab='prio';page=1;render()" title="Show prioritized alerts">Prio</button>
  <button id="tabNoise" onclick="tab='noise';page=1;render()" title="Show alerts classified as noise">Noise</button>
  <button id="tabInsights" onclick="tab='insights';loadInsights()" title="Show grouped insights and recommendations">Insights</button>
  <button id="tabML" onclick="tab='ml';loadCurrentRules()" title="Show analyses, rules and reports">ML</button>
  <button id="tabAdmin" onclick="tab='admin';render()" title="Admin actions">Admin</button>
</div>
<div id="main"></div>
<script>
let rows=[], insights=[], analyses=[], reviews=[], report='', rulesObj=null, settings={}, tab='prio', page=1, pageSize=50, insightsFilter='', insightsSort={key:null, dir:1};
const now=new Date(), from=new Date(now.getTime()-3*864e5);
document.getElementById('from').value=from.toISOString().slice(0,10);
document.getElementById('to').value=now.toISOString().slice(0,10);
function q(){return {from:dt('from'),to:dt('to'),rules:val('rules'),laya:document.getElementById('useML').checked,laya_threshold:parseFloat(val('mlThreshold')||'0.5')}}
function val(id){return document.getElementById(id).value}
function dt(id){let v=val(id); if(!v) return ''; let d=new Date(v+'T00:00:00'); if(id==='to') d.setDate(d.getDate()+1); return d.toISOString()}
function pick(id){let el=document.getElementById(id); if(el.showPicker) el.showPicker(); else el.focus()}
function msg(s){document.getElementById('status').innerHTML=s?`<span class="pill">${esc(s)}</span>`:''}
async function api(path, opts){let r=await fetch(path,opts); let j=await r.json(); if(!r.ok) throw Error(j.error||r.statusText); return j}
function showJob(status,message){
  const icon = status==='running' ? '<span class="spinner"></span>' : status==='done' ? '<span class="pill" style="background:#14532d">DONE</span>' : status==='failed' ? '<span class="pill" style="background:#7f1d1d">FAILED</span>' : '';
  document.getElementById('status').innerHTML = `${icon} ${esc(message||'')}`;
}
async function fetchRange(refresh){let body={...q(),workers:+val('workers'),refresh_activity:refresh}; let j=await api('/api/fetch',{method:'POST',body:JSON.stringify(body)}); showJob('running','job '+j.job+' started'); poll(j.job)}
async function runAnalysis(){let body={...q(),test_days:+val('testDays'),min_support:+val('minSupport')}; let j=await api('/api/analyze',{method:'POST',body:JSON.stringify(body)}); showJob('running','analysis job '+j.job+' started'); poll(j.job)}
async function poll(id){let j=await api('/api/jobs/'+id); showJob(j.status, (j.status||'')+(j.message?(' - '+j.message):'')); if(j.status==='running') setTimeout(()=>poll(id),1500); else {loadAlerts();loadAnalyses();}}
async function loadAlerts(){let p=new URLSearchParams(q()); let j=await api('/api/alerts?'+p); rows=j.alerts; page=1; msg(`${rows.length} alerts loaded`); render()}
async function loadInsights(){let p=new URLSearchParams(q()); let j=await api('/api/insights?'+p); insights=j.insights; render()}
async function loadAnalyses(){analyses=(await api('/api/analyses')).analyses; render()}
async function loadReport(id){let j=await api('/api/analyses/'+id); report=j.report; rulesObj=j.rules; if(j.rules_path) document.getElementById('rules').value=j.rules_path; tab='ml'; render()}
async function loadCurrentRules(){let p=new URLSearchParams({path:val('rules')}); try{let j=await api('/api/rules?'+p); rulesObj=j.rules; report=report||''}catch(e){rulesObj=null; report=e.message} render()}
async function loadSettings(){settings=(await api('/api/admin/settings')).settings; if(tab==='admin') render()}
async function loadReviews(){reviews=(await api('/api/tpl-reviews')).reviews; if(tab==='admin') render()}
function esc(s){return String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function setPage(n,total){page=Math.max(1,Math.min(n,total));render()}
function render(){for (let t of ['Prio','Noise','Insights','Admin']) document.getElementById('tab'+t).classList.toggle('active',tab===t.toLowerCase()); document.getElementById('tabML').classList.toggle('active',tab==='ml'); if(tab==='ml') return renderML(); if(tab==='admin') return renderAdmin(); if(tab==='insights') return renderInsights(); let data=rows.filter(r=>tab==='noise'?r.decision==='noise':r.decision!=='noise'&&(r.priority==='P1'||r.priority==='P2'||r.decision==='useful'||r.decision==='unknown')); let pages=Math.max(1,Math.ceil(data.length/pageSize)); page=Math.min(page,pages); let shown=data.slice((page-1)*pageSize,page*pageSize); let pager=`<div class="row"><button onclick="setPage(1,${pages})">First</button><button onclick="setPage(page-1,${pages})">Prev</button><span class="muted">Page ${page}/${pages} - ${data.length} alerts</span><button onclick="setPage(page+1,${pages})">Next</button><button onclick="setPage(${pages},${pages})">Last</button><label>Per page <select onchange="pageSize=+this.value;page=1;render()"><option ${pageSize===25?'selected':''}>25</option><option ${pageSize===50?'selected':''}>50</option><option ${pageSize===100?'selected':''}>100</option><option ${pageSize===200?'selected':''}>200</option></select></label></div>`; document.getElementById('main').innerHTML=`${pager}<div class="tablewrap"><table><tr><th>Created</th><th>Prio</th><th>Decision</th><th>Rule</th><th>Message</th><th>Activity</th></tr>${shown.map(r=>`<tr><td>${esc(r.created_at)}</td><td><span class="pill">${esc(r.priority)}</span></td><td><span class="pill ${esc(r.decision)}">${esc(r.decision)}</span></td><td>${esc(r.by_rule)}<br><span class="muted">${esc(r.reason)}</span></td><td>${esc(r.message)}<br><span class="muted">${esc(r.template)}</span></td><td>${r.activity_loaded?'loaded':'missing'}<details><summary>json</summary><pre>${esc(JSON.stringify(r.raw,null,2))}</pre></details></td></tr>`).join('')||`<tr><td colspan="6" class="empty">No alerts for this tab/date range.</td></tr>`}</table></div>${pager}`}
function pct(x){return `${Math.round((x||0)*100)}%`}
 function updateMLBanner(){
   const el=document.getElementById('mlstatus');
   const on=document.getElementById('useML').checked;
   if(on){
     const thr=parseFloat(document.getElementById('mlThreshold').value||'0.5');
     // ponytail: simple visual warning banner for ML shadow mode
     el.innerHTML = `<span class="pill" style="background:#f59e0b;color:#111827">ML</span> Experimental zero-shot (no fine-tune). Shadow mode only. Threshold ${isFinite(thr)?thr.toFixed(2):'0.50'}.`;
   } else {
     el.textContent='';
   }
 }
 function setInsightsSort(key){
   if(insightsSort.key===key){ insightsSort.dir = -insightsSort.dir; } else { insightsSort.key=key; insightsSort.dir=1; }
   render();
 }
 function renderInsights(){
   // simple client-side filter by text across template, integration, recommendation, reason
   const f=(insightsFilter||'').toLowerCase();
   let list = f ? insights.filter(x=>[
     x.template||'', x.integration_name||'', x.recommendation||'', x.reason||''
   ].some(v=>String(v).toLowerCase().includes(f))) : insights;
   // sort if requested
   if(insightsSort.key){
     const rank = {"REMOVE CANDIDATE":0, "THRESHOLD REVIEW":1, "FLAPPING":2, "INVESTIGATE":3, "RECURRING USEFUL":4, "WATCH":5};
     const key=insightsSort.key, dir=insightsSort.dir;
     const val=(x)=>{
       switch(key){
         case 'rec': return rank[x.recommendation] ?? 999;
         case 'n': return +x.n;
         case 'noise': return +x.noise_rate;
         case 'useful': return +x.useful_rate;
         case 'amb': return +x.ambiguous_rate;
         case 'notes': return +x.notes_rate;
         case 'auto': return +x.autoclose_rate;
         case 'maxh': return +x.max_per_hour;
         case 'tpl': return String(x.template||'').toLowerCase();
         case 'integ': return String(x.integration_name||'').toLowerCase();
         default: return 0;
       }
     };
     list = list.slice().sort((a,b)=>{
       const va=val(a), vb=val(b);
       if(typeof va==='number' && typeof vb==='number') return dir*(va-vb);
       return dir*String(va).localeCompare(String(vb));
     });
   }
   const filterUI = `<div class=\"row\"><label>Filter<br><input id=\"insightsFilter\" value=\"${esc(insightsFilter)}\" oninput=\"insightsFilter=this.value;render()\" placeholder=\"search template/integration/recommendation\"></label></div>`;
   const th=(label,key)=>`<th><button onclick=\"setInsightsSort('${key}')\" style=\"background:#1f2937;border-color:#374151\">${label}</button></th>`;
   document.getElementById('main').innerHTML=`${filterUI}<div class="tablewrap"><table><tr>${th('Recommendation','rec')}${th('N','n')}${th('Noise','noise')}${th('Useful','useful')}${th('Ambiguous','amb')}${th('Notes','notes')}${th('Auto-close','auto')}${th('Max/hour','maxh')}${th('Template','tpl')}${th('Integration','integ')}</tr>${list.map(x=>`<tr><td><span class=\\\"pill\\\">${esc(x.recommendation)}</span><br><span class=\\\"muted\\\">${esc(x.reason)}</span></td><td>${x.n}</td><td>${pct(x.noise_rate)}</td><td>${pct(x.useful_rate)}</td><td>${pct(x.ambiguous_rate)}</td><td>${pct(x.notes_rate)}</td><td>${pct(x.autoclose_rate)}</td><td>${x.max_per_hour}</td><td>${esc(x.template)}</td><td>${esc(x.integration_name)}</td></tr>`).join('')||`<tr><td colspan="10" class="empty">No insights yet. Load alerts/activity first.</td></tr>`}</table></div>`
 }
function cond(c){let v=Array.isArray(c.value)?c.value.join(', '):c.value; return c.feature==='tag' ? `tag ${c.op} ${v}` : `${c.feature} ${c.op} ${v}`}
function ruleRows(){let all=[...(rulesObj?.guards||[]).map(r=>({...r,origin:'guard',precision:1,support:''})), ...(rulesObj?.rules||[])]; return all.map(r=>`<tr><td>${esc(r.id)}</td><td><span class="pill ${esc(r.label)}">${esc(r.label)}</span></td><td>${esc(r.origin||'')}</td><td>${esc(r.precision??'')}</td><td>${esc(r.support??'')}</td><td>${esc(r.test_precision??'')}</td><td>${esc(r.test_support??'')}</td><td>${esc(r.test_missed_useful??'')}</td><td>${esc(r.description||'')}<br><span class="muted">${esc((r.when||[]).map(cond).join(' AND '))}</span></td></tr>`).join('')}
function renderML(){document.getElementById('main').innerHTML=`<div class="card"><h2>Analyses</h2>${analyses.map(a=>`<p><button onclick="loadReport(${a.id})">open</button> #${a.id} ${esc(a.created_at)} ${esc(a.from_ts)} -> ${esc(a.to_ts)} <span class="pill">${esc(a.status)}</span><br><span class="muted">${esc(a.summary||'')}</span></p>`).join('')||'<p class="muted">No analysis yet</p>'}</div><div class="card"><h2>Rules</h2><table><tr><th>ID</th><th>Label</th><th>Origin</th><th>Precision</th><th>Support</th><th>Test precision</th><th>Test support</th><th>Missed useful</th><th>Conditions</th></tr>${ruleRows()}</table></div><div class="card"><h2>Report</h2><pre>${esc(report)}</pre></div><div class="card"><h2>Rules JSON</h2><pre>${esc(rulesObj?JSON.stringify(rulesObj,null,2):'')}</pre></div>`}
async function clearDb(){let ok=prompt('Type DELETE to empty alerts.db (alerts, activity, scores, analyses). This cannot be undone.'); if(ok!=='DELETE') return msg('database clear cancelled'); let j=await api('/api/admin/clear-db',{method:'POST',body:JSON.stringify({confirm:'DELETE'})}); rows=[]; insights=[]; analyses=[]; report=''; rulesObj=null; msg(j.message); render()}
async function saveSettings(){let body={llm_url:val('llmUrl'),llm_model:val('llmModel')}; let key=val('llmKey'); if(key) body.llm_key=key; let j=await api('/api/admin/settings',{method:'POST',body:JSON.stringify(body)}); settings=j.settings; msg('settings saved'); render()}
async function syncTplReviews(){let j=await api('/api/tpl-reviews/sync',{method:'POST',body:JSON.stringify(q())}); showJob('running','TPL review sync '+j.job+' started'); poll(j.job)}
function reviewRows(){return reviews.map(r=>`<tr><td>${esc(r.generated_at)}</td><td>${r.n}</td><td>${esc(r.label||'')}</td><td>${esc(r.confidence??'')}</td><td>${esc(r.reason||'')}</td><td>${esc(r.template)}</td></tr>`).join('')}
function renderAdmin(){document.getElementById('main').innerHTML=`<div class="card"><h2>LLM settings</h2><div class="row"><label>URL<br><input id="llmUrl" size="52" value="${esc(settings.llm_url||'')}" placeholder="https://.../v1/chat/completions"></label><label>Model<br><input id="llmModel" size="24" value="${esc(settings.llm_model||'')}" placeholder="model name"></label><label>API key<br><input id="llmKey" type="password" size="32" placeholder="${settings.has_llm_key?'saved - leave blank to keep':''}"></label><button onclick="saveSettings()">Save LLM settings</button><button onclick="syncTplReviews()">Sync TPL with model</button></div><p class="muted">API key is stored in the local SQLite DB and is not shown again. Sync uses the selected date range.</p></div><div class="card"><h2>TPL reviews</h2><button onclick="loadReviews()">Refresh reviews</button><div class="tablewrap"><table><tr><th>Generated</th><th>N</th><th>LLM label</th><th>Confidence</th><th>Reason</th><th>Template</th></tr>${reviewRows()||'<tr><td colspan="6" class="empty">No TPL reviews yet.</td></tr>'}</table></div></div><div class="card"><h2>Admin</h2><p class="muted">Danger zone. Empty the local SQLite database only; generated files are left untouched.</p><button onclick="clearDb()" style="background:#7f1d1d;border-color:#ef4444">Empty database</button></div>`}
loadAlerts(); loadAnalyses(); loadSettings(); loadReviews(); updateMLBanner();
</script>
"""

def now_iso(): return datetime.now(timezone.utc).isoformat()
def dumps(x): return json.dumps(x, separators=(",", ":"), ensure_ascii=False)
def dt_ms(s): return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.executescript("""
    create table if not exists alerts(id text primary key, created_at text, updated_at text, priority text, status text, source text, integration_name text, message text, raw_json text not null, fetched_at text not null);
    create table if not exists activity(alert_id text primary key, logs_json text, notes_json text, fetched_at text, fetch_error text);
    create table if not exists scores(alert_id text, rules_hash text, decision text, by_rule text, confidence real, reason text, template text, scored_at text, primary key(alert_id, rules_hash));
    create table if not exists analyses(id integer primary key autoincrement, created_at text, from_ts text, to_ts text, out_dir text, status text, summary text, stdout text, stderr text);
    create table if not exists settings(key text primary key, value text not null);
    create table if not exists tpl_reviews(template text primary key, generated_at text, n integer, payload_json text not null, llm_json text, status text);
    """)
    return c

def get_settings(conn):
    vals = {r["key"]: r["value"] for r in conn.execute("select key,value from settings")}
    return {"llm_url": vals.get("llm_url", ""), "llm_model": vals.get("llm_model", ""), "has_llm_key": bool(vals.get("llm_key"))}

def save_settings(vals):
    conn = db()
    for key in ("llm_url", "llm_model", "llm_key"):
        if key in vals:
            conn.execute("replace into settings values(?,?)", (key, str(vals.get(key) or "")))
    conn.commit(); out = get_settings(conn); conn.close(); return out

def upsert_alerts(conn, alerts):
    rows = []
    for a in alerts:
        integ = a.get("integration") or {}
        rows.append((a.get("id"), a.get("createdAt"), a.get("updatedAt"), a.get("priority"), a.get("status"), a.get("source"), integ.get("name"), a.get("message"), dumps(a), now_iso()))
    conn.executemany("replace into alerts values(?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()

def fetch_range(job, start, end, workers, refresh_activity):
    if not KEY: raise RuntimeError("OPSGENIE_API_KEY is not set")
    conn = db(); alerts = []; cur = datetime.fromisoformat(start.replace("Z", "+00:00")); stop = datetime.fromisoformat(end.replace("Z", "+00:00"))
    while cur < stop:
        nxt = min(cur + timedelta(days=1), stop)
        batch = collect_alerts(int(cur.timestamp() * 1000), int(nxt.timestamp() * 1000), KEY)
        alerts.extend(batch); upsert_alerts(conn, batch)
        JOBS[job]["message"] = f"alerts {len(alerts)}"
        cur = nxt
    ids = [a.get("id") for a in alerts if a.get("id")]
    if not refresh_activity:
        have = {r[0] for r in conn.execute("select alert_id from activity where alert_id in (%s) and fetched_at is not null" % ",".join("?" * len(ids)), ids)} if ids else set()
        ids = [i for i in ids if i not in have]
    done = 0
    def one(aid):
        try:
            act = fetch_activity(aid, KEY)
            with db() as c:
                c.execute("replace into activity values(?,?,?,?,?)", (aid, dumps(act.get("logs") or []), dumps(act.get("notes") or []), now_iso(), None))
        except Exception as e:
            with db() as c:
                c.execute("replace into activity values(?,?,?,?,?)", (aid, "[]", "[]", None, str(e)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for _ in ex.map(one, ids):
            done += 1; JOBS[job]["message"] = f"alerts {len(alerts)}, activity {done}/{len(ids)}"
    return f"fetched {len(alerts)} alerts, {len(ids)} activity records"

def load_rules(path):
    with open(path, encoding="utf-8") as f: raw = f.read()
    return json.loads(raw), hashlib.sha256(raw.encode()).hexdigest()[:16]

def score_rows(conn, rows, rules_path, laya_fn=None):
    try: rules, rh = load_rules(rules_path)
    except FileNotFoundError: rules, rh = ({"guards": [], "rules": []}, "none")
    hist = History(); out = []
    for r in rows:
        a = normalize(json.loads(r["raw_json"]))
        # Build activity object if present; used for heuristic noise detection
        act = {"logs": json.loads(r["logs_json"] or "[]"), "notes": json.loads(r["notes_json"] or "[]")}
        f = features(a, hist)
        d = decide(f, rules, laya_fn)
        # ponytail: minimal heuristic fallback – if no rule matched, tag 'noise' when label() says so
        if d["decision"] == "unknown":
            lab = label(a, act, 20, 10)
            if lab == "noise":
                d = {"decision": "noise", "by": "heuristic", "confidence": 0.6, "reason": "auto-close/flap heuristic"}
        conn.execute("replace into scores values(?,?,?,?,?,?,?,?)", (a.get("id"), rh, d["decision"], d["by"], d["confidence"], d["reason"], f.get("template"), now_iso()))
        out.append({"id": a.get("id"), "created_at": r["created_at"], "priority": r["priority"], "message": r["message"], "decision": d["decision"], "by_rule": d["by"], "confidence": d["confidence"], "reason": d["reason"], "template": f.get("template"), "activity_loaded": bool(r["activity_at"]), "raw": a})
    conn.commit(); return out

def recommendation(n, noise_rate, useful_rate, amb_rate, notes_rate, autoclose_rate, max_hour):
    if n >= 10 and noise_rate >= 0.8 and notes_rate < 0.1:
        return "REMOVE CANDIDATE", "high volume, mostly noise, almost no notes"
    if n >= 10 and autoclose_rate >= 0.7 and useful_rate < 0.2:
        return "THRESHOLD REVIEW", "mostly auto-closes; threshold may be too sensitive"
    if n >= 10 and amb_rate >= 0.7:
        return "INVESTIGATE", "high volume but mostly ambiguous outcomes"
    if n >= 10 and useful_rate >= 0.7:
        return "RECURRING USEFUL", "often actionable; fix root cause rather than suppress"
    if max_hour >= 5:
        return "FLAPPING", "many occurrences in the same hour"
    return "WATCH", "not enough signal yet"

def insights_rows(conn, start, end):
    rows = conn.execute("""
        select a.*, activity.logs_json, activity.notes_json
        from alerts a left join activity on activity.alert_id=a.id
        where a.created_at >= ? and a.created_at < ?
        order by a.created_at
    """, (start, end)).fetchall()
    hist = History(); groups = defaultdict(lambda: {"n": 0, "labels": defaultdict(int), "notes": 0, "autoclose": 0, "hours": defaultdict(int), "integration": None})
    for r in rows:
        a = normalize(json.loads(r["raw_json"])); f = features(a, hist)
        act = {"logs": json.loads(r["logs_json"] or "[]"), "notes": json.loads(r["notes_json"] or "[]")}
        lab = label(a, act, 20, 10)
        g = groups[f["template"]]
        g["n"] += 1; g["labels"][lab] += 1; g["integration"] = f.get("integration_name")
        if act["notes"]: g["notes"] += 1
        if lab == "noise" and not (a.get("acknowledged") or "ackTime" in (a.get("report") or {})): g["autoclose"] += 1
        ts = parse_ts(a.get("createdAt"))
        if ts: g["hours"][ts.strftime("%Y-%m-%dT%H")] += 1
    out = []
    for tpl, g in groups.items():
        n = g["n"]
        if n < 3: continue
        nr, ur, ar = g["labels"]["noise"] / n, g["labels"]["useful"] / n, g["labels"]["ambiguous"] / n
        notes_rate, autoclose_rate = g["notes"] / n, g["autoclose"] / n
        max_hour = max(g["hours"].values() or [0])
        rec, reason = recommendation(n, nr, ur, ar, notes_rate, autoclose_rate, max_hour)
        out.append({"template": tpl, "integration_name": g["integration"], "n": n, "noise_rate": nr, "useful_rate": ur, "ambiguous_rate": ar, "notes_rate": notes_rate, "autoclose_rate": autoclose_rate, "max_per_hour": max_hour, "recommendation": rec, "reason": reason})
    rank = {"REMOVE CANDIDATE": 0, "THRESHOLD REVIEW": 1, "FLAPPING": 2, "INVESTIGATE": 3, "RECURRING USEFUL": 4, "WATCH": 5}
    return sorted(out, key=lambda x: (rank[x["recommendation"]], -x["n"]))[:200]

def tpl_review_payloads(conn, start, end, limit=30):
    rows = conn.execute("""
        select a.*, activity.logs_json, activity.notes_json
        from alerts a left join activity on activity.alert_id=a.id
        where a.created_at >= ? and a.created_at < ?
        order by a.created_at
    """, (start, end)).fetchall()
    hist = History(); by_tpl = defaultdict(lambda: {"n": 0, "labels": defaultdict(int), "priorities": defaultdict(int), "integrations": set(), "examples": []})
    for r in rows:
        a = normalize(json.loads(r["raw_json"])); f = features(a, hist)
        act = {"logs": json.loads(r["logs_json"] or "[]"), "notes": json.loads(r["notes_json"] or "[]")}
        g = by_tpl[f["template"]]
        g["n"] += 1; g["labels"][label(a, act, 20, 10)] += 1; g["priorities"][a.get("priority") or "P3"] += 1
        if f.get("integration_name"): g["integrations"].add(f["integration_name"])
        if len(g["examples"]) < 3: g["examples"].append(a.get("message") or "")
    families = []
    for _, _, pattern, vals in template_family_candidates(by_tpl.keys()):
        items = [by_tpl[v] for v in vals]
        n = sum(x["n"] for x in items)
        if n < 3: continue
        labels, priorities, integrations, examples = defaultdict(int), defaultdict(int), set(), []
        for x in items:
            for k, v in x["labels"].items(): labels[k] += v
            for k, v in x["priorities"].items(): priorities[k] += v
            integrations |= x["integrations"]; examples += x["examples"][:1]
        families.append({"template": pattern, "n": n, "labels": dict(labels), "priorities": dict(priorities), "integrations": sorted(integrations)[:5], "examples": examples[:3]})
    seen = {x["template"] for x in families}
    singles = [{"template": tpl, "n": g["n"], "labels": dict(g["labels"]), "priorities": dict(g["priorities"]), "integrations": sorted(g["integrations"])[:5], "examples": g["examples"]} for tpl, g in by_tpl.items() if tpl not in seen and g["n"] >= 3]
    return sorted(families + singles, key=lambda x: -x["n"])[:limit]

def call_llm(settings, payload):
    vals = {r["key"]: r["value"] for r in settings.execute("select key,value from settings")}
    url, model, key = vals.get("llm_url"), vals.get("llm_model"), vals.get("llm_key")
    if not url or not model: raise RuntimeError("LLM URL/model missing in Admin settings")
    prompt = "Classify this alert template family as useful, noise, threshold_review, investigate, or unknown. Return strict JSON with label, confidence, reason.\n" + json.dumps(payload, ensure_ascii=False)
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0}).encode()
    headers = {"content-type": "application/json"}
    if key: headers["authorization"] = "Bearer " + key
    req = request.Request(url, data=body, headers=headers, method="POST")
    with request.urlopen(req, timeout=60) as res:
        data = json.loads(res.read().decode())
    content = data.get("choices", [{}])[0].get("message", {}).get("content", json.dumps(data))
    try: return json.loads(content)
    except json.JSONDecodeError: return {"label": "unknown", "confidence": 0, "reason": content[:500]}

def sync_tpl_reviews(job, start, end):
    conn = db(); payloads = tpl_review_payloads(conn, start, end)
    for i, payload in enumerate(payloads, 1):
        JOBS[job]["message"] = f"LLM review {i}/{len(payloads)}"
        llm = call_llm(conn, payload)
        conn.execute("replace into tpl_reviews values(?,?,?,?,?,?)", (payload["template"], now_iso(), payload["n"], dumps(payload), dumps(llm), "pending"))
        conn.commit()
    conn.close(); return f"synced {len(payloads)} template reviews"

def write_range_files(conn, start, end, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rows = conn.execute("select * from alerts where created_at >= ? and created_at < ? order by created_at", (start, end)).fetchall()
    with gzip.open(os.path.join(out_dir, "alerts.jsonl.gz"), "wt", encoding="utf-8") as f:
        for r in rows: f.write(r["raw_json"] + "\n")
    with open(os.path.join(out_dir, "activity.jsonl"), "w", encoding="utf-8") as f:
        for r in conn.execute("select * from activity where alert_id in (select id from alerts where created_at >= ? and created_at < ?)", (start, end)):
            f.write(dumps({"id": r["alert_id"], "logs": json.loads(r["logs_json"] or "[]"), "notes": json.loads(r["notes_json"] or "[]")}) + "\n")

def analyze_range(job, start, end, test_days, min_support):
    conn = db(); out_dir = os.path.join("out_web", str(uuid.uuid4())[:8]); data_dir = os.path.join(out_dir, "data")
    write_range_files(conn, start, end, data_dir)
    conn.execute("insert into analyses(created_at,from_ts,to_ts,out_dir,status) values(?,?,?,?,?)", (now_iso(), start, end, out_dir, "running")); aid = conn.execute("select last_insert_rowid()").fetchone()[0]; conn.commit()
    cmd = ["python", "analyze.py", "--data", data_dir, "--out", out_dir, "--test-days", str(test_days), "--min-support", str(min_support)]
    p = subprocess.run(cmd, text=True, capture_output=True)
    status = "done" if p.returncode == 0 else "failed"
    conn.execute("update analyses set status=?, summary=?, stdout=?, stderr=? where id=?", (status, (p.stdout + p.stderr).strip().split("\n")[-1], p.stdout, p.stderr, aid)); conn.commit()
    if p.returncode: raise RuntimeError(p.stderr or p.stdout)
    return f"analysis #{aid} wrote {out_dir}"

def clear_db():
    conn = db()
    for table in ("scores", "activity", "alerts", "analyses"):
        conn.execute(f"delete from {table}")
    conn.commit()
    conn.close()

def start_job(fn, *args):
    jid = str(uuid.uuid4())[:8]; JOBS[jid] = {"status": "running", "message": ""}
    def run():
        try: JOBS[jid].update(status="done", message=fn(jid, *args))
        except Exception as e: JOBS[jid].update(status="failed", message=str(e))
    threading.Thread(target=run, daemon=True).start(); return jid

class Handler(BaseHTTPRequestHandler):
    def send(self, obj, code=200):
        b = json.dumps(obj, ensure_ascii=False).encode(); self.send_response(code); self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def body(self): return json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
    def do_GET(self):
        u = parse.urlparse(self.path); qs = parse.parse_qs(u.query)
        try:
            if u.path == "/":
                b = HTML.encode(); self.send_response(200); self.send_header("content-type", "text/html; charset=utf-8"); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b); return
            if u.path == "/api/alerts":
                start, end, rules = qs["from"][0], qs["to"][0], qs.get("rules", ["out/rules.json"])[0]
                # include activity logs/notes to allow heuristic noise detection when no rule matches
                conn = db(); rows = conn.execute("select a.*, activity.fetched_at activity_at, activity.logs_json, activity.notes_json from alerts a left join activity on activity.alert_id=a.id where created_at >= ? and created_at < ? order by created_at", (start, end)).fetchall()
                laya = None
                if qs.get("laya", ["false"])[0].lower() in ("1","true","yes"):
                    try:
                        thr = float(qs.get("laya_threshold", ["0.5"])[0])
                    except ValueError:
                        thr = 0.5
                    laya = make_laya(None, thr)
                return self.send({"alerts": score_rows(conn, rows, rules, laya)})
            if u.path == "/api/insights":
                return self.send({"insights": insights_rows(db(), qs["from"][0], qs["to"][0])})
            if u.path == "/api/rules":
                path = qs.get("path", ["out/rules.json"])[0]
                with open(path, encoding="utf-8") as f: rules = json.load(f)
                return self.send({"rules": rules, "rules_path": path})
            if u.path == "/api/admin/settings":
                conn = db(); out = get_settings(conn); conn.close(); return self.send({"settings": out})
            if u.path == "/api/tpl-reviews":
                conn = db(); rows = []
                for r in conn.execute("select * from tpl_reviews order by generated_at desc, n desc limit 200"):
                    llm = json.loads(r["llm_json"] or "{}")
                    rows.append({"template": r["template"], "generated_at": r["generated_at"], "n": r["n"], "status": r["status"], "label": llm.get("label"), "confidence": llm.get("confidence"), "reason": llm.get("reason")})
                conn.close(); return self.send({"reviews": rows})
            if u.path == "/api/analyses":
                rows = [dict(r) for r in db().execute("select id,created_at,from_ts,to_ts,out_dir,status,summary from analyses order by id desc limit 20")]
                return self.send({"analyses": rows})
            if u.path.startswith("/api/analyses/"):
                aid = int(u.path.rsplit("/", 1)[1]); r = db().execute("select * from analyses where id=?", (aid,)).fetchone()
                if not r: return self.send({"error": "not found"}, 404)
                report = open(os.path.join(r["out_dir"], "report.md"), encoding="utf-8").read() if r["status"] == "done" else (r["stderr"] or r["stdout"] or "")
                rules_path = os.path.join(r["out_dir"], "rules.json"); rules = json.load(open(rules_path, encoding="utf-8")) if os.path.exists(rules_path) else None
                return self.send({"analysis": dict(r), "report": report, "rules": rules, "rules_path": rules_path})
            if u.path.startswith("/api/jobs/"): return self.send(JOBS.get(u.path.rsplit("/", 1)[1], {"status": "missing"}))
            self.send({"error": "not found"}, 404)
        except Exception as e: self.send({"error": str(e)}, 500)
    def do_POST(self):
        try:
            b = self.body()
            if self.path == "/api/fetch":
                jid = start_job(fetch_range, b["from"], b["to"], int(b.get("workers", 4)), bool(b.get("refresh_activity")))
                return self.send({"job": jid})
            if self.path == "/api/analyze":
                jid = start_job(analyze_range, b["from"], b["to"], int(b.get("test_days", 1)), int(b.get("min_support", 5)))
                return self.send({"job": jid})
            if self.path == "/api/admin/clear-db":
                if b.get("confirm") != "DELETE": return self.send({"error": "confirmation required"}, 400)
                clear_db(); return self.send({"message": "database emptied"})
            if self.path == "/api/admin/settings":
                return self.send({"settings": save_settings(b)})
            if self.path == "/api/tpl-reviews/sync":
                jid = start_job(sync_tpl_reviews, b["from"], b["to"])
                return self.send({"job": jid})
            self.send({"error": "not found"}, 404)
        except Exception as e: self.send({"error": str(e)}, 500)

if __name__ == "__main__":
    db().close()
    print("open http://127.0.0.1:8000")
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
