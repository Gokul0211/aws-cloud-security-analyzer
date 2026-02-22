#!/usr/bin/env python3
"""
CloudGuard — Web Dashboard  v2.0
Reads from SQLite (cloudguard.db) for real trend data.
Falls back to scan_*.json files if no DB found.

Usage:
  python dashboard.py                         # default port 5000
  python dashboard.py --port 8080             # custom port
  python dashboard.py --reports-dir ./reports # where JSON files live
  python dashboard.py --db cloudguard.db      # explicit SQLite path
"""

import os
import json
import glob
import sqlite3
import argparse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Optional

# ── Config ──────────────────────────────────────────────
REPORTS_DIR = "reports"
DB_PATH     = "cloudguard.db"


# ══════════════════════════════════════════════════════════
#  DATA LAYER (SQLite → JSON fallback)
# ══════════════════════════════════════════════════════════

def db_ok(db_path: str) -> bool:
    return os.path.exists(db_path)


def load_trends_db(db_path: str) -> List[Dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT scan_time, region, account_id,
                   total, critical, high, medium, low,
                   score, attack_paths
            FROM scans ORDER BY scan_time ASC
        """).fetchall()
    return [dict(r) for r in rows]


def load_latest_db(db_path: str) -> Optional[Dict]:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT report_json FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return json.loads(row[0]) if row else None


def load_top_recurring_db(db_path: str) -> List[Dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT check_id, service, severity,
                   COUNT(*) as occurrences, AVG(risk_score) as avg_risk
            FROM findings
            GROUP BY check_id
            ORDER BY occurrences DESC
            LIMIT 10
        """).fetchall()
    return [dict(r) for r in rows]


def load_scans_json(reports_dir: str) -> List[Dict]:
    files = sorted(glob.glob(os.path.join(reports_dir, "scan_*.json")), reverse=True)
    scans = []
    for f in files[:50]:
        try:
            with open(f) as fp:
                data = json.load(fp)
                data["_file"] = os.path.basename(f)
                scans.append(data)
        except Exception:
            pass
    return scans


# ══════════════════════════════════════════════════════════
#  HTML BUILDER
# ══════════════════════════════════════════════════════════

def build_html(latest: Dict, trends: List[Dict], recurring: List[Dict],
               scan_count: int, use_db: bool) -> str:

    s     = latest.get("summary", {})
    sev   = s.get("severity_breakdown", {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0})
    finds = latest.get("findings", [])
    paths = latest.get("attack_paths", [])
    gd    = latest.get("graph_data", {"nodes":[],"links":[]})
    mitre = s.get("top_mitre_techniques", [])

    score_color = ("#22c55e" if s.get("compliance_score",0) >= 80 else
                   "#f97316" if s.get("compliance_score",0) >= 50 else "#dc2626")

    # Trend series
    t_labels = [t["scan_time"][:10] for t in trends]
    t_scores = [t.get("score", t.get("compliance_score", 0)) for t in trends]
    t_crits  = [t.get("critical", 0) for t in trends]

    def badge(sv):
        c = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706","LOW":"#65a30d"}
        return f'<span class="badge" style="background:{c.get(sv,"#6b7280")}">{sv}</span>'

    find_rows = "".join(f"""
    <tr>
      <td>{badge(f["severity"])}</td>
      <td>{f["service"]}</td>
      <td class="mono">{f["resource"][:38]}</td>
      <td>{f["message"]}</td>
      <td class="risk" style="color:{'#dc2626' if f.get('risk_score',0)>=8 else '#ea580c' if f.get('risk_score',0)>=6 else '#64748b'}">{f.get('risk_score','—')}</td>
      <td class="sm gray">{f.get('cis','—')}</td>
      <td class="sm"><span class="mitre-badge">{f.get('mitre','—')}</span> {f.get('mitre_name','')}</td>
      <td class="sm gray">{f.get('remediation','—')}</td>
    </tr>""" for f in finds[:150])

    path_rows = "".join(f"""
    <tr>
      <td class="mono sm">{ap['entry_point']}</td>
      <td class="mono sm">{ap['target']}</td>
      <td style="text-align:center">{ap.get('hop_count','?')}</td>
      <td style="color:#dc2626;font-weight:700;text-align:center">{ap['risk_score']}</td>
      <td class="sm">{('<br>→ '.join(ap.get('steps',[])))}</td>
    </tr>""" for ap in paths[:10])

    recurring_rows = "".join(f"""
    <tr>
      <td class="mono sm">{r['check_id']}</td>
      <td>{r['service']}</td>
      <td>{badge(r['severity'])}</td>
      <td style="text-align:center;font-weight:700">{r['occurrences']}</td>
      <td style="text-align:center;color:#f97316">{round(r.get('avg_risk',0),1)}</td>
    </tr>""" for r in recurring)

    mitre_bars = "".join(f"""
    <div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;margin-bottom:3px">
        <span style="font-size:12px;color:#c7d2fe">{name}</span>
        <span style="font-size:11px;color:#64748b">{cnt}</span>
      </div>
      <div style="background:#0f172a;border-radius:3px;height:5px">
        <div style="background:#6366f1;border-radius:3px;height:5px;width:{min(cnt/max(mitre[0][1],1)*100,100):.0f}%"></div>
      </div>
    </div>""" for name, cnt in mitre) if mitre else "<p class='sm gray'>No data yet.</p>"

    db_badge = ('<span style="background:#166534;color:#86efac;font-size:10px;padding:2px 8px;border-radius:10px;margin-left:8px">SQLite ✓</span>'
                if use_db else
                '<span style="background:#92400e;color:#fcd34d;font-size:10px;padding:2px 8px;border-radius:10px;margin-left:8px">JSON mode</span>')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudGuard Dashboard</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#f1f5f9;min-height:100vh}}
nav{{background:#1e293b;border-bottom:1px solid #334155;padding:0 36px;height:54px;display:flex;align-items:center;gap:20px}}
.logo{{font-size:18px;font-weight:800;color:#38bdf8;display:flex;align-items:center;gap:8px}}
.nav-r{{margin-left:auto;font-size:12px;color:#64748b}}
.wrap{{max-width:1500px;margin:0 auto;padding:26px 36px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}}
.card{{background:#1e293b;border-radius:10px;padding:16px;border:1px solid #334155}}
.card .lbl{{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}}
.card .val{{font-size:30px;font-weight:800}}
.sec{{background:#1e293b;border-radius:10px;padding:20px;margin-bottom:18px;border:1px solid #334155}}
.sec h2{{font-size:15px;font-weight:700;color:#e2e8f0;margin-bottom:14px;display:flex;align-items:center;gap:8px}}
.g2{{display:grid;grid-template-columns:2fr 1fr;gap:18px;margin-bottom:18px}}
.g3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;margin-bottom:18px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{text-align:left;padding:8px 10px;background:#0f172a;color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap}}
td{{padding:8px 10px;border-bottom:1px solid #0f172a;vertical-align:top;color:#cbd5e1}}
tr:hover td{{background:#0f172a50}}
.badge{{padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700;color:#fff}}
.mono{{font-family:monospace;font-size:11px}}
.sm{{font-size:11px}}
.gray{{color:#64748b}}
.risk{{text-align:center;font-weight:700}}
.mitre-badge{{background:#312e81;color:#a5b4fc;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:10px}}
.score-ring{{width:64px;height:64px;border-radius:50%;border:5px solid {score_color};display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:800;color:{score_color};margin:4px auto}}
#chart-trend{{width:100%;height:220px}}
#chart-sev{{width:100%;height:220px}}
#graph-wrap{{width:100%;height:420px;background:#0f172a;border-radius:8px;overflow:hidden}}
.legend{{display:flex;gap:12px;margin-top:8px;flex-wrap:wrap}}
.ldot{{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:3px}}
.legend span{{font-size:11px;color:#64748b;display:flex;align-items:center}}
.fbar{{display:flex;gap:7px;margin-bottom:12px;flex-wrap:wrap}}
.fb{{padding:4px 11px;border-radius:14px;border:1px solid #334155;background:transparent;color:#94a3b8;cursor:pointer;font-size:11px;transition:all .15s}}
.fb.on{{background:#1d4ed8;border-color:#1d4ed8;color:#fff}}
.fb:hover{{border-color:#475569}}
.empty{{text-align:center;padding:40px;color:#334155;font-size:14px}}
</style>
</head>
<body>

<nav>
  <div class="logo">🛡️ CloudGuard {db_badge}</div>
  <div class="nav-r">
    Last scan: {latest.get('scan_time','—')[:19].replace('T',' ')} UTC &nbsp;|&nbsp;
    {scan_count} scan(s) stored &nbsp;|&nbsp;
    Account: {latest.get('account_id','—')} &nbsp;|&nbsp;
    Region: {latest.get('region','—')}
    <button onclick="location.reload()" style="margin-left:12px;background:#334155;border:none;color:#94a3b8;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:11px">↻ Refresh</button>
  </div>
</nav>

<div class="wrap">

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card" style="text-align:center">
      <div class="lbl">Compliance</div>
      <div class="score-ring">{s.get('compliance_score',0)}%</div>
      <div class="sm gray" style="text-align:center">{s.get('checks_passed',0)}/{s.get('checks_total',0)} passed</div>
    </div>
    <div class="card"><div class="lbl">Findings</div><div class="val">{s.get('total_findings',0)}</div></div>
    <div class="card"><div class="lbl">Critical</div><div class="val" style="color:#dc2626">{sev['CRITICAL']}</div></div>
    <div class="card"><div class="lbl">High</div><div class="val" style="color:#ea580c">{sev['HIGH']}</div></div>
    <div class="card"><div class="lbl">Medium</div><div class="val" style="color:#d97706">{sev['MEDIUM']}</div></div>
    <div class="card"><div class="lbl">Low</div><div class="val" style="color:#65a30d">{sev['LOW']}</div></div>
    <div class="card"><div class="lbl">Attack Paths</div><div class="val" style="color:#a855f7">{s.get('attack_paths_found',0)}</div></div>
  </div>

  <!-- Trend + Severity over time -->
  <div class="g2">
    <div class="sec">
      <h2>📈 Compliance Score Trend</h2>
      <svg id="chart-trend"></svg>
    </div>
    <div class="sec">
      <h2>📊 Critical Findings Trend</h2>
      <svg id="chart-sev"></svg>
    </div>
  </div>

  <!-- MITRE + Recurring -->
  <div class="g2">
    <div class="sec">
      <h2>🎯 MITRE ATT&CK Top Techniques</h2>
      {mitre_bars}
    </div>
    <div class="sec">
      <h2>🔁 Recurring Findings</h2>
      {'<table><thead><tr><th>Check</th><th>Service</th><th>Severity</th><th>Occurrences</th><th>Avg Risk</th></tr></thead><tbody>' + recurring_rows + '</tbody></table>' if recurring else '<p class="sm gray">Need 2+ scans for recurring analysis.</p>'}
    </div>
  </div>

  <!-- Attack Graph -->
  <div class="sec">
    <h2>🕸️ Infrastructure Attack Graph <span class="sm gray" style="font-weight:400">— drag nodes to explore</span></h2>
    <div id="graph-wrap"></div>
    <div class="legend">
      <span><span class="ldot" style="background:#f59e0b"></span>S3</span>
      <span><span class="ldot" style="background:#6366f1"></span>IAM Role</span>
      <span><span class="ldot" style="background:#818cf8"></span>IAM User</span>
      <span><span class="ldot" style="background:#10b981"></span>EC2</span>
      <span><span class="ldot" style="background:#3b82f6"></span>RDS</span>
      <span><div style="width:18px;height:2px;background:#ef4444;display:inline-block;margin-right:4px;vertical-align:middle"></div>Attack</span>
      <span><div style="width:18px;height:2px;background:#334155;display:inline-block;margin-right:4px;vertical-align:middle"></div>Trust</span>
      <span><span class="ldot" style="background:transparent;border:2px solid #fbbf24"></span>Sensitive</span>
    </div>
  </div>

  <!-- Attack Paths -->
  {'<div class="sec"><h2>⛓️ Attack Paths (' + str(len(paths)) + ')</h2><table><thead><tr><th>Entry Point</th><th>Target</th><th>Hops</th><th>Risk</th><th>Exploit Chain</th></tr></thead><tbody>' + path_rows + '</tbody></table></div>' if paths else ''}

  <!-- Findings Table -->
  <div class="sec">
    <h2>📋 Findings ({len(finds)} total)</h2>
    <div class="fbar">
      <button class="fb on" onclick="filt(this,'ALL')">All ({len(finds)})</button>
      <button class="fb" onclick="filt(this,'CRITICAL')">🔴 Critical ({sev['CRITICAL']})</button>
      <button class="fb" onclick="filt(this,'HIGH')">🟠 High ({sev['HIGH']})</button>
      <button class="fb" onclick="filt(this,'MEDIUM')">🟡 Medium ({sev['MEDIUM']})</button>
      <button class="fb" onclick="filt(this,'LOW')">🟢 Low ({sev['LOW']})</button>
    </div>
    {'<table><thead><tr><th>Sev</th><th>Svc</th><th>Resource</th><th>Issue</th><th>Risk</th><th>CIS</th><th>MITRE</th><th>Remediation</th></tr></thead><tbody id="ftbody">' + find_rows + '</tbody></table>' if finds else '<div class="empty">✅ No findings! Run a scan to see results.</div>'}
  </div>

  <!-- Scan History -->
  <div class="sec">
    <h2>📂 Scan History ({scan_count} scans)</h2>
    {'<table><thead><tr><th>Time (UTC)</th><th>Account</th><th>Region</th><th>Total</th><th>Critical</th><th>High</th><th>Score</th><th>Paths</th></tr></thead><tbody>' + "".join(f"""
    <tr>
      <td class="mono sm">{t.get('scan_time','')[:19].replace('T',' ')}</td>
      <td class="sm gray">{t.get('account_id','—')}</td>
      <td class="sm gray">{t.get('region','—')}</td>
      <td>{t.get('total',0)}</td>
      <td style="color:#dc2626;font-weight:700">{t.get('critical',0)}</td>
      <td style="color:#ea580c">{t.get('high',0)}</td>
      <td style="color:#22c55e;font-weight:700">{t.get('score',0)}%</td>
      <td style="color:#a855f7">{t.get('attack_paths',0)}</td>
    </tr>""" for t in reversed(trends[-30:])) + '</tbody></table>' if trends else '<div class="empty">No scans yet. Run python scanner.py</div>'}
  </div>

</div>

<script>
// ── Data ──────────────────────────────────────────────
const tLabels = {json.dumps(t_labels)};
const tScores = {json.dumps(t_scores)};
const tCrits  = {json.dumps(t_crits)};
const gd      = {json.dumps(gd)};

// ── Trend Chart ──────────────────────────────────────
function drawLineChart(svgId, labels, data, color, label) {{
  const el = document.getElementById(svgId);
  if (!el) return;
  const W = el.parentElement.clientWidth - 10 || 500, H = 220;
  const m = {{t:14,r:14,b:30,l:40}};
  const w = W-m.l-m.r, h = H-m.t-m.b;
  const svg = d3.select('#'+svgId).attr('viewBox',`0 0 ${{W}} ${{H}}`);
  const g   = svg.append('g').attr('transform',`translate(${{m.l}},${{m.t}})`);

  if (labels.length < 2) {{
    g.append('text').attr('x',w/2).attr('y',h/2).attr('text-anchor','middle')
      .attr('fill','#334155').text('Need 2+ scans');
    return;
  }}

  const x = d3.scalePoint().domain(labels).range([0,w]);
  const maxY = label==='%' ? 100 : d3.max(data)||1;
  const y = d3.scaleLinear().domain([0,maxY]).range([h,0]);

  // Grid
  g.append('g').call(d3.axisLeft(y).ticks(4).tickSize(-w).tickFormat(d=>d+(label||'')))
   .selectAll('text').attr('fill','#475569').attr('font-size',9);
  g.selectAll('.tick line').attr('stroke','#1e293b').attr('stroke-dasharray','3,3');
  g.select('.domain').remove();

  g.append('g').attr('transform',`translate(0,${{h}})`).call(d3.axisBottom(x).tickSize(0))
   .selectAll('text').attr('fill','#475569').attr('font-size',9).attr('transform','rotate(-30)').attr('text-anchor','end');

  // Area + Line
  const area = d3.area().x((d,i)=>x(labels[i])).y0(h).y1(d=>y(d)).curve(d3.curveCatmullRom);
  const line = d3.line().x((d,i)=>x(labels[i])).y(d=>y(d)).curve(d3.curveCatmullRom);

  g.append('path').datum(data).attr('fill',color+'20').attr('d',area);
  g.append('path').datum(data).attr('fill','none').attr('stroke',color)
   .attr('stroke-width',2.5).attr('d',line);

  // Dots
  g.selectAll('circle').data(data).join('circle')
   .attr('cx',(d,i)=>x(labels[i])).attr('cy',d=>y(d))
   .attr('r',4).attr('fill',color).attr('stroke','#0f172a').attr('stroke-width',2)
   .append('title').text((d,i)=>`${{labels[i]}}: ${{d}}${{label||''}}`);
}}

drawLineChart('chart-trend', tLabels, tScores, '#38bdf8', '%');
drawLineChart('chart-sev',   tLabels, tCrits,  '#ef4444', '');

// ── D3 Attack Graph ──────────────────────────────────
(function(){{
  const wrap = document.getElementById('graph-wrap');
  const W = wrap.clientWidth || 1000, H = 420;
  const svg = d3.select('#graph-wrap').append('svg').attr('width','100%').attr('height',H);

  if (!gd.nodes.length) {{
    svg.append('text').attr('x',W/2).attr('y',H/2).attr('text-anchor','middle')
      .attr('fill','#334155').attr('font-size',14)
      .text('No graph data — install networkx and re-scan');
    return;
  }}

  svg.append('defs').append('marker').attr('id','arr')
    .attr('viewBox','0 -5 10 10').attr('refX',22).attr('refY',0)
    .attr('markerWidth',5).attr('markerHeight',5).attr('orient','auto')
    .append('path').attr('d','M0,-5L10,0L0,5').attr('fill','#ef4444');

  const sim = d3.forceSimulation(gd.nodes)
    .force('link', d3.forceLink(gd.links).id(d=>d.id).distance(140))
    .force('charge', d3.forceManyBody().strength(-500))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('collision', d3.forceCollide(22));

  const link = svg.append('g').selectAll('line').data(gd.links).join('line')
    .attr('stroke', d=>d.attack_type?'#ef4444':'#334155')
    .attr('stroke-width', d=>d.attack_type?2.5:1)
    .attr('stroke-opacity', 0.8)
    .attr('marker-end', d=>d.attack_type?'url(#arr)':null);

  const cm = {{S3:'#f59e0b',IAM:'#6366f1',IAM_USER:'#818cf8',EC2:'#10b981',RDS:'#3b82f6'}};

  const node = svg.append('g').selectAll('circle').data(gd.nodes).join('circle')
    .attr('r', d=>d.sensitive?17:13)
    .attr('fill', d=>cm[d.service]||'#ec4899')
    .attr('stroke', d=>d.sensitive?'#fbbf24':'#1e293b')
    .attr('stroke-width', d=>d.sensitive?2.5:1.5)
    .style('cursor','pointer')
    .call(d3.drag()
      .on('start',(e,d)=>{{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;}})
      .on('drag', (e,d)=>{{d.fx=e.x;d.fy=e.y;}})
      .on('end',  (e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}}));

  // Tooltip
  const tip = d3.select('body').append('div').style('position','fixed')
    .style('background','#1e293b').style('border','1px solid #334155')
    .style('border-radius','6px').style('padding','8px 12px')
    .style('font-size','12px').style('color','#e2e8f0')
    .style('pointer-events','none').style('opacity',0).style('max-width','260px');

  node.on('mouseover',(e,d)=>{{
    tip.style('opacity',1).style('left',e.clientX+12+'px').style('top',e.clientY-10+'px')
      .html(`<strong>[${{d.service}}]</strong> ${{d.id}}${{d.sensitive?'<br><span style="color:#fbbf24">⚠ Sensitive resource</span>':''}}`);
  }}).on('mouseout',()=>tip.style('opacity',0));

  const lbl = svg.append('g').selectAll('text').data(gd.nodes).join('text')
    .attr('font-size',9).attr('fill','#64748b').attr('text-anchor','middle').attr('dy',27)
    .text(d=>d.id.length>18?d.id.slice(0,16)+'…':d.id);

  sim.on('tick',()=>{{
    link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
        .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('cx',d=>d.x).attr('cy',d=>d.y);
    lbl.attr('x',d=>d.x).attr('y',d=>d.y);
  }});
}})();

// ── Finding Filter ───────────────────────────────────
function filt(btn, sev) {{
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  const body = document.getElementById('ftbody');
  if (!body) return;
  body.querySelectorAll('tr').forEach(r=>{{
    const b = r.querySelector('.badge');
    r.style.display = (sev==='ALL'||b?.textContent===sev) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════
#  HTTP HANDLER
# ══════════════════════════════════════════════════════════

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  [{datetime.now().strftime('%H:%M:%S')}] {self.address_string()} — {fmt % args}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"

        use_db  = db_ok(DB_PATH)
        latest  = {}
        trends  = []
        recurring = []

        if use_db:
            latest    = load_latest_db(DB_PATH) or {}
            trends    = load_trends_db(DB_PATH)
            recurring = load_top_recurring_db(DB_PATH)
            count     = len(trends)
        else:
            scans  = load_scans_json(REPORTS_DIR)
            latest = scans[0] if scans else {}
            trends = [{"scan_time": s.get("scan_time",""),
                       "region":    s.get("region",""),
                       "account_id": s.get("account_id",""),
                       "total":     s.get("summary",{}).get("total_findings",0),
                       "critical":  s.get("summary",{}).get("severity_breakdown",{}).get("CRITICAL",0),
                       "high":      s.get("summary",{}).get("severity_breakdown",{}).get("HIGH",0),
                       "score":     s.get("summary",{}).get("compliance_score",0),
                       "attack_paths": s.get("summary",{}).get("attack_paths_found",0),
                       } for s in scans]
            count = len(scans)

        if path == "/":
            html = build_html(latest, trends, recurring, count, use_db)
            self._send(200, "text/html", html.encode())

        elif path == "/api/latest":
            self._send(200, "application/json",
                       json.dumps(latest, indent=2, default=str).encode())

        elif path == "/api/trends":
            self._send(200, "application/json", json.dumps(trends).encode())

        elif path == "/api/recurring":
            self._send(200, "application/json", json.dumps(recurring).encode())

        elif path == "/api/health":
            self._send(200, "application/json",
                       json.dumps({"status":"ok","db":use_db,"scans":count}).encode())

        else:
            self._send(404, "text/plain", b"Not found")

    def _send(self, code, ct, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)


# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════

def main():
    global REPORTS_DIR, DB_PATH

    parser = argparse.ArgumentParser(description="CloudGuard Web Dashboard")
    parser.add_argument("--port",        type=int, default=5000)
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--db",          default="cloudguard.db")
    args = parser.parse_args()

    REPORTS_DIR = args.reports_dir
    DB_PATH     = args.db

    use_db = db_ok(DB_PATH)
    mode   = f"SQLite ({DB_PATH})" if use_db else f"JSON files ({REPORTS_DIR}/)"

    print(f"""
╔════════════════════════════════════════╗
║     CloudGuard Dashboard  v2.0         ║
╚════════════════════════════════════════╝
  Mode    : {mode}
  URL     : http://localhost:{args.port}

  API endpoints:
    /api/latest    — latest scan JSON
    /api/trends    — compliance history
    /api/recurring — top recurring findings
    /api/health    — status

  Press Ctrl+C to stop
""")

    server = HTTPServer(("0.0.0.0", args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")


if __name__ == "__main__":
    main()