"""
utils/html_report.py - Interactive HTML Report Generator
=========================================================
Generate laporan hasil scan dalam 1 file HTML self-contained:
  - Searchable & filterable endpoint table
  - Kategori 4-way dengan color coding
  - Subdomain liveness overview
  - Tech fingerprint badges
  - Parameter list dengan sensitive highlight
  - Dark theme modern, no external dependency (CSS + JS inline)

Semua di-embed dalam 1 file .html — bisa dibuka langsung di browser,
di-share, atau di-archive tanpa perlu server.
"""

import json
import html as html_lib
from datetime import datetime


class HTMLReport:

    def generate(self, data: dict, output_path: str):
        """
        Generate HTML report dari data scan.

        Args:
            data: dict hasil scan (bisa dari crawl/recon/active mode)
            output_path: path output .html
        """
        target    = data.get("target", "Unknown")
        mode      = data.get("mode", "scan")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Extract data sesuai mode
        classified = self._extract_classified(data)
        subdomains = self._extract_subdomains(data)
        parameters = self._extract_parameters(data)
        tech       = data.get("tech", {})
        stats      = self._extract_stats(data)
        status_map = self._extract_status_map(data)

        html_content = self._build_html(
            target=target, mode=mode, timestamp=timestamp,
            classified=classified, subdomains=subdomains,
            parameters=parameters, tech=tech, stats=stats,
            status_map=status_map,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path

    # =============================================================
    # DATA EXTRACTION
    # =============================================================
    def _extract_classified(self, data: dict) -> dict:
        # Recon mode: ambil dari aggregated
        if data.get("mode") == "recon":
            agg = data.get("aggregated", {})
            return {
                "private_open":   agg.get("all_private_open", []),
                "public_open":    agg.get("all_public_open", []),
                "private_closed": agg.get("all_private_closed", []),
                "public_closed":  agg.get("all_public_closed", []),
            }
        # Harvest mode
        if data.get("mode") == "harvest":
            # Baik raw maupun classified: pakai bucket classified kalau ada
            # (raw mode kini juga menyertakan classified untuk badge di report)
            c = data.get("classified", {})
            if c:
                return {
                    "private_open":   c.get("private_open", []),
                    "public_open":    c.get("public_open", []),
                    "private_closed": [], "public_closed": [],
                }
            # fallback: semua flat di public
            return {
                "private_open": [], "public_open": data.get("urls", []),
                "private_closed": [], "public_closed": [],
            }
        # Crawl/active mode
        c = data.get("classified", {})
        return {
            "private_open":   c.get("private_open", []),
            "public_open":    c.get("public_open", []),
            "private_closed": c.get("private_closed", []),
            "public_closed":  c.get("public_closed", []),
        }

    def _extract_status_map(self, data: dict) -> dict:
        """
        Bikin map url -> status_code dari berbagai sumber data.
        Dipakai buat nampilin badge [200]/[404]/dll di report.
        """
        smap = {}
        for key in ("validated", "raw_results", "results", "raw"):
            for item in (data.get(key) or []):
                if isinstance(item, dict) and item.get("url"):
                    sc = item.get("status_code")
                    if sc is not None:
                        smap[item["url"]] = sc
        if data.get("mode") == "recon":
            agg = data.get("aggregated", {})
            for item in (agg.get("details") or []):
                if isinstance(item, dict) and item.get("url"):
                    sc = item.get("status_code")
                    if sc is not None:
                        smap[item["url"]] = sc
        return smap

    def _extract_subdomains(self, data: dict) -> list:
        if data.get("mode") == "recon":
            enum = data.get("enum", {})
            return enum.get("live_details", [])
        return []

    def _extract_parameters(self, data: dict) -> dict:
        if data.get("mode") == "recon":
            agg = data.get("aggregated", {})
            return {
                "all": agg.get("all_parameters", []),
                "sensitive": agg.get("all_sensitive_params", []),
            }
        p = data.get("parameters", {})
        return {
            "all": p.get("all", []),
            "sensitive": p.get("sensitive", []),
        }

    def _extract_stats(self, data: dict) -> dict:
        if data.get("mode") == "recon":
            agg = data.get("aggregated", {})
            enum_stats = data.get("enum", {}).get("stats", {})
            return {
                "total_subs":     enum_stats.get("total_found", 0),
                "live_subs":      enum_stats.get("live_count", 0),
                "total_endpoints": agg.get("total_endpoints", 0),
            }
        return {
            "total_endpoints": data.get("total_validated", 0),
            "extracted":       data.get("total_found", 0),
        }

    # =============================================================
    # HTML BUILDER
    # =============================================================
    def _build_html(self, **kw) -> str:
        target     = html_lib.escape(str(kw["target"]))
        mode       = html_lib.escape(str(kw["mode"]).upper())
        timestamp  = kw["timestamp"]
        classified = kw["classified"]
        subdomains = kw["subdomains"]
        parameters = kw["parameters"]
        tech       = kw["tech"]
        stats      = kw["stats"]
        status_map = kw.get("status_map", {})

        # Build endpoint rows (untuk JS data)
        endpoint_data = []
        cat_meta = {
            "private_open":   ("PRIVATE-OPEN", "critical"),
            "public_open":    ("PUBLIC-OPEN", "ok"),
            "private_closed": ("PRIVATE-CLOSED", "warn"),
            "public_closed":  ("PUBLIC-CLOSED", "muted"),
        }
        for cat_key, (label, cls) in cat_meta.items():
            for url in classified.get(cat_key, []):
                sc = status_map.get(url, "")
                endpoint_data.append({
                    "url": url, "category": label, "class": cls,
                    "status": sc if sc != "" else "-",
                })

        endpoints_json = json.dumps(endpoint_data)

        # Stat cards
        stat_cards = self._build_stat_cards(classified, stats)

        # Subdomain section
        subdomain_html = self._build_subdomain_section(subdomains)

        # Tech badges
        tech_html = self._build_tech_section(tech)

        # Parameter section
        param_html = self._build_param_section(parameters)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShadowPath Report - {target}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: #0d1117; color: #e6edf3; line-height:1.6; padding: 24px;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
header {{
  border-bottom: 1px solid #30363d; padding-bottom: 20px; margin-bottom: 24px;
}}
h1 {{ font-size: 28px; color: #58a6ff; margin-bottom: 8px; }}
.meta {{ color: #8b949e; font-size: 14px; }}
.meta span {{ margin-right: 20px; }}
.badge-mode {{
  display:inline-block; background:#1f6feb; color:#fff; padding:2px 10px;
  border-radius:12px; font-size:12px; font-weight:600;
}}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:28px; }}
.stat-card {{
  background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px;
}}
.stat-card .num {{ font-size:28px; font-weight:700; }}
.stat-card .label {{ color:#8b949e; font-size:13px; margin-top:4px; }}
.critical .num {{ color:#f85149; }}
.ok .num {{ color:#3fb950; }}
.warn .num {{ color:#d29922; }}
.muted .num {{ color:#8b949e; }}
.info .num {{ color:#58a6ff; }}
section {{ margin-bottom:32px; }}
h2 {{ font-size:20px; margin-bottom:16px; color:#e6edf3; border-left:3px solid #58a6ff; padding-left:12px; }}
.controls {{ display:flex; gap:12px; margin-bottom:16px; flex-wrap:wrap; }}
input[type=text], select {{
  background:#0d1117; border:1px solid #30363d; color:#e6edf3;
  padding:8px 12px; border-radius:6px; font-size:14px;
}}
input[type=text] {{ flex:1; min-width:200px; }}
table {{ width:100%; border-collapse:collapse; background:#161b22; border-radius:8px; overflow:hidden; }}
th {{ background:#21262d; padding:10px 14px; text-align:left; font-size:13px; color:#8b949e; text-transform:uppercase; cursor:pointer; user-select:none; }}
th:hover {{ color:#e6edf3; }}
td {{ padding:10px 14px; border-top:1px solid #21262d; font-size:14px; word-break:break-all; }}
tr:hover td {{ background:#1c2128; }}
.tag {{ display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; }}
.tag.critical {{ background:#3d1518; color:#f85149; }}
.tag.ok {{ background:#12261e; color:#3fb950; }}
.tag.warn {{ background:#2d2410; color:#d29922; }}
.tag.muted {{ background:#21262d; color:#8b949e; }}
a {{ color:#58a6ff; text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
.badges {{ display:flex; flex-wrap:wrap; gap:8px; }}
.tech-badge {{ background:#161b22; border:1px solid #30363d; padding:6px 12px; border-radius:6px; font-size:13px; }}
.tech-cat {{ color:#8b949e; font-size:11px; text-transform:uppercase; margin-bottom:6px; }}
.tech-group {{ margin-bottom:16px; }}
.param-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:8px; }}
.param {{ background:#161b22; border:1px solid #30363d; padding:6px 12px; border-radius:6px; font-size:13px; font-family:monospace; }}
.param.sensitive {{ border-color:#f85149; color:#f85149; }}
.sub-table td.status-live {{ color:#3fb950; font-weight:600; }}
.sub-table td.status-empty {{ color:#8b949e; }}
.sub-table td.status-dns {{ color:#d29922; }}
.sub-table td.status-dead {{ color:#f85149; }}
.stcode {{ display:inline-block; min-width:38px; text-align:center; padding:2px 8px; border-radius:5px; font-size:12px; font-weight:600; font-family:monospace; }}
.st-2xx {{ background:#132e1c; color:#3fb950; border:1px solid #238636; }}
.st-3xx {{ background:#0d2436; color:#58a6ff; border:1px solid #1f6feb; }}
.st-auth {{ background:#2d2a10; color:#d29922; border:1px solid #9e6a03; }}
.st-4xx {{ background:#2d1518; color:#f85149; border:1px solid #b62324; }}
.st-5xx {{ background:#31161a; color:#ff7b72; border:1px solid #da3633; }}
.st-unknown {{ background:#161b22; color:#8b949e; border:1px solid #30363d; }}
footer {{ text-align:center; color:#8b949e; font-size:12px; margin-top:40px; padding-top:20px; border-top:1px solid #30363d; }}
.empty {{ color:#8b949e; font-style:italic; padding:20px; text-align:center; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🎯 ShadowPath Report</h1>
    <div class="meta">
      <span><b>Target:</b> {target}</span>
      <span><b>Mode:</b> <span class="badge-mode">{mode}</span></span>
      <span><b>Generated:</b> {timestamp}</span>
    </div>
  </header>

  {stat_cards}

  {tech_html}

  {subdomain_html}

  <section>
    <h2>🔗 Endpoints</h2>
    <div class="controls">
      <input type="text" id="search" placeholder="Search endpoints...">
      <select id="filter">
        <option value="">All categories</option>
        <option value="PRIVATE-OPEN">Private-Open</option>
        <option value="PUBLIC-OPEN">Public-Open</option>
        <option value="PRIVATE-CLOSED">Private-Closed</option>
        <option value="PUBLIC-CLOSED">Public-Closed</option>
      </select>
    </div>
    <table id="endpoints">
      <thead><tr><th data-sort="url">URL</th><th data-sort="status">Status</th><th data-sort="category">Category</th></tr></thead>
      <tbody id="ep-body"></tbody>
    </table>
    <div id="ep-empty" class="empty" style="display:none;">No endpoints match your filter</div>
  </section>

  {param_html}

  <footer>
    Generated by ShadowPath · Hidden Endpoint Discovery Engine
  </footer>
</div>

<script>
const endpoints = {endpoints_json};
let sortKey = 'category', sortAsc = true;

function render() {{
  const q = document.getElementById('search').value.toLowerCase();
  const filter = document.getElementById('filter').value;
  let rows = endpoints.filter(e =>
    e.url.toLowerCase().includes(q) &&
    (filter === '' || e.category === filter)
  );
  rows.sort((a,b) => {{
    let x = a[sortKey], y = b[sortKey];
    return sortAsc ? (x>y?1:-1) : (x<y?1:-1);
  }});
  const body = document.getElementById('ep-body');
  const empty = document.getElementById('ep-empty');
  if (rows.length === 0) {{
    body.innerHTML = ''; empty.style.display = 'block'; return;
  }}
  empty.style.display = 'none';
  body.innerHTML = rows.map(e => {{
    const cls = e.category.toLowerCase().replace('-','').includes('privateopen') ? 'critical'
              : e.category === 'PUBLIC-OPEN' ? 'ok'
              : e.category === 'PRIVATE-CLOSED' ? 'warn' : 'muted';
    // Badge status HTTP berwarna
    const sc = e.status;
    let scls = 'st-unknown';
    if (sc >= 200 && sc < 300) scls = 'st-2xx';
    else if (sc >= 300 && sc < 400) scls = 'st-3xx';
    else if (sc === 401 || sc === 403) scls = 'st-auth';
    else if (sc >= 400 && sc < 500) scls = 'st-4xx';
    else if (sc >= 500) scls = 'st-5xx';
    const scBadge = `<span class="stcode ${{scls}}">${{sc}}</span>`;
    return `<tr><td><a href="${{e.url}}" target="_blank" rel="noopener">${{e.url}}</a></td>`
         + `<td>${{scBadge}}</td>`
         + `<td><span class="tag ${{cls}}">${{e.category}}</span></td></tr>`;
  }}).join('');
}}

document.getElementById('search').addEventListener('input', render);
document.getElementById('filter').addEventListener('change', render);
document.querySelectorAll('th[data-sort]').forEach(th => {{
  th.addEventListener('click', () => {{
    const k = th.dataset.sort;
    if (sortKey === k) sortAsc = !sortAsc; else {{ sortKey = k; sortAsc = true; }}
    render();
  }});
}});
render();
</script>
</body>
</html>"""

    def _build_stat_cards(self, classified: dict, stats: dict) -> str:
        cards = []
        # Endpoint category counts
        po = len(classified.get("private_open", []))
        puo = len(classified.get("public_open", []))
        pc = len(classified.get("private_closed", []))
        puc = len(classified.get("public_closed", []))

        cards.append(f'<div class="stat-card critical"><div class="num">{po}</div><div class="label">⚠️ Private-Open</div></div>')
        cards.append(f'<div class="stat-card ok"><div class="num">{puo}</div><div class="label">✅ Public-Open</div></div>')
        cards.append(f'<div class="stat-card warn"><div class="num">{pc}</div><div class="label">🔒 Private-Closed</div></div>')
        cards.append(f'<div class="stat-card muted"><div class="num">{puc}</div><div class="label">⚪ Public-Closed</div></div>')

        # Subdomain stat kalau ada
        if stats.get("total_subs"):
            cards.append(f'<div class="stat-card info"><div class="num">{stats["live_subs"]}</div><div class="label">📡 Live Subdomains</div></div>')

        return f'<div class="stats">{"".join(cards)}</div>'

    def _build_subdomain_section(self, subdomains: list) -> str:
        if not subdomains:
            return ""
        status_class = {
            "live": "status-live", "reachable_empty": "status-empty",
            "dns_only": "status-dns", "dead": "status-dead",
        }
        rows = []
        for d in sorted(subdomains, key=lambda x: x.get("status", "")):
            host   = html_lib.escape(d.get("host", ""))
            status = d.get("status", "")
            server = html_lib.escape(d.get("server", "") or "?")
            title  = html_lib.escape((d.get("title", "") or "")[:60])
            cls    = status_class.get(status, "")
            rows.append(
                f'<tr><td><a href="http://{host}" target="_blank" rel="noopener">{host}</a></td>'
                f'<td class="{cls}">{status.upper()}</td>'
                f'<td>{server}</td><td>{title}</td></tr>'
            )
        return f"""<section>
    <h2>📡 Subdomains ({len(subdomains)})</h2>
    <table class="sub-table">
      <thead><tr><th>Host</th><th>Status</th><th>Server</th><th>Title</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>
  </section>"""

    def _build_tech_section(self, tech: dict) -> str:
        if not tech:
            return ""
        groups = []
        for cat, techs in tech.items():
            if not techs:
                continue
            label = cat.replace("_", " ").title()
            badges = "".join(f'<span class="tech-badge">{html_lib.escape(str(t))}</span>' for t in techs)
            groups.append(f'<div class="tech-group"><div class="tech-cat">{label}</div><div class="badges">{badges}</div></div>')
        if not groups:
            return ""
        return f'<section><h2>🛠️ Technology Stack</h2>{"".join(groups)}</section>'

    def _build_param_section(self, parameters: dict) -> str:
        all_params = parameters.get("all", [])
        sensitive  = set(parameters.get("sensitive", []))
        if not all_params:
            return ""
        items = []
        for p in sorted(all_params):
            cls = "param sensitive" if p in sensitive else "param"
            items.append(f'<div class="{cls}">{html_lib.escape(str(p))}</div>')
        return f"""<section>
    <h2>🔑 Parameters ({len(all_params)}, {len(sensitive)} sensitive)</h2>
    <div class="param-grid">{"".join(items)}</div>
  </section>"""
