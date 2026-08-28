"""Unified HTML report across all three Entra ID security scanners.

Renders every finding from the shared store in a single page with
three columns, one per tool, plus a global summary at the top.
"""

from html import escape
from datetime import datetime, timezone

from entra_security_report import Storage, Query

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

TOOL_META = {
    "workload-identity": {
        "label": "Workload Identity",
        "icon": "&#x1F511;",
        "desc": "App registrations, permissions, credentials, ownership",
    },
    "attack-path": {
        "label": "Attack Path",
        "icon": "&#x26A1;",
        "desc": "Privilege escalation paths via role and group membership",
    },
    "zt-policy": {
        "label": "Zero Trust Policy",
        "icon": "&#x1F6E1;",
        "desc": "Conditional Access policy gaps against Zero Trust baseline",
    },
}

TOOL_ORDER = ["workload-identity", "attack-path", "zt-policy"]


def _tally(findings):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    counts["total"] = sum(counts.values())
    return counts


def _sev_bar(counts, total):
    if not total:
        return ""
    segs = []
    for s in SEVERITY_ORDER:
        n = counts.get(s, 0)
        if n:
            pct = (n / total) * 100
            segs.append(f'<div class="seg sev-{s}" style="width:{pct:.1f}%"></div>')
    return f'<div class="sev-bar">{"".join(segs)}</div>'


def _finding_card(f):
    sev = f.severity
    title = escape(f.title)
    detail = escape(f.detail)
    subject = escape(f.subject.display_name)
    rule = escape(f.rule)
    return f"""<div class="fcard sev-{sev}">
      <div class="fcard-head">
        <span class="pill sev-{sev}">{sev}</span>
        <span class="fcard-subject">{subject}</span>
      </div>
      <div class="fcard-title">{title}</div>
      <div class="fcard-detail">{detail}</div>
      <div class="fcard-rule">{rule}</div>
    </div>"""


def _column(tool_key, findings):
    meta = TOOL_META.get(tool_key, {"label": tool_key, "icon": "", "desc": ""})
    counts = _tally(findings)
    total = counts["total"]

    stat_parts = []
    stat_parts.append(f'<span class="col-total">{total}</span>')
    for s in ("critical", "high", "medium", "low"):
        n = counts.get(s, 0)
        if n:
            stat_parts.append(f'<span class="col-sev sev-{s}">{n} {s}</span>')

    bar = _sev_bar(counts, total)

    cards = "".join(
        _finding_card(f)
        for f in sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.subject.display_name.lower()))
    )
    if not cards:
        cards = '<div class="col-empty">No findings</div>'

    return f"""<div class="col">
      <div class="col-header">
        <div class="col-icon">{meta["icon"]}</div>
        <div class="col-title">{escape(meta["label"])}</div>
        <div class="col-desc">{escape(meta["desc"])}</div>
      </div>
      <div class="col-stats">{" ".join(stat_parts)}</div>
      {bar}
      <div class="col-cards">{cards}</div>
    </div>"""


_CSS = """
:root {
  --bg: #f8fafc; --card: #fff; --border: #e2e8f0;
  --text: #0f172a; --muted: #64748b;
  --sev-critical: #ff0000; --bg-critical: #fff0f0;
  --sev-high:     #ff7a00; --bg-high:     #fff7ed;
  --sev-medium:   #eab308; --bg-medium:   #fefce8;
  --sev-low:      #2563eb; --bg-low:      #eff6ff;
  --sev-info:     #64748b; --bg-info:     #f1f5f9;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  line-height: 1.45;
}
main { max-width: 1400px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
h1 { font-size: 1.9rem; margin: 0 0 .25rem; }
.subtitle { color: var(--muted); margin: 0; font-size: .95rem; }
.tenant { color: var(--muted); font-size: .9rem; margin: .15rem 0 0; font-family: ui-monospace, Menlo, monospace; }
.ts { color: var(--muted); font-size: .85rem; margin: .1rem 0 1.5rem; }

.global-summary {
  background: var(--card); border: 1px solid var(--border); border-radius: 12px;
  padding: 1.25rem 1.5rem; margin-bottom: 2rem;
}
.gstats { display: flex; gap: 2.5rem; align-items: baseline; flex-wrap: wrap; }
.gstat .n { font-size: 1.75rem; font-weight: 700; display: block; line-height: 1; }
.gstat .l { font-size: .72rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.gstat.sev-critical .n { color: var(--sev-critical); }
.gstat.sev-high .n { color: var(--sev-high); }
.gstat.sev-medium .n { color: var(--sev-medium); }
.gstat.sev-low .n { color: var(--sev-low); }
.gstat.zero .n { color: var(--muted); opacity: .4; }
.gstat.zero .l { opacity: .55; }

.sev-bar { display: flex; height: 6px; border-radius: 999px; overflow: hidden; background: var(--border); margin-top: .75rem; }
.sev-bar .seg { height: 100%; }
.sev-bar .sev-critical { background: var(--sev-critical); }
.sev-bar .sev-high { background: var(--sev-high); }
.sev-bar .sev-medium { background: var(--sev-medium); }
.sev-bar .sev-low { background: var(--sev-low); }
.sev-bar .sev-info { background: var(--sev-info); }

.columns { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.25rem; }
@media (max-width: 1000px) { .columns { grid-template-columns: 1fr; } }

.col {
  background: var(--card); border: 1px solid var(--border); border-radius: 12px;
  padding: 1.25rem; display: flex; flex-direction: column;
}
.col-header { margin-bottom: .75rem; }
.col-icon { font-size: 1.5rem; margin-bottom: .25rem; }
.col-title { font-size: 1.1rem; font-weight: 700; }
.col-desc { font-size: .78rem; color: var(--muted); margin-top: .15rem; }

.col-stats {
  display: flex; gap: .75rem; align-items: baseline; flex-wrap: wrap;
  font-size: .82rem; margin-bottom: .5rem;
}
.col-total { font-size: 1.3rem; font-weight: 700; }
.col-sev { font-weight: 600; }
.col-sev.sev-critical { color: var(--sev-critical); }
.col-sev.sev-high { color: var(--sev-high); }
.col-sev.sev-medium { color: var(--sev-medium); }
.col-sev.sev-low { color: var(--sev-low); }

.col-cards { display: flex; flex-direction: column; gap: .6rem; margin-top: .75rem; flex: 1; overflow-y: auto; max-height: 80vh; }
.col-empty { color: var(--muted); font-size: .85rem; padding: 1rem; text-align: center; }

.fcard {
  border: 1px solid var(--border); border-left: 4px solid; border-radius: 8px;
  padding: .65rem .85rem; font-size: .85rem;
}
.fcard.sev-critical { border-left-color: var(--sev-critical); background: var(--bg-critical); }
.fcard.sev-high { border-left-color: var(--sev-high); background: var(--bg-high); }
.fcard.sev-medium { border-left-color: var(--sev-medium); background: var(--bg-medium); }
.fcard.sev-low { border-left-color: var(--sev-low); background: var(--bg-low); }
.fcard.sev-info { border-left-color: var(--sev-info); background: var(--bg-info); }

.fcard-head { display: flex; align-items: center; gap: .5rem; margin-bottom: .25rem; }
.fcard-subject { font-weight: 600; font-size: .85rem; }
.fcard-title { font-weight: 500; margin-bottom: .15rem; }
.fcard-detail { color: var(--muted); font-size: .8rem; }
.fcard-rule { font-family: ui-monospace, Menlo, monospace; font-size: .68rem; color: var(--muted); margin-top: .25rem; }

.pill {
  display: inline-block; font-size: .62rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: .05em; padding: .1rem .4rem; border-radius: 999px; color: #fff; white-space: nowrap;
}
.pill.sev-critical { background: var(--sev-critical); }
.pill.sev-high { background: var(--sev-high); }
.pill.sev-medium { background: var(--sev-medium); }
.pill.sev-low { background: var(--sev-low); }
.pill.sev-info { background: var(--sev-info); }
"""


def render_unified(tenant_id="", output_path="unified_report.html"):
    storage = Storage()
    query = Query(storage)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    by_tool = {}
    all_findings = []
    for tool_key in TOOL_ORDER:
        findings = query.all(tool=tool_key)
        by_tool[tool_key] = findings
        all_findings.extend(findings)

    total_counts = _tally(all_findings)
    total = total_counts["total"]

    tenant_line = ""
    if tenant_id:
        masked = "..." + tenant_id.split("-")[-1]
        tenant_line = f'<p class="tenant">Tenant {escape(masked)}</p>'

    global_stats = []
    global_stats.append(f'<div class="gstat"><span class="n">{total}</span><span class="l">total findings</span></div>')
    for s in ("critical", "high", "medium", "low"):
        n = total_counts.get(s, 0)
        z = " zero" if not n else ""
        global_stats.append(f'<div class="gstat sev-{s}{z}"><span class="n">{n}</span><span class="l">{s}</span></div>')
    global_stats.append(f'<div class="gstat"><span class="n">{len(TOOL_ORDER)}</span><span class="l">tools</span></div>')

    global_bar = _sev_bar(total_counts, total)
    columns = "".join(_column(t, by_tool[t]) for t in TOOL_ORDER)

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Entra Security Suite</title>
<style>{_CSS}</style></head><body><main>
<h1>Entra Security Suite</h1>
<p class="subtitle">Unified findings across all scanners</p>
{tenant_line}
<p class="ts">{ts}</p>

<div class="global-summary">
  <div class="gstats">{"".join(global_stats)}</div>
  {global_bar}
</div>

<div class="columns">{columns}</div>

</main></body></html>"""

    with open(output_path, "w") as fp:
        fp.write(html)
    return output_path


if __name__ == "__main__":
    import os
    tenant_id = os.environ.get("TENANT_ID", "e5e2596b-f25e-4c40-9504-d9a5aaef7304")
    out = render_unified(tenant_id=tenant_id)
    print(f"Unified report written to {out}")
