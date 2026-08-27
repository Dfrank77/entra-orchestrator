"""Render cross-tool correlations as a visual risk report.

Two sections:
1. Compromisable-identity chains: dangerous app -> risky owner(s) ->
   each owner's privilege escalation path, shown as a visual chain.
2. Over-privileged and unowned: dangerous apps with no owner.

Cards use a three-tier visual hierarchy so they scan fast:
  - headline row: severity badge + app + permission tag
  - muted consequence line ("so what")
  - a set-apart chain zone (the "who can exploit it")

Palette matched to the shared entra-security-report suite.
"""

from html import escape
from datetime import datetime, timezone


_CSS = """
:root {
  --bg: #ffffff; --card: #fff; --border: #e5e7eb;
  --text: #0f172a; --muted: #64748b;
  --sev-critical: #ff0000; --bg-critical: #ffb3b3;
  --sev-high:     #ff7a00; --bg-high:     #ffcc99;
  --zone: rgba(255,255,255,0.55);
  --step-bg: #ffffff; --step-border: #d9dee5;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  line-height: 1.45;
}
main { max-width: 960px; margin: 0 auto; padding: 2.5rem 1.5rem; }
h1 { font-size: 1.9rem; margin: 0 0 .25rem; }
h2.section {
  font-size: 1.15rem; margin: 2.25rem 0 1rem; padding-bottom: .4rem;
  border-bottom: 1px solid var(--border);
}
.subtitle { color: var(--muted); margin: 0; }
.tenant { color: var(--muted); font-size: .9rem; margin: .15rem 0 0; font-family: ui-monospace, Menlo, monospace; }
.ts { color: var(--muted); font-size: .85rem; margin: .1rem 0 1.5rem; }

/* summary */
.summary {
  background: var(--card); border: 1px solid var(--border); border-radius: 12px;
  padding: 1.25rem 1.5rem; margin-bottom: 1rem;
  display: flex; gap: 2.5rem; align-items: baseline; flex-wrap: wrap;
}
.summary .n { font-size: 1.75rem; font-weight: 700; display: block; line-height: 1; }
.summary .l { font-size: .72rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.summary .headline { padding-right: 2.5rem; border-right: 1px solid var(--border); }
.summary .headline .n { font-size: 2.1rem; }
.summary .crit .n { color: var(--sev-critical); }
.summary .high .n { color: var(--sev-high); }

/* legend */
.legend {
  display: flex; gap: 1.5rem; flex-wrap: wrap; align-items: center;
  font-size: .78rem; color: var(--muted); margin: 0 0 2rem; padding: .6rem .9rem;
  background: #fafafa; border: 1px solid var(--border); border-radius: 8px;
}
.legend .item { display: flex; align-items: center; gap: .4rem; }
.legend .dot { width: .7rem; height: .7rem; border-radius: 3px; display: inline-block; }
.legend .dot.crit { background: var(--sev-critical); }
.legend .dot.high { background: var(--sev-high); }
.legend .arrow { font-weight: 700; color: var(--text); }

/* cards */
.card {
  background: var(--card); border: 1px solid var(--border);
  border-left: 6px solid var(--sev-critical); border-radius: 12px;
  padding: 1rem 1.25rem; margin-bottom: 1.1rem;
}
.card.sev-critical { background: var(--bg-critical); border-left-color: var(--sev-critical); }
.card.sev-high     { background: var(--bg-high);     border-left-color: var(--sev-high); }

/* tier 1: headline */
.headline-row { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }
.badge {
  color: #fff; font-size: .68rem; font-weight: 700; letter-spacing: .05em;
  padding: .18rem .5rem; border-radius: 999px; text-transform: uppercase;
}
.badge.sev-critical { background: var(--sev-critical); }
.badge.sev-high     { background: var(--sev-high); }
.app-name { font-size: 1.15rem; font-weight: 700; }
.perm-tag {
  font-family: ui-monospace, Menlo, monospace; font-size: .76rem;
  background: rgba(0,0,0,0.07); padding: .12rem .45rem; border-radius: 5px;
  color: #1e293b;
}
.path-count {
  margin-left: auto; font-size: .72rem; color: #475569;
  background: rgba(255,255,255,0.7); border: 1px solid var(--step-border);
  padding: .15rem .55rem; border-radius: 999px; white-space: nowrap;
}

/* tier 2: consequence */
.consequence { color: #334155; font-size: .85rem; margin: .3rem 0 0; }

/* tier 3: chain zone */
.chain-zone {
  background: var(--zone); border-radius: 8px; padding: .75rem .9rem;
  margin-top: .75rem;
}
.owner + .owner { margin-top: .7rem; padding-top: .7rem; border-top: 1px dashed var(--step-border); }
.owner-head { font-weight: 600; font-size: .9rem; margin-bottom: .4rem; }
.path { display: flex; align-items: center; flex-wrap: wrap; gap: .35rem; }
.step {
  background: var(--step-bg); border: 1px solid var(--step-border);
  border-radius: 6px; padding: .28rem .55rem; font-size: .82rem; white-space: nowrap;
}
.step.role { font-weight: 700; }
.arrow { color: #475569; font-weight: 700; font-size: .85rem; }

/* unowned cards: lighter, no chain */
.card.unowned { padding: .7rem 1.25rem; }
.card.unowned .consequence { margin-top: .2rem; font-style: italic; }

.empty { color: var(--muted); padding: 1.25rem; }

/* ownership confidence */
.ownership-tag {
  font-size: .68rem; font-weight: 600; letter-spacing: .03em;
  padding: .15rem .45rem; border-radius: 5px; white-space: nowrap;
}
.ownership-tag.has-rbac {
  background: #dcfce7; color: #166534; border: 1px solid #bbf7d0;
}
.ownership-tag.graph-only {
  background: #fef9c3; color: #854d0e; border: 1px solid #fde68a;
}
.ownership-tag.none {
  background: #fee2e2; color: #991b1b; border: 1px solid #fecaca;
}
.ownership-tag.unknown {
  background: #f1f5f9; color: #64748b; border: 1px solid #e2e8f0;
}
"""


def _sev_class(sev):
    return f"sev-{sev}" if sev in ("critical", "high") else "sev-high"


def _consequence(detail, title):
    """Trim the title-repeat: if detail starts by repeating the title's
    'Holds X' phrasing, keep only the part after the colon."""
    if ":" in detail:
        return detail.split(":", 1)[1].strip()
    return detail


def _step_html(path):
    parts = []
    for i, node in enumerate(path):
        cls = "step role" if i == len(path) - 1 else "step"
        parts.append(f'<span class="{cls}">{escape(str(node))}</span>')
        if i < len(path) - 1:
            parts.append('<span class="arrow">&rarr;</span>')
    return f'<div class="path">{"".join(parts)}</div>'


def _owner_html(owner):
    name = escape(owner["owner_name"])
    paths = []
    for f in owner["attack_findings"]:
        p = f.evidence.get("path") or [name, f.evidence.get("role", "privileged role")]
        paths.append(_step_html(p))
    return f'<div class="owner"><div class="owner-head">owned by {name}</div>{"".join(paths)}</div>'


def _chain_card(result):
    f = result["app_finding"]
    sc = _sev_class(f.severity)
    perm = escape(str(f.evidence.get("permission", "")))
    conseq = escape(_consequence(f.detail, f.title))
    total_paths = sum(len(o["attack_findings"]) for o in result["risky_owners"])
    owners = "".join(_owner_html(o) for o in result["risky_owners"])
    confidence = result.get("ownership_confidence", "unknown")
    conf_label = {"has-rbac": "RBAC verified", "graph-only": "Graph only", "none": "no owner", "unknown": "unknown"}.get(confidence, confidence)
    return f'''<div class="card {sc}">
      <div class="headline-row">
        <span class="badge {sc}">{escape(f.severity)}</span>
        <span class="app-name">{escape(result["app"].display_name)}</span>
        <span class="perm-tag">{perm}</span>
        <span class="ownership-tag {confidence}">{conf_label}</span>
        <span class="path-count">{total_paths} escalation path{"s" if total_paths != 1 else ""}</span>
      </div>
      <div class="consequence">{conseq}</div>
      <div class="chain-zone">{owners}</div>
    </div>'''


def _unowned_card(result):
    f = result["app_finding"]
    sc = _sev_class(f.severity)
    perm = escape(str(f.evidence.get("permission", "")))
    return f'''<div class="card unowned {sc}">
      <div class="headline-row">
        <span class="badge {sc}">{escape(f.severity)}</span>
        <span class="app-name">{escape(result["app"].display_name)}</span>
        <span class="perm-tag">{perm}</span>
        <span class="path-count">no owner</span>
      </div>
      <div class="consequence">Over-privileged and unaccountable &mdash; no owner assigned.</div>
    </div>'''


def _count_sev(results):
    c = sum(1 for r in results if r["app_finding"].severity == "critical")
    h = sum(1 for r in results if r["app_finding"].severity == "high")
    return c, h


def render_report(chains, unowned, tenant_id="", output_path="orchestrator_report.html"):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    crit, high = _count_sev(chains + unowned)

    tenant_line = ""
    if tenant_id:
        masked = "..." + tenant_id.split("-")[-1]
        tenant_line = f'<p class="tenant">Tenant {escape(masked)}</p>'

    legend = '''<div class="legend">
      <span class="item"><span class="dot crit"></span> critical</span>
      <span class="item"><span class="dot high"></span> high</span>
      <span class="item"><span class="arrow">&rarr;</span> escalation step (user &rarr; group &rarr; role)</span>
      <span class="item">"owned by" = app owner who can be compromised</span>
      <span class="item"><span class="ownership-tag has-rbac" style="font-size:.65rem">RBAC verified</span> owner confirmed by Azure RBAC</span>
      <span class="item"><span class="ownership-tag graph-only" style="font-size:.65rem">Graph only</span> ownership from Graph only &mdash; may be stale</span>
    </div>'''

    chains_body = "".join(_chain_card(r) for r in chains) or '<div class="empty">No compromisable-identity chains found.</div>'
    unowned_body = "".join(_unowned_card(r) for r in unowned) or '<div class="empty">No unowned privileged apps found.</div>'

    html = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Entra Orchestrator - Correlation Report</title>
<style>{_CSS}</style></head><body><main>
<h1>Entra Orchestrator</h1>
<p class="subtitle">Cross-tool correlation across the Entra ID security suite</p>
{tenant_line}
<p class="ts">{ts}</p>
<div class="summary">
  <div class="headline"><span class="n">{len(chains)}</span><span class="l">apps controlled by a compromisable identity</span></div>
  <div class="crit"><span class="n">{crit}</span><span class="l">critical</span></div>
  <div class="high"><span class="n">{high}</span><span class="l">high</span></div>
  <div><span class="n">{len(unowned)}</span><span class="l">over-privileged &amp; unowned</span></div>
</div>
{legend}

<h2 class="section">Controlled by compromisable identities</h2>
{chains_body}

<h2 class="section">Over-privileged and unowned</h2>
{unowned_body}

</main></body></html>'''

    with open(output_path, "w") as fp:
        fp.write(html)
    return output_path
