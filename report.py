"""Render cross-tool correlations as a visual risk report.

Two sections:

1. Compromisable-identity chains: a dangerous application -> its risky
   owner(s) -> each owner's privilege escalation path, rendered as a
   visual chain so the relationship is obvious at a glance.

2. Over-privileged and unowned: dangerous apps with no owner at all -
   a standing risk with no accountable party.

Palette and card treatment matched to the shared entra-security-report
suite (tinted card backgrounds, severity-colored left border).
"""

from html import escape
from datetime import datetime, timezone

# Palette lifted directly from the shared entra-security-report suite.
_CSS = """
:root {
  --bg: #ffffff; --card: #fff; --border: #e5e7eb;
  --text: #0f172a; --muted: #64748b;
  --sev-critical: #ff0000; --bg-critical: #ffb3b3;
  --sev-high:     #ff7a00; --bg-high:     #ffcc99;
  --step-bg: #ffffff; --step-border: #e5e7eb;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  line-height: 1.5;
}
main { max-width: 960px; margin: 0 auto; padding: 2.5rem 1.5rem; }
h1 { font-size: 1.9rem; margin: 0 0 .25rem; }
h2.section {
  font-size: 1.15rem; margin: 2.5rem 0 1rem; padding-bottom: .4rem;
  border-bottom: 1px solid var(--border);
}
.subtitle { color: var(--muted); margin: 0; }
.ts { color: var(--muted); font-size: .85rem; margin: .1rem 0 2rem; }

.summary {
  background: var(--card); border: 1px solid var(--border); border-radius: 12px;
  padding: 1.25rem 1.5rem; margin-bottom: 1rem;
  display: flex; gap: 2.5rem; align-items: baseline; flex-wrap: wrap;
}
.summary .n { font-size: 1.75rem; font-weight: 700; display: block; line-height: 1; }
.summary .l { font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.summary .headline { padding-right: 2.5rem; border-right: 1px solid var(--border); }
.summary .headline .n { font-size: 2.1rem; }
.summary .crit .n { color: var(--sev-critical); }
.summary .high .n { color: var(--sev-high); }

.card {
  background: var(--card); border: 1px solid var(--border);
  border-left: 6px solid var(--sev-critical); border-radius: 12px;
  padding: 1.25rem 1.5rem; margin-bottom: 1.5rem;
}
.card.sev-critical { background: var(--bg-critical); border-left-color: var(--sev-critical); }
.card.sev-high     { background: var(--bg-high);     border-left-color: var(--sev-high); }

.card-app { display: flex; align-items: center; gap: .75rem; flex-wrap: wrap; }
.badge {
  color: #fff; font-size: .7rem; font-weight: 700; letter-spacing: .05em;
  padding: .2rem .55rem; border-radius: 999px; text-transform: uppercase;
}
.badge.sev-critical { background: var(--sev-critical); }
.badge.sev-high     { background: var(--sev-high); }
.app-name { font-size: 1.2rem; font-weight: 700; }
.app-perm { color: #334155; font-family: ui-monospace, Menlo, monospace; font-size: .85rem; }
.app-detail { color: #334155; font-size: .9rem; margin: .35rem 0 0; }

.owner {
  margin-left: 1rem; padding-left: 1.25rem;
  border-left: 2px solid rgba(0,0,0,0.25); margin-top: 1.1rem;
}
.owner-head { font-weight: 600; margin-bottom: .5rem; }
.owner-note { color: #475569; font-size: .85rem; font-weight: 400; }

.path { display: flex; align-items: center; flex-wrap: wrap; gap: .4rem; margin: .35rem 0; }
.step {
  background: var(--step-bg); border: 1px solid var(--step-border);
  border-radius: 6px; padding: .3rem .6rem; font-size: .85rem; white-space: nowrap;
}
.step.role { font-weight: 600; }
.arrow { color: #475569; font-size: .9rem; }

.unowned-note { color: #475569; font-size: .9rem; margin-top: .5rem; font-style: italic; }
.empty { color: var(--muted); padding: 1.5rem; }
"""


def _sev_class(severity):
    return f"sev-{severity}" if severity in ("critical", "high") else "sev-high"


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
    findings = owner["attack_findings"]
    paths_html = []
    for f in findings:
        path = f.evidence.get("path") or [name, f.evidence.get("role", "privileged role")]
        paths_html.append(_step_html(path))
    n = len(findings)
    note = f'{n} escalation path{"s" if n != 1 else ""}'
    return f'''<div class="owner">
      <div class="owner-head">owned by {name}
        <span class="owner-note">&mdash; {note}</span></div>
      {"".join(paths_html)}
    </div>'''


def _card_head(app, finding):
    sev = finding.severity
    sc = _sev_class(sev)
    perm = escape(str(finding.evidence.get("permission", "")))
    return sc, f'''<div class="card-app">
        <span class="badge {sc}">{escape(sev)}</span>
        <span class="app-name">{escape(app.display_name)}</span>
        <span class="app-perm">{perm}</span>
      </div>
      <div class="app-detail">{escape(finding.detail)}</div>'''


def _chain_card(result):
    sc, head = _card_head(result["app"], result["app_finding"])
    owners = "".join(_owner_html(o) for o in result["risky_owners"])
    return f'<div class="card {sc}">{head}{owners}</div>'


def _unowned_card(result):
    sc, head = _card_head(result["app"], result["app_finding"])
    note = '<div class="unowned-note">No owner assigned &mdash; over-privileged and unaccountable.</div>'
    return f'<div class="card {sc}">{head}{note}</div>'


def _count_sev(results):
    c = sum(1 for r in results if r["app_finding"].severity == "critical")
    h = sum(1 for r in results if r["app_finding"].severity == "high")
    return c, h


def render_report(chains, unowned, output_path="orchestrator_report.html"):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(chains) + len(unowned)
    crit, high = _count_sev(chains + unowned)

    chains_body = "".join(_chain_card(r) for r in chains) or '<div class="empty">No compromisable-identity chains found.</div>'
    unowned_body = "".join(_unowned_card(r) for r in unowned) or '<div class="empty">No unowned privileged apps found.</div>'

    html = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Entra Orchestrator - Correlation Report</title>
<style>{_CSS}</style></head><body><main>
<h1>Entra Orchestrator</h1>
<p class="subtitle">Cross-tool correlation across the Entra ID security suite</p>
<p class="ts">{ts}</p>
<div class="summary">
  <div class="headline"><span class="n">{len(chains)}</span><span class="l">apps controlled by a compromisable identity</span></div>
  <div class="crit"><span class="n">{crit}</span><span class="l">critical</span></div>
  <div class="high"><span class="n">{high}</span><span class="l">high</span></div>
  <div><span class="n">{len(unowned)}</span><span class="l">over-privileged &amp; unowned</span></div>
</div>

<h2 class="section">Controlled by compromisable identities</h2>
{chains_body}

<h2 class="section">Over-privileged and unowned</h2>
{unowned_body}

</main></body></html>'''

    with open(output_path, "w") as fp:
        fp.write(html)
    return output_path
