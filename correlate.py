"""Cross-tool correlation over the shared findings store.

A single scanner sees one dimension. Correlation surfaces risks no
single tool can:

1. Subject overlap: the same subject flagged by more than one tool.
2. Ownership join: an over-privileged app whose owner is a user that
   the attack-path tool flags as having a privilege escalation path.
   Neither tool sees this alone - the workload scanner knows the app
   is dangerous, the attack-path tool knows the user is reachable,
   and only joining them reveals that the dangerous app is controlled
   by a compromisable identity.
"""

from entra_security_report import Storage, Query

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _query():
    return Query(Storage())


def correlated_subjects():
    """Subjects flagged by more than one tool, ranked by worst severity."""
    q = _query()
    by_subject = q.by_subject()
    overlaps = []
    for subject_id, findings in by_subject.items():
        tools = {f.tool for f in findings}
        if len(tools) < 2:
            continue
        worst = max(SEVERITY_RANK.get(f.severity, 0) for f in findings)
        overlaps.append({
            "subject": findings[0].subject,
            "tools": sorted(tools),
            "findings": findings,
            "worst_severity_rank": worst,
            "tool_count": len(tools),
        })
    overlaps.sort(key=lambda o: (o["worst_severity_rank"], o["tool_count"]), reverse=True)
    return overlaps


def owned_privileged_apps():
    """Over-privileged apps whose owner is a user with an attack path.

    Returns each dangerous app paired with the risky owners and the
    attack-path findings that make those owners risky.
    """
    q = _query()

    # Attack-path findings indexed by the user subject id they concern.
    attack_by_user = {}
    for f in q.all(tool="attack-path"):
        attack_by_user.setdefault(f.subject.id, []).append(f)

    results = []
    for f in q.all(tool="workload-identity"):
        owner_ids = f.evidence.get("owner_ids") or []
        if not owner_ids:
            continue
        risky_owners = []
        for oid in owner_ids:
            paths = attack_by_user.get(oid)
            if paths:
                risky_owners.append({
                    "owner_id": oid,
                    "owner_name": paths[0].subject.display_name,
                    "attack_findings": paths,
                })
        if risky_owners:
            results.append({
                "app": f.subject,
                "app_finding": f,
                "risky_owners": risky_owners,
            })

    # Worst first: critical apps with the most risky owners
    results.sort(
        key=lambda r: (SEVERITY_RANK.get(r["app_finding"].severity, 0), len(r["risky_owners"])),
        reverse=True,
    )
    return results


def ownerless_privileged_apps():
    """Over-privileged apps with no owner at all.

    An over-privileged app that nobody owns is its own risk: no
    accountable party, harder to govern, and a standing escalation
    target. The workload scanner flags the privilege and the missing
    owner separately; the orchestrator surfaces the dangerous
    combination.
    """
    q = _query()
    results = []
    for f in q.all(tool="workload-identity"):
        if f.rule not in ("tier0-application-permission", "broad-data-permission"):
            continue
        if f.evidence.get("owner_ids"):
            continue
        results.append({"app": f.subject, "app_finding": f})
    results.sort(
        key=lambda r: SEVERITY_RANK.get(r["app_finding"].severity, 0),
        reverse=True,
    )
    return results


if __name__ == "__main__":
    print("=== Subject overlap (flagged by multiple tools) ===")
    overlaps = correlated_subjects()
    if not overlaps:
        print("  none\n")
    else:
        for o in overlaps:
            print(f"  {o['subject'].display_name}: {', '.join(o['tools'])}")
        print()

    print("=== Ownership join (dangerous app owned by a risky user) ===")
    owned = owned_privileged_apps()
    if not owned:
        print("  none")
    else:
        for r in owned:
            app = r["app"]
            print(f"  {app.display_name} [{r['app_finding'].severity}] - {r['app_finding'].title}")
            for ro in r["risky_owners"]:
                paths = ro["attack_findings"]
                print(f"      owned by {ro['owner_name']}: {len(paths)} attack-path finding(s)")
                for pf in paths[:2]:
                    print(f"        - {pf.title}")

    from report import render_report
    _out = render_report(owned_privileged_apps(), ownerless_privileged_apps())
    print(f"\nReport written to {_out}")
