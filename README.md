# Entra ID Attack Path Visualizer

Scans a Microsoft Entra ID tenant via Microsoft Graph, detects privilege escalation paths through direct role assignments, group memberships, and PIM eligible assignments, and produces a structured HTML report.

Part of a three-tool portfolio built on the shared [`entra-security-report`](https://github.com/Dfrank77/entra-security-report) library, alongside [`entra-workload-identity-scanner`](https://github.com/Dfrank77/entra-workload-identity-scanner) and [`entra-zt-policy-engine`](https://github.com/Dfrank77/entra-zt-policy-engine).

![Sample report](docs/privilege_report_screenshot.jpeg)

## The Problem

Organizations lose track of who has administrative privileges in Entra ID:

- **Shadow admins** inherit admin access through nested group memberships without anyone realizing it
- **PIM blind spots**: users with eligible (not yet activated) roles do not show up in standard directory role queries, but they can activate to admin at any time
- **Role sprawl**: multiple users and groups assigned to privileged roles unnecessarily
- **Manual reviews miss indirect paths**: a user in a group that is assigned Global Administrator is a Global Administrator, but that does not show up in the user's direct role assignments

Manual review of hundreds of users and groups takes 40+ hours per quarter. This tool automates it in under 5 minutes.

## What It Detects

Each escalation path is emitted as a structured finding with stable identity across scans, allowing the tool to answer "what is new since last run" and "what got fixed."

| Rule | Severity | What it means |
|---|---|---|
| direct-role-assignment (HIGH-risk role) | critical | User directly holds a tier-0 admin role like Global Administrator or Privileged Role Administrator |
| direct-role-assignment (MEDIUM-risk role) | high | User directly holds a mid-tier admin role |
| transitive-role-via-group (HIGH-risk role) | critical | User inherits a tier-0 role through group membership |
| transitive-role-via-group (MEDIUM-risk role) | high | User inherits a mid-tier role through group membership |
| pim-eligible-direct (HIGH-risk role) | high | User is PIM-eligible for a tier-0 role, dormant privilege they can activate |
| pim-eligible-via-group (HIGH-risk role) | high | User is PIM-eligible through group membership |
| pim-eligible-direct or pim-eligible-via-group (MEDIUM-risk) | medium | Same as above for mid-tier roles |

Findings persist across scans in `.findings/` via the shared reporting library. Re-running the scanner produces automatic diffs: `X new since last run`, `Y fixed since last run`.

## Output

One artifact is generated: `output/privilege_report.html` — a structured card-based report matching the other two tools. One card per subject (user), findings grouped by highest severity, colored by tier.

## Installation

### Prerequisites

- Python 3.10+
- Microsoft Entra ID tenant with admin read access
- Entra ID P2 license (for PIM eligible role scanning)

### Setup

    git clone https://github.com/Dfrank77/entra-attack-path-visualizer.git
    cd entra-attack-path-visualizer
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    pip install git+https://github.com/Dfrank77/entra-security-report.git

If you have the shared library locally, use `pip install -e ../entra-security-report` instead.

### Microsoft Graph Permissions Required

| Permission | Why |
|---|---|
| User.Read.All | Read all user profiles |
| Group.Read.All | Read all group memberships |
| Directory.Read.All | Read directory data |
| RoleManagement.Read.All | Read role assignments |
| RoleManagement.Read.Directory | Read directory role definitions |
| RoleEligibilitySchedule.Read.Directory | Read PIM eligible role assignments |

## Usage

    source venv/bin/activate
    python entra_scanner.py
    python visualizer.py
    open output/privilege_report.html

### What Happens

1. Scanner authenticates via browser, enumerates users, groups, active role assignments, and PIM eligible assignments. Every escalation path becomes a `Finding` object with severity mapped from role tier and assignment type. Findings persist to `.findings/`.
2. Visualizer reads the latest scan from storage and renders the structured HTML report through the shared `render()` function.

## Architecture

- `entra_scanner.py`: scanner, emits Finding objects, persists to shared storage
- `visualizer.py`: reads latest scan, produces structured HTML report
- `output/`: generated report (gitignored)
- `.findings/`: persisted findings and scan history (gitignored)

### Design decisions worth calling out

**Findings are structured, not display strings.** Each path is a Finding with a subject (the user), evidence (the full path array plus type), and severity mapped from HIGH/MEDIUM risk times active/eligible assignment. The workload scanner and ZT engine produce findings in the same schema, which is what enables cross-tool correlation.

**Severity mapping.** HIGH-risk role + active = critical. HIGH-risk role + eligible = high. MEDIUM-risk role + active = high. MEDIUM-risk role + eligible = medium. This is the "direct + privileged = urgent, dormant + mid-tier = watch" logic explicit in code rather than left as text.

**PIM queries use aiohttp directly.** The Graph SDK's `roleEligibilitySchedules` support is unreliable. Rather than fight SDK bugs, the scanner makes direct REST calls using aiohttp with a raw bearer token. Async is required because the Graph SDK is async-only.

## Author

**Darius Frank** — IAM & Cloud Security

- GitHub: [@Dfrank77](https://github.com/Dfrank77)
- LinkedIn: [Darius Frank](https://www.linkedin.com/in/darius-frank/)

## License

MIT — see [LICENSE](LICENSE)

## Disclaimer

This tool is for authorized security assessments and compliance audits only. You must have appropriate permissions to scan your Entra ID environment. Unauthorized access to systems is illegal.
