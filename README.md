# entra-orchestrator

⚠️ Under active development. Core correlation works; HTML reporting and live scan orchestration are in progress.

Cross-tool correlation for the Entra ID security suite. Reads findings from three independent scanners and surfaces risks that no single tool can see on its own.

## Why

Each scanner in the suite sees one dimension of tenant risk:

- **[entra-workload-identity-scanner](https://github.com/Dfrank77/entra-workload-identity-scanner)** knows which apps hold dangerous permissions.
- **[entra-attack-path-visualizer](https://github.com/Dfrank77/entra-attack-path-visualizer)** knows which users can escalate to privileged roles.
- **[entra-zt-policy-engine](https://github.com/Dfrank77/entra-zt-policy-engine)** knows which Conditional Access controls are missing.

Run separately, each produces its own report. None of them answers the question that actually matters: *is a dangerous app controlled by a compromisable identity?*

The orchestrator answers it by joining findings across tools.

## How

All three scanners write findings in a shared schema ([entra-security-report](https://github.com/Dfrank77/entra-security-report)) to a common store. The orchestrator reads that store and correlates:

**Ownership join** — for every over-privileged application, resolve its owners and check whether any owner is a user the attack-path scanner flags as having a privilege escalation path. Where they match, the dangerous app is owned by a compromisable identity: a real attack chain that neither tool reports alone.

## Example output

Okta-Provisioning-01 [critical] — Holds RoleManagement.ReadWrite.Directory, owned by a user who inherits Application Administrator via group membership.

The workload scanner flagged the app. The attack-path scanner flagged the user. Only the join reveals that the user who can be escalated to Application Administrator owns an app that can rewrite directory roles.

## Usage

Requires the shared store populated by the three scanners (set \`ENTRA_FINDINGS_DIR\` and run each scanner), plus the shared \`entra_security_report\` library on the path. Then run \`python correlate.py\`.
