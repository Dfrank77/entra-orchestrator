# Case Study: From Compromised User to Full Tenant Takeover in Three Steps

## Overview

During a multi-tenant security assessment of a simulated enterprise environment, the Entra Orchestrator correlated findings across three independent scanners and surfaced a critical attack chain. A single compromised user account could escalate to full tenant control through an overprivileged application registration.

This write-up walks through the finding, explains why each link in the chain matters, and details the remediation.

## Environment

Two Entra ID tenants connected via Cross-Tenant Synchronization:

- **WorkforceLab** (source): 751 users, 52 groups, 201 apps -- simulates a central workforce directory
- **dfrank-iam** (target): 567 users (250 native + 300 synced from WorkforceLab), 57 groups, 71 apps -- simulates a managed tenant receiving external identities

The scanners ran against dfrank-iam, the tenant where internal resources and cross-tenant identities converge.

## The Finding

**Severity:** Critical

**Application:** Okta-Provisioning-01

**Permission:** `RoleManagement.ReadWrite.Directory` (application-level)

**Owner:** Omar Delgado

**Omar Delgado's group memberships:**
- SG-Application-Owners (inherits Application Administrator)
- SG-IT-Admins (inherits Helpdesk Administrator)

## The Attack Chain

### Step 1: Compromise the user

Omar Delgado is a regular employee who belongs to two security groups. He has no direct admin role assignment, so he looks low-risk at first glance. But his group memberships give him two inherited directory roles, including Application Administrator.

An attacker compromises Omar's account through phishing, credential stuffing, or session hijacking. Because there is no Conditional Access policy requiring MFA for admin roles (also flagged in this assessment), the attacker authenticates without a second factor.

### Step 2: Abuse Application Administrator to modify the app

As an Application Administrator and owner of Okta-Provisioning-01, Omar (now the attacker) can:

- Add a new client secret to the application
- Modify the application's redirect URIs
- Consent to additional permissions

The attacker generates a new client secret for Okta-Provisioning-01 and authenticates as the application's service principal.

### Step 3: Use the app's permissions to take over the tenant

Okta-Provisioning-01 holds `RoleManagement.ReadWrite.Directory` as an application permission. This permission allows the holder to assign any directory role to any principal, including Global Administrator.

The attacker, now operating as the Okta-Provisioning-01 service principal, calls the Microsoft Graph API to assign the Global Administrator role to their own user account (or a new account they create). They now have full control of the tenant.

**Total steps from compromised user to Global Admin: 3**

## Why the Orchestrator Caught This

No single scanner detected the full chain:

- The **Workload Identity Scanner** flagged Okta-Provisioning-01 as critical because it holds `RoleManagement.ReadWrite.Directory`. But it does not analyze who owns the app or what roles those owners hold.
- The **Attack Path Visualizer** flagged Omar Delgado's transitive role inheritance through SG-Application-Owners and SG-IT-Admins. But it does not examine which applications those users own or what permissions those apps hold.
- The **Zero Trust Policy Engine** flagged the missing MFA policy for admin roles. But it does not connect that gap to specific users or applications.

The Orchestrator joined the ownership data from the Workload Identity Scanner with the privilege escalation paths from the Attack Path Visualizer. It identified that the owner of a Tier 0 application also has an escalation path to Application Administrator, which means the same person who can modify the app's credentials already has the directory role required to do so.

## Remediation

1. **Remove `RoleManagement.ReadWrite.Directory` from Okta-Provisioning-01.** This permission is almost never needed for SCIM provisioning. Replace it with the minimum scoped permissions the integration actually requires (typically `User.ReadWrite.All` and `Group.ReadWrite.All`).

2. **Remove Omar Delgado as owner of Okta-Provisioning-01.** Application ownership should be assigned to a service account or a small, tightly controlled admin group, not to individual employees who hold other privileged roles.

3. **Restrict the SG-Application-Owners group.** Review membership and remove users who do not need Application Administrator. Consider breaking this into scoped groups per application rather than one group that grants blanket app admin.

4. **Enforce MFA for all admin roles via Conditional Access.** This was flagged separately by the Zero Trust Policy Engine. Requiring MFA for any user with a directory role assignment (direct or inherited) would block the initial compromise from escalating.

5. **Implement Privileged Identity Management (PIM) for Application Administrator.** Make the role eligible rather than permanently assigned, requiring just-in-time activation with approval and MFA.

## Conclusion

This finding demonstrates why cross-tool correlation matters. The dangerous configuration was not a single misconfiguration but a combination of three independently reasonable decisions: an integration app with broad permissions, a convenience group that grants Application Administrator, and a missing Conditional Access policy. Each scanner saw one piece. The Orchestrator saw the chain.
