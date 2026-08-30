# AD-Enum Findings Guide

AD-Enum is a read-only assessment and enumeration tool. A finding is an
observation that needs environmental context: the affected account, object,
service, permissions, business purpose, and compensating controls all matter.
`CONFIRMED` means the relevant evidence was actually observed by the collector;
it does not mean that compromise was demonstrated. Inventory or service
presence alone is not necessarily a vulnerability.

Use the report's affected objects, evidence, source artifacts, and coverage
state when triaging. Validate with the least intrusive method that answers the
question. Do not change production data or use recovered credentials merely to
prove impact.

## Active Directory Certificate Services (ADCS)

### What it means

AD-Enum reports native ESC1 conditions and vulnerability identifiers returned by
the Certipy collector. ESC1 requires the combination shown in the evidence,
including subject/SAN supply, an authentication-capable policy, effective
enrollment rights, and no approval or signature gate.

### Why it matters

An enrollee with the required rights may be able to obtain a certificate that
authenticates as another identity. The consequence depends on template scope,
CA publication, enrollment ACLs, and the identity represented by the
certificate.

### Safe validation

Review the named template, CA, EKUs/application policies, publication state,
ACL evidence, and approval settings. Corroborate a Certipy result with the
native evidence where possible. Do not request certificates or perform
authentication tests as another identity.

### Remediation

Remove unnecessary enrollment rights, prevent unauthorized subject/SAN supply,
require approval or authorized signatures where appropriate, and unpublish or
retire templates that are not needed. Review CA and template ACLs after each
change.

## Kerberos and account/LDAP secret exposure

### What it means

The report may identify `AS-REP-roastable`, `Kerberoastable-account`,
`PASSWD_NOTREQD`, `des-only-kerberos`, `reversible-password-encryption`,
`password-never-expires`, `stale-privileged-account`, or
`ldap-attribute-secret`. The last rule requires explicit value-bearing
credential, token, or secret-like content in selected AD text attributes;
keywords or an attribute name alone are not enough. Disabled accounts may
remain in evidence but are suppressed from the normal actionable finding view.

### Why it matters

These settings can make authentication material easier to obtain or weaken
account protection. Risk is higher for enabled service, privileged, or
long-lived accounts, and lower when an account is disabled or tightly scoped.

### Safe validation

Confirm the account's enabled state, SPNs, privilege, password age, and the
reported directory flags using read-only directory review. For
`ldap-attribute-secret`, confirm the attribute, account, and actual value in
the protected artifact. Do not request service tickets for testing, crack
material, or attempt logon with discovered data.

### Remediation

Use managed service accounts where suitable, rotate exposed or old passwords,
remove unnecessary SPNs and legacy encryption settings, require passwords where
appropriate, and disable or remove stale privileged accounts. Set expiration
and password-protection controls according to the account's role.

## Delegation

### What it means

AD-Enum reports unconstrained, constrained, protocol-transition, or resource-
based constrained delegation (`rbcd`) relationships, with the relevant target
and, for RBCD, allowed principal evidence.

### Why it matters

Delegation can allow a trusted service or principal to act to a Kerberos service
as another identity. An overly broad or low-privilege-controlled delegation
relationship may enable privilege escalation.

### Safe validation

Review the delegation attributes, target service, allowed principals, and
whether the relationship is required. Treat expected domain-controller
relationships as context and verify them against the intended design. Do not
request delegated tickets or impersonate users.

### Remediation

Remove unnecessary delegation, restrict allowed principals to dedicated service
accounts or hosts, avoid unconstrained delegation for ordinary systems, and
protect accounts that can modify delegation-related attributes.

## ACL and dangerous directory rights

### What it means

The report identifies a low-privilege principal with effective rights such as
group-membership modification, password reset, `servicePrincipalName` write,
DACL modification, or ownership change on a high-value object. GPO modification
is reported separately as `gpo-modify`.

### Why it matters

These rights can change identity, authorization, authentication, or policy
objects. Impact depends on the exact principal, inheritance, target, and
whether the target controls privileged access.

### Safe validation

Review the effective-rights and ACE evidence, including inherited scope and
principal group membership. Confirm that the access is intentional with the
object owner. Do not modify memberships, passwords, SPNs, owners, or ACLs to
demonstrate control.

### Remediation

Remove unnecessary ACEs and nested-group paths, delegate only the smallest
required right, review inheritance, and monitor changes to privileged objects
and GPOs.

## GPO and SYSVOL credential exposure

### What it means

AD-Enum reports `gpp-cpassword` when it observes a Group Policy Preferences
`cpassword` value, and `gpo-cleartext-credential` when it observes
credential-like content in inspected GPO files. The report preserves the
observed value and file context; a `cpassword` is not described as plaintext
or decoded unless the implementation says so.

### Why it matters

Policy files are commonly readable by domain users and may expose credentials
to more principals than intended. The account's privileges and whether the
secret is still valid determine the practical impact.

### Safe validation

Confirm the GPO, SYSVOL path, file, account, and exact secret-like content from
the protected report artifacts. Keyword matches without an actual value are not
equivalent to a recovered credential. Do not reuse or test the value.

### Remediation

Remove secrets from GPO and SYSVOL material, rotate any affected credential,
replace legacy preference items with supported protected mechanisms, and review
replication and access to historical policy files.

## SMB shares and signing

### What it means

Share access is rendered as `READ`, `READ / WRITE`, `DENIED`, or `UNKNOWN`.
`writable-share` is a finding for an observed writable non-administrative share;
`anonymous-share-enumeration` reports unauthenticated share enumeration.
`signing-not-required` reports hosts where SMB signing was observed as not
required.

### Why it matters

Read access can disclose sensitive data. Write access can become security-
relevant when privileged users, deployment systems, services, or automated
processes consume files there. Missing signing can increase exposure to
tampering or relay when other prerequisites exist.

### Safe validation

Confirm the share, UNC path, identity, and permissions. Identify downstream
consumers and data sensitivity without uploading files or changing production
content. `ADMIN$`, `C$`, and equivalent administrative shares are not
automatically low-privilege writable-share findings.

### Remediation

Apply least-privilege share and filesystem ACLs, remove unnecessary write
access, separate deployment content from user-writable locations, and require
SMB signing where operationally supported.

## LDAP security

### What it means

`anonymous-directory-enumeration` means unauthenticated directory data was
readable. `ldap-signing-not-required` means the observed LDAP posture does not
require signing; AD-Enum does not claim that a relay was performed.

### Why it matters

Anonymous directory data can aid reconnaissance. LDAP without required signing
may permit tampering or relay in environments where the other protocol and
authentication prerequisites are present.

### Safe validation

Repeat the bounded anonymous query or inspect the native posture evidence.
Review LDAP channel-binding and signing policy with the directory team. Do not
run relay, coercion, or write tests.

### Remediation

Disable unnecessary anonymous directory reads and require LDAP signing and
appropriate channel binding on domain controllers and clients, accounting for
legacy dependencies before enforcement.

## Relay exposure paths

### What it means

`relay-path` is a safe-mode inventory observation of a potential NTLM relay
destination, often combined with a host where SMB signing is not required. It
is a path hypothesis, not proof that relay succeeded.

### Why it matters

If protocol, signing, authentication, and privilege prerequisites align, NTLM
authentication may be relayed to a service.

### Safe validation

Review the Relay inventory, destination protocol, signing posture, and service
configuration with owners. Keep validation read-only; do not coerce clients,
capture authentication, or attempt relay.

### Remediation

Prefer Kerberos, reduce NTLM where feasible, require SMB signing, enforce LDAP
signing/channel binding, and apply service-specific protections to identified
destinations.

## Domain and password policy

### What it means

The report may identify `password-complexity` disabled or a minimum password
length below eight characters.

### Why it matters

Weak domain policy increases the chance that guessed or obtained passwords are
usable, especially for privileged and service accounts.

### Safe validation

Confirm the canonical policy and its source in the report. Consider fine-
grained password policies and exceptions before judging the effective control.

### Remediation

Enable appropriate complexity and length requirements, use stronger controls
for privileged/service identities, and review exceptions and policy precedence.

## SCCM / MECM and CRED-1

### What it means

AD-Enum uses CinderPath as its specialized CRED-1 adapter. A confirmed `CRED-1`
result means PXE/SCCM policy material allowed credential recovery. The recovered
target credential is operator evidence and must be treated as credential
exposure.

### Why it matters

Credentials embedded in task-sequence or policy material may grant access well
beyond the deployment workflow, depending on the account and scope.

### Safe validation

Reproduce the read-only CRED-1 assessment against the reported distribution
point and confirm the same policy/credential exposure. Do not use the recovered
credential to authenticate elsewhere merely to prove impact.

### Remediation

Remove exposed credentials from task-sequence and policy material, rotate every
recovered credential, review PXE/SCCM exposure and affected task sequences, and
confirm that old policy material no longer exposes the secret.

## Authenticated access and service authorization

### What it means

`AUTHENTICATED` means the supplied scanner identity successfully authenticated
to the reported service. It does not by itself mean administrator, code
execution, full control, or compromise. Explicit `ADMIN` or `ELEVATED` evidence
is stronger than authentication success alone; `UNKNOWN` privilege remains
unknown.

### Why it matters

Unexpected authentication expands the reachable attack surface and may expose
service data, but authorization is service- and role-specific.

### Safe validation

Use authentication-only checks and review the service's authorization mapping.
Avoid command execution or administrative changes merely to verify the result.

### Remediation

Remove unnecessary service logon rights, restrict remote access, harden
high-value hosts, and review service-specific authorization and group
membership.

## MSSQL / TDS service observations

### What it means

The service view distinguishes a TCP port open, `TDS CONFIRMED` after a bounded
TDS PRELOGIN exchange, and scanner authentication success or denial. A SQL
service being present or reachable is inventory, not automatically a
vulnerability.

### Why it matters

An exposed database may be sensitive, and weak authorization can increase risk,
but impact requires evidence about authentication, roles, network scope, and
data.

### Safe validation

Use TDS PRELOGIN and, where authorized, authentication-only or metadata checks.
Do not execute commands, invoke `xp_cmdshell`, or alter database contents.

### Remediation

Restrict network exposure, require appropriate encryption and authentication,
remove unnecessary logins and roles, and apply service-specific hardening and
patching.

## DFS namespaces and links

### What it means

AD-Enum collects DFS namespace/link objects from LDAP and correlates reported
targets with observed SMB access. `READ / WRITE`, `READ`, `DENIED`, and
`UNKNOWN` describe the observed target share access; DFS publication alone is
not a vulnerability.

### Why it matters

DFS can direct users and automated processes to file locations whose access or
content deserves review. A writable target is more significant when trusted
consumers use it.

### Safe validation

Confirm the namespace, link, target, and correlated SMB access. Identify
consumers and ownership without crawling or changing target content.

### Remediation

Remove stale links and targets, restrict target-share permissions, and ensure
deployment or privileged consumers do not rely on user-writable locations.

## Trusts, foreign principals, DNS, and LAPS inventory

### What it means

These are primarily inventory and context in the current implementation:
trusted-domain relationships and foreign security principals, DNS/host mapping,
and LAPS schema/authorization observations. They do not automatically create a
normalized vulnerability finding.

### Why it matters

Unexpected trusts, external principals, name-resolution exposure, or broad LAPS
read authorization can be security-relevant in context.

### Safe validation

Compare each relationship, principal, DNS record, and LAPS authorization with
the approved architecture and ownership. Use read-only directory and DNS
review; do not alter trusts, records, or passwords.

### Remediation

Remove obsolete trust paths and foreign principals, correct stale DNS data,
and restrict LAPS password-reading rights to the administrators and devices
that require them.

## Interpreting coverage and zero results

`COMPLETE` (or a capability-specific `PASS`) with zero observations means the
collection completed and nothing matching that check was found. It is not proof
that every object or control in the environment is secure.

`PARTIAL`, `NOT TESTED`, `NOT RUN`, `NOT CHECKED`, `NOT AVAILABLE`, and `FAILED`
indicate a collection limitation, unavailable dependency, intentionally skipped
check, or failure. Read the detail in `coverage.json`, `scan.json`, and the
module artifacts before treating an empty finding set as meaningful assurance.

## Useful references

- Microsoft documentation for [Active Directory Certificate Services](https://learn.microsoft.com/windows-server/identity/ad-cs/active-directory-certificate-services-overview), [LDAP signing](https://learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing), and [SMB signing](https://learn.microsoft.com/windows-server/storage/file-server/smb-signing).
- MITRE ATT&CK technique names for [Kerberoasting (T1558.003)](https://attack.mitre.org/techniques/T1558/003/) and [AS-REP Roasting (T1558.004)](https://attack.mitre.org/techniques/T1558/004/).
