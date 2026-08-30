# AD-Enum 1.0.0

AD-Enum 1.0.0 is a read-only Active Directory assessment release.

Highlights:

- Native AD inventory, AD CS, Kerberos, delegation, ACL, GPO/SYSVOL, LDAP,
  DNS, trust, and security-posture collection.
- SMB share inventory and writable-share evidence.
- SCCM/MECM topology and automatic CRED-1 assessment through CinderPath.
- MSSQL/TDS service validation and DFS LDAP namespace/link collection.
- Current-identity access validation with explicit authentication failure
  states.
- Consolidated text, JSON, credential, findings, coverage, and optional HTML
  reports.

The release is intended for authorized assessments and defensive review. It
does not perform password cracking, spraying, deployment execution, writes, or
exploitation. Some checks depend on target permissions, external tool
availability, and network observability; CRED-1 requires a suitable local
Ethernet/PXE capture path.
