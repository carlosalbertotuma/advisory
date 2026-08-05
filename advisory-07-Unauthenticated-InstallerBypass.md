# Security Advisory — Unauthenticated Installer Bypass Leading to Super Administrator Account Takeover

## Overview

**Title:** Unauthenticated Installer Bypass Leading to Super Administrator Account Takeover  
**Product:** Krayin CRM  
**Affected Version:** 2.2.4  
**Vulnerability Type:** Authentication Bypass / Improper Access Control / Installer Exposure After Installation  
**CWE-306:** Missing Authentication for Critical Function  
**CWE-284:** Improper Access Control  
**CWE-863:** Incorrect Authorization  
**CVE:** Pending

---

# CVE Description

Krayin CRM 2.2.4 contains an authentication bypass vulnerability in the installer component. After the application has been installed, the installer remains accessible through its AJAX API endpoints. An unauthenticated remote attacker can bypass the installation protection by sending the `X-Requested-With: XMLHttpRequest` header and invoke installer endpoints without authentication. The exposed `POST /install/api/admin-config-setup` endpoint updates the existing super administrator account, allowing an attacker to replace the administrator's username, email address, and password, resulting in complete administrative account takeover.

---

# Severity

**CVSS v3.1 Base Score:** 9.8 (Critical)

**Vector:**

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

---

# Affected Component

- Installer Middleware (`CanInstall`)
- Installer API
- Administrative Configuration Endpoint

Affected endpoint:

```
POST /install/api/admin-config-setup
```

---

# Technical Details

The installer is intended to become inaccessible once the application has been successfully installed.

The protection implemented by the `CanInstall` middleware only blocks standard HTTP requests after installation. However, the middleware explicitly allows AJAX requests identified by the `X-Requested-With: XMLHttpRequest` header.

As a result:

- Visiting `/install` normally redirects the user away from the installer.
- Sending the same request as an AJAX request bypasses the middleware.
- All installer API endpoints remain reachable without authentication.

One of these endpoints is:

```
POST /install/api/admin-config-setup
```

This endpoint performs an `updateOrInsert()` operation on the administrator record (User ID 1), replacing the existing administrator information with attacker-controlled values.

An unauthenticated attacker can therefore overwrite:

- Administrator name
- Administrator email
- Administrator password

The attacker can immediately authenticate using the newly created credentials and obtain full administrative access to the application.

Additional installer API endpoints also remain exposed after installation and may allow further modification of application settings or installation-related operations.

---

# Impact

A remote unauthenticated attacker can:

- Bypass installer restrictions.
- Access installer functionality after deployment.
- Replace the existing super administrator credentials.
- Take over the administrator account.
- Gain complete administrative privileges.
- Modify application configuration.
- Fully compromise the CRM instance.

Successful exploitation results in complete loss of confidentiality, integrity, and availability.

---

# Root Cause

The installer protection depends on whether the request is identified as an AJAX request rather than verifying that the installer has been permanently disabled after installation.

Security-sensitive installer functionality remains reachable after deployment, exposing privileged administrative operations without authentication.

---

# Proof of Concept (PoC)

Replace the administrator account without authentication:

```bash
curl -i -X POST "http://TARGET/install/api/admin-config-setup" \
  -H "X-Requested-With: XMLHttpRequest" \
  --data-urlencode "admin=PwnedAdmin" \
  --data-urlencode "email=attacker@evil.com" \
  --data-urlencode "password=Pwned12345"
```

After execution:

- The administrator account is updated.
- The attacker can authenticate using the supplied credentials.
- Full administrative access is obtained.

---

# Remediation

The installer should never remain accessible after installation.

Recommended fixes include:

- Permanently disable all installer routes after installation.
- Remove installer API endpoints from the routing table once setup has completed.
- Require authentication and proper authorization for any maintenance functionality.
- Eliminate any security decisions based on the `X-Requested-With` header.
- Ensure installer endpoints cannot be reached regardless of request type.

---

# Security Impact

- Authentication Bypass
- Administrative Account Takeover
- Full Application Compromise
- Privilege Escalation
- Unauthorized Configuration Modification

---

# CWE Classification

- **CWE-306** — Missing Authentication for Critical Function
- **CWE-284** — Improper Access Control
- **CWE-863** — Incorrect Authorization

---

# CVSS v3.1

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality | High |
| Integrity | High |
| Availability | High |

**Base Score:** **9.8 (Critical)**

---

# Timeline

- Vulnerability discovered during security assessment.
- Vendor notified through responsible disclosure.
- CVE Identifier: Pending.
```
