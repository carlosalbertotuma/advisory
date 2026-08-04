# Security Advisories — bl4dsc4n

Public disclosure repository for independently discovered vulnerabilities in open-source software and web applications.

This repository contains security advisories for vulnerabilities discovered through manual source code review, vulnerability research, and dynamic security testing.

All CVE identifiers were assigned by the appropriate CVE Numbering Authority (CNA) following responsible and coordinated disclosure practices with affected vendors or projects.

---

## Researcher

| Field | Value |
|---|---|
| Discoverer | Carlos Tuma (bl4dsc4n) |
| Affiliation | RedScan Academy / 0ff3ns!v3 S3cur!ty Community |
| Research Focus | Web Application Security, Red Team Operations, Vulnerability Research |
| Disclosure Policy | Responsible / Coordinated Disclosure through vendor channels or CNA process |

---

# CVE Index

## Discovered Vulnerabilities

| CVE ID | Type | Severity | Product |
|---|---|---|---|
| CVE-2026-2058 | TBD | TBD | TBD |
| CVE-2025-56713 | TBD | TBD | TBD |
| CVE-2025-56714 | TBD | TBD | TBD |
| CVE-2025-56716 | TBD | TBD | TBD |
| CVE-2025-56719 | TBD | TBD | TBD |
| CVE-2025-56720 | TBD | TBD | TBD |
| CVE-2025-56721 | TBD | TBD | TBD |
| CVE-2025-56722 | TBD | TBD | TBD |
| CVE-2025-56723 | TBD | TBD | TBD |
| CVE-2025-56724 | TBD | TBD | TBD |
| CVE-2025-56725 | TBD | TBD | TBD |
| CVE-2025-56727 | TBD | TBD | TBD |
| CVE-2025-56728 | TBD | TBD | TBD |
| CVE-2025-56729 | TBD | TBD | TBD |
| CVE-2025-56730 | TBD | TBD | TBD |
| CVE-2025-56731 | TBD | TBD | TBD |
| CVE-2025-56732 | TBD | TBD | TBD |
| CVE-2025-56733 | TBD | TBD | TBD |
| CVE-2025-56734 | TBD | TBD | TBD |
| CVE-2025-56735 | TBD | TBD | TBD |
| CVE-2025-56736 | TBD | TBD | TBD |
| CVE-2025-56737 | TBD | TBD | TBD |
| CVE-2025-56738 | TBD | TBD | TBD |
| CVE-2025-56739 | TBD | TBD | TBD |
| CVE-2025-56741 | TBD | TBD | TBD |
| CVE-2025-56742 | TBD | TBD | TBD |
| CVE-2025-56744 | TBD | TBD | TBD |
| CVE-2025-61561 | TBD | TBD | TBD |
| CVE-2025-61562 | TBD | TBD | TBD |
| CVE-2025-61563 | TBD | TBD | TBD |
| CVE-2025-61565 | TBD | TBD | TBD |
| CVE-2025-61566 | TBD | TBD | TBD |
| CVE-2025-61567 | TBD | TBD | TBD |
| CVE-2025-61568 | TBD | TBD | TBD |
| CVE-2025-61569 | TBD | TBD | TBD |
| CVE-2025-61570 | TBD | TBD | TBD |

---

# Research Summary

This repository contains **36 CVEs** discovered during independent security research.

The vulnerabilities include multiple classes of security issues commonly found in web applications, including:

- **SQL Injection**  
  Injection flaws caused by insufficient input validation and unsafe database query construction.

- **Cross-Site Scripting (XSS)**  
  Client-side code execution vulnerabilities affecting application interfaces through unsafe handling of user-controlled data.

- **Broken Access Control / IDOR / BOLA**  
  Authorization weaknesses allowing unauthorized access or manipulation of application resources.

- **Improper Authorization**  
  Missing or insufficient privilege validation enabling unauthorized actions.

- **Remote Code Execution (RCE)**  
  Vulnerabilities allowing server-side code execution through insecure application functionality.

- **Server-Side Request Forgery (SSRF)**  
  Issues allowing attackers to influence server-side requests and interact with internal resources.

- **File Upload Vulnerabilities**  
  Improper validation of uploaded files leading to security impact.

- **Other Web Application Security Issues**  
  Additional vulnerabilities identified through source code analysis and security testing.

---

# Research Methodology

All vulnerabilities were identified using a combination of:

- Manual source code review
- Secure code analysis
- Authentication and authorization testing
- Dynamic application testing
- API endpoint analysis
- Input validation assessment
- Business logic testing

Testing was performed against controlled environments and local deployments of affected applications.

No unauthorized access to production systems was performed during research.

---

# Disclosure Process

All vulnerabilities were reported responsibly to affected vendors and maintainers.

The disclosure process followed coordinated vulnerability disclosure principles:

1. Vulnerability identification
2. Technical validation and impact assessment
3. Private notification to affected parties
4. Remediation coordination
5. Public disclosure after appropriate disclosure timelines

CVE identifiers were assigned through the official CVE program.

---

# Researcher Profile

**Carlos Tuma (@bl4dsc4n)**

Security Researcher focused on:

- Web Application Security
- Red Team Operations
- Vulnerability Research
- Offensive Security
- Secure Code Review

Founder of:

**RedScan Academy**  
**0ff3ns!v3 S3cur!ty Community**

---

# License

These advisories are published for educational and defensive security purposes.

The repository does not include weaponized exploit frameworks or automated exploitation tools.

The objective is to improve software security awareness, assist defenders, and provide technical documentation of discovered vulnerabilities.
