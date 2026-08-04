# Security Advisories — bl4dsc4n

Public repository containing security advisories, technical analyses, and Proof-of-Concepts (PoCs) for vulnerabilities independently discovered in open-source software.

All vulnerabilities were identified through manual source code review, secure code analysis, and dynamic application security testing in controlled laboratory environments. The research follows responsible disclosure practices, with technical details published after disclosure or CVE assignment.

---

# Researcher

| Field             | Value                                                      |
| ----------------- | ---------------------------------------------------------- |
| Researcher        | Carlos Tuma (bl4dsc4n)                                     |
| Organization      | RedScan Academy                                            |
| Community         | 0ff3ns!v3 S3cur!ty                                         |
| Research Focus    | Web Application Security, Red Team, Vulnerability Research |
| Disclosure Policy | Responsible / Coordinated Disclosure                       |

---

# Advisory Repositories

## Main Advisory Repository

**CLOUD-CLASSROOMS-php-1.0**

Technical documentation including:

* Root cause analysis
* Vulnerability details
* Affected source code
* Security impact
* Mitigation guidance
* CVE references

Repository

https://github.com/carlosalbertotuma/CLOUD-CLASSROOMS-php-1.0

---

## Proof-of-Concept Repository #1

Repository

https://github.com/carlosalbertotuma/Cloud-Classroom-PHP-1.0---Poc2

Covered Advisories

* CVE-2026-2058
* CVE-2025-56713

---

## Proof-of-Concept Repository #2

Repository

https://github.com/carlosalbertotuma/Cloud-ClassRooms-PHP-1.0-Poc3

Covered Advisories

* CVE-2025-56714
* CVE-2025-61561
* CVE-2025-61562
* CVE-2025-61563
* CVE-2025-61565
* CVE-2025-61566
* CVE-2025-61567
* CVE-2025-61568
* CVE-2025-61569
* CVE-2025-61570

---

## Dedicated PoC Repository

Repository

https://github.com/carlosalbertotuma/CVE-2026-2058-PoC

Contains the complete Proof-of-Concept for **CVE-2026-2058**, including vulnerable request, exploitation steps, technical analysis, and reproduction instructions.

---

# Public CVE Index

## CloudClassroom PHP Project 1.0

| CVE ID         | Vulnerability                        | CWE     | Affected Component             | Parameter |
| -------------- | ------------------------------------ | ------- | ------------------------------ | --------- |
| CVE-2026-2058  | SQL Injection                        | CWE-89  | Post Query (postquerypublic)   | `gnamex`  |
| CVE-2025-56713 | SQL Injection Authentication Bypass  | CWE-89  | `loginlinkstudent`             | `sid`     |
| CVE-2025-56714 | SQL Injection (UNION-Based)          | CWE-89  | `viewresult.php`               | `seno`    |
| CVE-2025-61561 | IDOR                                 | CWE-639 | `updatedetailsfromstudent.php` | `eno`     |
| CVE-2025-61562 | IDOR                                 | CWE-639 | `mydetailsfaculty.php`         | `myfid`   |
| CVE-2025-61563 | IDOR                                 | CWE-639 | `mydetailsstudent.php`         | `myds`    |
| CVE-2025-61565 | IDOR                                 | CWE-639 | `updatedetailsfromfaculty.php` | `myfid`   |
| CVE-2025-61566 | Reflected Cross-Site Scripting (XSS) | CWE-79  | `askquery.php`                 | `eid`     |
| CVE-2025-61567 | Reflected Cross-Site Scripting (XSS) | CWE-79  | `takeassessment2.php`          | `exid`    |
| CVE-2025-61568 | SQL Injection (UNION-Based)          | CWE-89  | `takeassessment2.php`          | `exid`    |
| CVE-2025-61569 | Stored Cross-Site Scripting (XSS)    | CWE-79  | `updatedetailsfromstudent.php` | Address   |
| CVE-2025-61570 | Stored Cross-Site Scripting (XSS)    | CWE-79  | `updatedetailsfromfaculty.php` | Address   |

---

# Reserved CVEs

The following CVE identifiers have been assigned and are currently reserved. Technical advisories will be published after the corresponding coordinated disclosure process has been completed.

* CVE-2025-56716
* CVE-2025-56719
* CVE-2025-56720
* CVE-2025-56721
* CVE-2025-56722
* CVE-2025-56723
* CVE-2025-56724
* CVE-2025-56725
* CVE-2025-56727
* CVE-2025-56728
* CVE-2025-56729
* CVE-2025-56730
* CVE-2025-56731
* CVE-2025-56732
* CVE-2025-56733
* CVE-2025-56734
* CVE-2025-56735
* CVE-2025-56736
* CVE-2025-56737
* CVE-2025-56738
* CVE-2025-56739
* CVE-2025-56741
* CVE-2025-56742
* CVE-2025-56744

---

# Research Statistics

## Assigned CVEs

| Status                  |  Count |
| ----------------------- | -----: |
| Public Advisories       | **1** |
| Reserved CVEs           | **35** |
| **Total Assigned CVEs** | **36** |

---

## Published Vulnerability Classes

| Class                          | Count |
| ------------------------------ | ----: |
| SQL Injection                  |     4 |
| Broken Access Control (IDOR)   |     4 |
| Reflected Cross-Site Scripting |     2 |
| Stored Cross-Site Scripting    |     2 |

---

# Research Methodology

The vulnerabilities documented in this repository were identified through:

* Manual source code review
* Secure code analysis
* Dynamic application security testing
* Authentication testing
* Authorization testing
* Business logic assessment
* Input validation analysis
* Manual Proof-of-Concept development

All testing was performed against locally deployed instances of the affected software.

No production systems were accessed during the research process.

---

# References

## National Vulnerability Database (NVD)

CVE-2026-2058

https://nvd.nist.gov/vuln/detail/CVE-2026-2058

---

## GitHub Proof-of-Concept

https://github.com/carlosalbertotuma/CVE-2026-2058-PoC

---

## Main Advisory

https://github.com/carlosalbertotuma/CLOUD-CLASSROOMS-php-1.0

---

## Additional Proof-of-Concepts

https://github.com/carlosalbertotuma/Cloud-Classroom-PHP-1.0---Poc2

https://github.com/carlosalbertotuma/Cloud-ClassRooms-PHP-1.0-Poc3

---

# Responsible Disclosure

Each published advisory includes:

* Vulnerability description
* Technical impact
* Root cause analysis
* Affected component
* Proof-of-Concept
* Reproduction steps
* Mitigation recommendations

Additional reserved CVEs will be published after completion of the coordinated disclosure process.

---

# Disclaimer

This repository is intended exclusively for educational, defensive, and security research purposes.

No weaponized exploit frameworks or offensive tooling are included.

The goal of this project is to promote responsible vulnerability disclosure, improve software security, and provide high-quality technical documentation for the security community.
