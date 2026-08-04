# Security Advisories — bl4dsc4n

Public repository containing security advisories, technical analyses, and Proof-of-Concepts (PoCs) for vulnerabilities independently discovered in open-source software.

The vulnerabilities documented in this repository were identified through manual source code review and dynamic security testing and were disclosed following responsible disclosure practices.

---

# Researcher

| Field             | Value                                                                          |
| ----------------- | ------------------------------------------------------------------------------ |
| Researcher        | Carlos Tuma (bl4dsc4n)                                                         |
| Organization      | RedScan Academy                                                                |
| Community         | 0ff3ns!v3 S3cur!ty                                                             |
| Research Focus    | Web Application Security, Offensive Security, Red Team, Vulnerability Research |
| Disclosure Policy | Responsible / Coordinated Disclosure                                           |

---

# Advisory Repositories

## Main Advisory

**CLOUD-CLASSROOMS-php-1.0**

Technical documentation containing:

* Root cause analysis
* Technical impact
* Vulnerable source code
* Affected components
* CVE references
* Mitigation recommendations

---

## Proof-of-Concept Repository #1

**Cloud-Classroom-PHP-1.0---Poc2**

Covered Advisories

* CVE-2026-2058
* CVE-2025-56713

---

## Proof-of-Concept Repository #2

**Cloud-ClassRooms-PHP-1.0-Poc3**

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

# Public CVE Index

## CloudClassroom PHP Project 1.0

| CVE            | Vulnerability                       | CWE     | Affected Component           | Parameter |
| -------------- | ----------------------------------- | ------- | ---------------------------- | --------- |
| CVE-2026-2058  | SQL Injection                       | CWE-89  | Post Query (postquerypublic) | `gnamex`  |
| CVE-2025-56713 | SQL Injection Authentication Bypass | CWE-89  | loginlinkstudent             | `sid`     |
| CVE-2025-56714 | SQL Injection (UNION-Based)         | CWE-89  | viewresult.php               | `seno`    |
| CVE-2025-61561 | IDOR                                | CWE-639 | updatedetailsfromstudent.php | `eno`     |
| CVE-2025-61562 | IDOR                                | CWE-639 | mydetailsfaculty.php         | `myfid`   |
| CVE-2025-61563 | IDOR                                | CWE-639 | mydetailsstudent.php         | `myds`    |
| CVE-2025-61565 | IDOR                                | CWE-639 | updatedetailsfromfaculty.php | `myfid`   |
| CVE-2025-61566 | Reflected Cross-Site Scripting      | CWE-79  | askquery.php                 | `eid`     |
| CVE-2025-61567 | Reflected Cross-Site Scripting      | CWE-79  | takeassessment2.php          | `exid`    |
| CVE-2025-61568 | SQL Injection (UNION-Based)         | CWE-89  | takeassessment2.php          | `exid`    |
| CVE-2025-61569 | Stored Cross-Site Scripting         | CWE-79  | updatedetailsfromstudent.php | Address   |
| CVE-2025-61570 | Stored Cross-Site Scripting         | CWE-79  | updatedetailsfromfaculty.php | Address   |

---

# Reserved CVEs

The following CVE identifiers have been assigned and are currently reserved. Technical advisories and Proof-of-Concepts will be published after the corresponding coordinated disclosure process has been completed.

| CVE ID         | Status   |
| -------------- | -------- |
| CVE-2025-56716 | Reserved |
| CVE-2025-56719 | Reserved |
| CVE-2025-56720 | Reserved |
| CVE-2025-56721 | Reserved |
| CVE-2025-56722 | Reserved |
| CVE-2025-56723 | Reserved |
| CVE-2025-56724 | Reserved |
| CVE-2025-56725 | Reserved |
| CVE-2025-56727 | Reserved |
| CVE-2025-56728 | Reserved |
| CVE-2025-56729 | Reserved |
| CVE-2025-56730 | Reserved |
| CVE-2025-56731 | Reserved |
| CVE-2025-56732 | Reserved |
| CVE-2025-56733 | Reserved |
| CVE-2025-56734 | Reserved |
| CVE-2025-56735 | Reserved |
| CVE-2025-56736 | Reserved |
| CVE-2025-56737 | Reserved |
| CVE-2025-56738 | Reserved |
| CVE-2025-56739 | Reserved |
| CVE-2025-56741 | Reserved |
| CVE-2025-56742 | Reserved |
| CVE-2025-56744 | Reserved |

---

# Research Statistics

## Assigned CVEs

| Status                  |  Count |
| ----------------------- | -----: |
| Public CVEs             | **1** |
| Reserved CVEs           | **35** |
| **Total Assigned CVEs** | **36** |

---

## Published Vulnerability Classes

| Vulnerability Class            | Count |
| ------------------------------ | ----: |
| SQL Injection                  |     4 |
| Broken Access Control (IDOR)   |     4 |
| Reflected Cross-Site Scripting |     2 |
| Stored Cross-Site Scripting    |     2 |

---

# Research Methodology

The published vulnerabilities were identified through:

* Manual source code review
* Static application security analysis
* Dynamic application security testing
* Authentication testing
* Authorization testing
* Business logic assessment
* Input validation analysis
* Manual Proof-of-Concept development

All testing was performed against locally deployed instances of the affected software in a controlled laboratory environment.

No production systems were accessed during the research process.

---

# Responsible Disclosure

Each vulnerability was privately reported to the affected maintainer or vendor whenever possible before public disclosure.

Technical advisories include:

* Vulnerability description
* Root cause analysis
* Affected component
* Reproduction steps
* Security impact
* Proof-of-Concept
* Remediation recommendations

Additional reserved CVEs will be published after completion of the coordinated disclosure process.

---

# Repository Structure

```
.
├── Advisories
│   ├── CVE-2026-2058
│   ├── CVE-2025-56713
│   ├── CVE-2025-56714
│   ├── CVE-2025-61561
│   ├── CVE-2025-61562
│   ├── CVE-2025-61563
│   ├── CVE-2025-61565
│   ├── CVE-2025-61566
│   ├── CVE-2025-61567
│   ├── CVE-2025-61568
│   ├── CVE-2025-61569
│   └── CVE-2025-61570
│
├── Proof-of-Concepts
│
├── Screenshots
│
└── README.md
```

---

# Disclaimer

The information in this repository is provided exclusively for educational, research, and defensive security purposes.

No weaponized exploit frameworks or offensive tooling are included.

The objective of this repository is to improve software security through responsible vulnerability disclosure, technical documentation, and collaboration with software maintainers.
