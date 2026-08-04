# Security Advisories — bl4dsc4n

Public repository containing security advisories, technical analyses, and Proof-of-Concepts (PoCs) for vulnerabilities independently discovered in the **CloudClassroom PHP Project 1.0**.

All vulnerabilities were identified through manual source code review and dynamic application security testing and disclosed following responsible disclosure practices.

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

## Main Advisory

**https://github.com/carlosalbertotuma/CLOUD-CLASSROOMS-php-1.0**

Contains:

* Technical write-ups
* Vulnerability analysis
* Root cause analysis
* Impact assessment
* CVE references
* Mitigation guidance

---

## Proof-of-Concept Repository #1

**https://github.com/carlosalbertotuma/Cloud-Classroom-PHP-1.0---Poc2**

Covered CVEs:

| CVE            | Vulnerability                       |
| -------------- | ----------------------------------- |
| CVE-2026-2058  | SQL Injection                       |
| CVE-2025-56713 | SQL Injection Authentication Bypass |

---

## Proof-of-Concept Repository #2

**https://github.com/carlosalbertotuma/Cloud-ClassRooms-PHP-1.0-Poc3**

Covered CVEs:

| CVE            | Vulnerability               |
| -------------- | --------------------------- |
| CVE-2025-56714 | SQL Injection (UNION-Based) |
| CVE-2025-61561 | IDOR                        |
| CVE-2025-61562 | IDOR                        |
| CVE-2025-61563 | IDOR                        |
| CVE-2025-61565 | IDOR                        |
| CVE-2025-61566 | Reflected XSS               |
| CVE-2025-61567 | Reflected XSS               |
| CVE-2025-61568 | SQL Injection               |
| CVE-2025-61569 | Stored XSS                  |
| CVE-2025-61570 | Stored XSS                  |

---

# CVE Index

## CloudClassroom PHP Project 1.0

| CVE ID             | Vulnerability                       | CWE     | Affected Component             | Vulnerable Parameter    |
| ------------------ | ----------------------------------- | ------- | ------------------------------ | ----------------------- |
| **CVE-2026-2058**  | SQL Injection                       | CWE-89  | Post Query (postquerypublic)   | `gnamex`                |
| **CVE-2025-56713** | SQL Injection Authentication Bypass | CWE-89  | `loginlinkstudent`             | `sid`                   |
| **CVE-2025-56714** | SQL Injection (UNION-Based)         | CWE-89  | `viewresult.php`               | `seno`                  |
| **CVE-2025-61561** | IDOR                                | CWE-639 | `updatedetailsfromstudent.php` | `eno`                   |
| **CVE-2025-61562** | IDOR                                | CWE-639 | `mydetailsfaculty.php`         | `myfid`                 |
| **CVE-2025-61563** | IDOR                                | CWE-639 | `mydetailsstudent.php`         | `myds`                  |
| **CVE-2025-61565** | IDOR                                | CWE-639 | `updatedetailsfromfaculty.php` | `myfid`                 |
| **CVE-2025-61566** | Reflected Cross-Site Scripting      | CWE-79  | `askquery.php`                 | `eid`                   |
| **CVE-2025-61567** | Reflected Cross-Site Scripting      | CWE-79  | `takeassessment2.php`          | `exid`                  |
| **CVE-2025-61568** | SQL Injection (UNION-Based)         | CWE-89  | `takeassessment2.php`          | `exid`                  |
| **CVE-2025-61569** | Stored Cross-Site Scripting         | CWE-79  | `updatedetailsfromstudent.php` | Address field (`eno`)   |
| **CVE-2025-61570** | Stored Cross-Site Scripting         | CWE-79  | `updatedetailsfromfaculty.php` | Address field (`myfid`) |

---

# Vulnerability Categories

## SQL Injection

### CVE-2026-2058

* SQL Injection
* Vulnerable POST parameter: `gnamex`
* Component: Post Query (`postquerypublic`)

### CVE-2025-56713

* SQL Injection
* Authentication Bypass
* Vulnerable POST parameter: `sid`
* Component: `loginlinkstudent`

### CVE-2025-56714

* UNION-Based SQL Injection
* Vulnerable GET parameter: `seno`
* Component: `viewresult.php`

### CVE-2025-61568

* UNION-Based SQL Injection
* Vulnerable GET parameter: `exid`
* Component: `takeassessment2.php`

---

## Broken Access Control (IDOR)

### CVE-2025-61561

* Endpoint: `updatedetailsfromstudent.php`
* Parameter: `eno`

### CVE-2025-61562

* Endpoint: `mydetailsfaculty.php`
* Parameter: `myfid`

### CVE-2025-61563

* Endpoint: `mydetailsstudent.php`
* Parameter: `myds`

### CVE-2025-61565

* Endpoint: `updatedetailsfromfaculty.php`
* Parameter: `myfid`

---

## Cross-Site Scripting (Reflected)

### CVE-2025-61566

* Endpoint: `askquery.php`
* Parameter: `eid`

### CVE-2025-61567

* Endpoint: `takeassessment2.php`
* Parameter: `exid`

---

## Cross-Site Scripting (Stored)

### CVE-2025-61569

* Endpoint: `updatedetailsfromstudent.php`
* Field: Address

### CVE-2025-61570

* Endpoint: `updatedetailsfromfaculty.php`
* Field: Address

---

# Research Statistics

## Total CVEs

**12**

---

## Vulnerability Distribution

| Category                       | Count |
| ------------------------------ | ----: |
| SQL Injection                  |     4 |
| Broken Access Control (IDOR)   |     4 |
| Reflected Cross-Site Scripting |     2 |
| Stored Cross-Site Scripting    |     2 |

---

# Research Methodology

The vulnerabilities documented in this repository were identified through:

* Manual source code review
* Static code analysis
* Dynamic application testing
* Authentication testing
* Authorization testing
* Business logic assessment
* Input validation testing
* Manual Proof-of-Concept development

All testing was performed against locally deployed instances of CloudClassroom PHP Project 1.0.

No production systems were targeted during the research process.

---

# Responsible Disclosure

Each vulnerability was documented with sufficient technical evidence to allow maintainers to reproduce and validate the issue.

The disclosure process followed responsible disclosure principles, providing affected parties the opportunity to review and address the reported vulnerabilities before public documentation.

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
├── PoCs
│
├── Screenshots
│
└── README.md
```

---

# Disclaimer

The information provided in this repository is intended solely for educational, defensive, and research purposes.

No weaponized exploits or offensive frameworks are included.

The objective of this project is to improve software security by documenting vulnerabilities, assisting developers in remediation efforts, and contributing to the responsible disclosure ecosystem.
