# Advisory — ShopMagic for WooCommerce 4.9.3 — Unauthenticated Open Redirect in Click Tracking

## Summary

ShopMagic for WooCommerce 4.9.3 exposes a public click-tracking route at `/track/sm-click/`. The route accepts the destination URL from the `l` query parameter and returns it directly in the HTTP `Location` header.

The route only requires a syntactically valid UUID in the `c` parameter. A matching tracked-message record is not required: when the UUID is not found, the controller still redirects to the supplied destination.

This allows an unauthenticated visitor to create a trusted-site URL that redirects to an attacker-controlled external site.

## Severity

**Low / Informational — CWE-601 (URL Redirection to Untrusted Site)**

The issue can support phishing and abuse of the WordPress site's reputation. It does not provide server-side request forgery, code execution, authentication bypass, or direct data access.

## Affected component

- Plugin: ShopMagic for WooCommerce
- Tested version: `4.9.3`
- WooCommerce: active during the final reproduction as the plugin dependency
- Route: `GET /track/sm-click/`
- Parameters:
  - `c` — message UUID
  - `l` — redirect destination
- Authentication: none
- CSRF token: not required

Relevant code:

- `src/Marketing/Controller/MailTrackingController.php:41-104`
- `config/routes/public.php:18-25`

The public route is registered with `->authorize('__return_true')`. The controller calls `esc_url_raw()` on `l`, then returns the value as `Location` both when the message exists and when the UUID lookup raises `CannotProvideItemException`.

## Reproduction

The following request was executed against the local WordPress instance. The UUID is valid in format but does not need to exist in the ShopMagic tracking table.

```bash
curl -i -G \
  --data-urlencode 'c=00000000-0000-0000-0000-000000000000' \
  --data-urlencode 'l=https://webhook.site/<your-webhook-id>' \
  http://127.0.0.1:8081/track/sm-click/
```

Observed response:

```http
HTTP/1.1 302 Found
Location: https://webhook.site/<your-webhook-id>
Content-Length: 0
```

The same request was repeated with the laboratory host:

```bash
curl -i -G \
  --data-urlencode 'c=00000000-0000-0000-0000-000000000000' \
  --data-urlencode 'l=https://webhook.site/<your-webhook-id>' \
  http://172.25.44.135:8081/track/sm-click/
```

When the HTTP client followed the redirect, the webhook service returned `HTTP/2 200`, confirming that the redirect was followed by the client.

To follow automatically with curl:

```bash
curl -i -L -G \
  --data-urlencode 'c=00000000-0000-0000-0000-000000000000' \
  --data-urlencode 'l=https://webhook.site/<your-webhook-id>' \
  http://127.0.0.1:8081/track/sm-click/
```

An invalid UUID such as `c=not-a-uuid` returns `406 Not Acceptable`, but no valid tracked-message record is required for the redirect behavior.

## Technical details

The relevant flow is:

```php
$original_uri = esc_url_raw( $request->get_param( 'l' ) );
$message_id   = $request->get_param( 'c' );
$uuid         = Uuid::fromString( $message_id );

try {
    $tracked_email = $this->repository->find_one_by(
        [ 'message_id' => $uuid->toString() ]
    );
} catch ( CannotProvideItemException $e ) {
    return new \WP_HTTP_Response(
        null,
        \WP_Http::FOUND,
        [ 'Location' => esc_url_raw( $original_uri ) ]
    );
}
```

The normal success path also returns:

```php
[ 'Location' => esc_url_raw( $original_uri ) ]
```

No host allowlist, same-origin check, signed destination, or fallback validation is applied.

## Impact

An attacker can distribute a URL under the trusted WordPress origin that redirects visitors to an external domain, for example a phishing page. The redirect may be more credible because it uses the site's domain and the plugin's tracking path.

This is **not SSRF**. The WordPress server does not fetch the destination. The `302` response is followed by the victim's browser or HTTP client.

## Recommended remediation

1. Do not trust `l` as an arbitrary destination.
2. Prefer storing a server-side message/link identifier and resolving it to a known destination.
3. If a destination must be accepted, allow only approved local hosts and reject protocol-relative URLs (`//host`) and non-HTTP(S) schemes.
4. Use `wp_validate_redirect()` with a safe local fallback, then enforce an explicit host allowlist before emitting `Location`.
5. Add regression tests for:
   - `https://attacker.example/`
   - `//attacker.example/`
   - `javascript:...`
   - a valid but nonexistent UUID

## Validation notes

- The test was performed only against the authorized local WordPress laboratory.
- The plugin was correctly activated using its main file, `shopMagic.php`, with WooCommerce active.
- No authenticated session, nonce, WooCommerce account, or existing tracking record was required.
- The plugin's REST API remained protected by its capability check; this finding concerns only the public tracking route.
