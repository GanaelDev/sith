# Security Audit — Sith

**Repository:** `GanaelDev/sith`  
**Branch:** `master`  
**Audit date:** 2026-09-08  
**Audit type:** source-code, architecture, configuration, authentication/authorization, payment-flow and CI/CD security review  
**Overall risk:** **HIGH**

> **Important limitation:** this is a deep static audit of the repository. It is **not** a penetration test and does not prove the absence of vulnerabilities. Production infrastructure, reverse-proxy configuration, firewall rules, GitHub secret values, database contents, real traffic, deployed dependency versions, historical Git objects and runtime behavior were not fully observable. Findings marked **VERIFY** require runtime or privileged verification.

---

## 1. Executive summary

Sith is a large Django application with a broad attack surface: authentication, user profiles, subscriptions, clubs, counters, e-commerce, invoices, payments, forum, elections, file storage, administration and an API. The repository also contains a privileged production deployment pipeline.

The application already has a number of useful security foundations:

- Django CSRF middleware is enabled.
- Jinja autoescaping is enabled.
- Django `SecurityMiddleware` and clickjacking protection are enabled.
- `DEBUG` defaults to `False`.
- `SECRET_KEY` is loaded from the environment.
- Session and CSRF cookie security can be enabled.
- API keys are stored as hashes rather than plaintext.
- Object-level permission classes exist for the API.
- `.env`, SQLite databases, logs and several generated directories are ignored by Git.
- Dependabot is configured.
- Tests and linting run in CI.
- Xapian artifacts have explicit hashes.

Despite these controls, the current security posture should be considered **HIGH RISK** until production hardening and authorization/payment testing are completed.

The most important issues are not a single obvious remote-code-execution primitive; they are **security-boundary weaknesses** that could turn a smaller bug into a major compromise:

1. `ALLOWED_HOSTS = ["*"]` disables Django host-header validation.
2. Production security depends too heavily on environment values and does not fail closed on unsafe combinations.
3. The example configuration explicitly disables HTTPS and enables debug mode, creating dangerous deployment foot-guns.
4. Production deployment grants a GitHub workflow powerful SSH access and runs `sudo systemctl restart uwsgi` remotely.
5. Third-party GitHub Actions are not pinned to immutable commit SHAs.
6. The API has a custom API-key authentication model and a custom permission system; this deserves systematic BOLA/IDOR testing.
7. Payment callbacks are security-sensitive and currently expose internal exception representations in HTTP 500 responses.
8. Payment signature verification uses RSA PKCS#1 v1.5 + SHA-1, which is legacy cryptography and should be migrated if the payment provider supports a modern scheme.
9. Financial calculations convert database currency values to Python `float`, which creates avoidable precision and integrity risks.
10. The application stores significant personal and financial information, so file access, exports, logs, caching and authorization need to be treated as high-value assets.
11. CI currently focuses on quality/tests rather than a complete security gate.
12. The deployment model installs dependencies and performs migrations directly on the production host instead of deploying an immutable artifact.

---

# 2. Risk matrix

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| SEC-001 | **CRITICAL/HIGH** | Django | Wildcard `ALLOWED_HOSTS` | Confirmed |
| SEC-002 | **HIGH** | Production config | No fail-closed production security profile | Confirmed |
| SEC-003 | **HIGH** | Transport | HTTPS/security cookies are configurable; example disables HTTPS | Confirmed |
| SEC-004 | **HIGH** | CI/CD | GitHub Actions has privileged SSH deployment capability | Confirmed |
| SEC-005 | **HIGH** | Supply chain | Deployment executes mutable third-party action references | Confirmed |
| SEC-006 | **HIGH** | Authorization | Application-wide object authorization needs systematic BOLA/IDOR testing | Verify / high priority |
| SEC-007 | **HIGH** | Payments | Payment callback exposes internal exception details | Confirmed |
| SEC-008 | **HIGH** | Payments | Legacy SHA-1/PKCS#1 v1.5 signature verification | Confirmed / provider-dependent |
| SEC-009 | **HIGH** | Financial integrity | Monetary totals converted to `float` | Confirmed |
| SEC-010 | **HIGH** | Data protection | File/media authorization must be audited end-to-end | Verify / high priority |
| SEC-011 | **MEDIUM-HIGH** | API | Custom API-key and permission model requires negative testing | Verify |
| SEC-012 | **MEDIUM-HIGH** | Deployment | Direct package installation and migrations on production | Confirmed |
| SEC-013 | **MEDIUM** | CI | No visible dedicated SAST/secret/dependency security gate | Confirmed |
| SEC-014 | **MEDIUM** | CI | Workflow permissions are not explicitly least-privilege | Verify |
| SEC-015 | **MEDIUM** | HTTP | Security headers are incomplete at application level | Confirmed / runtime verify |
| SEC-016 | **MEDIUM** | Secrets | Secret history/fixtures/artifacts require dedicated scanning | Verify |
| SEC-017 | **MEDIUM** | Authentication | Session/authentication implementation is custom and must be tested as a boundary | Verify |
| SEC-018 | **MEDIUM** | Business logic | Basket/payment concurrency and replay protection require regression tests | Partially mitigated |
| SEC-019 | **MEDIUM** | Privacy | Logs and error reporting may expose sensitive operational data | Verify |
| SEC-020 | **MEDIUM** | Dependencies | Full resolved dependency vulnerability state not independently verified | Verify |
| SEC-021 | **LOW-MEDIUM** | Configuration | `.env.example` contains realistic secret-shaped material | Confirmed |
| SEC-022 | **LOW-MEDIUM** | API | API key lookup/rotation/audit lifecycle should be strengthened | Recommendation |
| SEC-023 | **LOW-MEDIUM** | Availability | Unbounded/large formset and expensive operations need DoS controls | Verify |
| SEC-024 | **LOW-MEDIUM** | Database | Indexing/constraint review needed for security-sensitive queries | Verify |

---

# 3. Detailed findings and resolutions

## SEC-001 — Wildcard `ALLOWED_HOSTS`

**Severity: HIGH**  
**Location:** `sith/settings.py`

Current configuration:

```python
ALLOWED_HOSTS = ["*"]
```

This disables Django's Host-header validation.

### Why this matters

The `Host` header participates in URL construction, redirects, password reset links and other host-dependent behavior. A wildcard does not automatically produce an exploit, but it removes an important Django security boundary.

### Resolution

Use an explicit environment list:

```python
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=[])
```

Production:

```text
ALLOWED_HOSTS=ae.utbm.fr
```

If multiple canonical hosts are required, enumerate them explicitly.

### Tests to add

- request with an unknown `Host` returns `400`;
- canonical host remains accepted;
- password-reset/absolute URLs never use an attacker-controlled host;
- reverse proxy preserves the expected host behavior.

---

## SEC-002 — No fail-closed production security profile

**Severity: HIGH**  
**Location:** `sith/settings.py`, environment configuration

The project correctly reads several security-sensitive settings from the environment, but unsafe production combinations are not prevented at application startup.

Examples:

- `DEBUG=true`
- `HTTPS=off`
- wildcard hosts
- SQLite in production
- dummy email backend in production

### Resolution

Create explicit environment validation, ideally in a dedicated production configuration module.

Recommended invariants:

```python
if ENVIRONMENT == "production":
    if DEBUG:
        raise RuntimeError("DEBUG must be disabled in production")
    if not ALLOWED_HOSTS or "*" in ALLOWED_HOSTS:
        raise RuntimeError("Production ALLOWED_HOSTS is invalid")
    if not SESSION_COOKIE_SECURE:
        raise RuntimeError("Secure session cookies are required")
    if not CSRF_COOKIE_SECURE:
        raise RuntimeError("Secure CSRF cookies are required")
```

Also reject SQLite in production if PostgreSQL is the supported production database.

### Better architecture

Use:

```text
sith/settings/base.py
sith/settings/test.py
sith/settings/development.py
sith/settings/production.py
```

or one settings file with a strict `ENVIRONMENT` switch.

Do not make critical production controls silently configurable to insecure values.

---

## SEC-003 — HTTPS security is still operator-controlled

**Severity: HIGH**  
**Location:** `sith/settings.py`, `.env.example`

Current settings make cookie security depend on:

```python
HTTPS = env.bool("HTTPS", default=True)
CSRF_COOKIE_SECURE = HTTPS
SESSION_COOKIE_SECURE = HTTPS
```

The example environment contains:

```text
HTTPS=off
SITH_DEBUG=true
```

This is acceptable for local development but dangerous as a template if copied into a deployment without deliberate review.

### Resolution

Separate development and production examples:

```text
.env.example
.env.production.example
```

Production should enforce:

```python
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SECURE_SSL_REDIRECT = True
```

If TLS is terminated by a reverse proxy, configure and test Django's proxy-awareness correctly.

Add HSTS only after confirming that the entire intended HTTPS domain tree is safe:

```python
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

Do not enable `includeSubDomains` or preload blindly.

---

## SEC-004 — Privileged production deployment through GitHub Actions

**Severity: HIGH**  
**Location:** `.github/workflows/deploy.yml`

The production workflow establishes SSH access using GitHub secrets and executes:

```text
git fetch
git reset --hard origin/master
uv sync --group prod
npm install
uv run ./manage.py install_xapian
uv run ./manage.py migrate
uv run ./manage.py collectstatic --clear --noinput
uv run ./manage.py compilemessages
sudo systemctl restart uwsgi
```

This makes the GitHub workflow a production trust boundary.

### Attack path

A compromise of any component capable of modifying the workflow or executing arbitrary code in the deployment job can potentially become:

```text
GitHub compromise
       ↓
CI execution
       ↓
SSH credentials
       ↓
production host
       ↓
sudo/system service
       ↓
application/server compromise
```

### Resolution — preferred

Move to an immutable artifact model:

```text
commit
  ↓
CI
  ├─ tests
  ├─ SAST
  ├─ dependency scan
  ├─ secret scan
  ├─ build
  └─ sign/hash artifact
       ↓
artifact registry
       ↓
production deployment
       ↓
health check
       ↓
rollback if unhealthy
```

The production server should receive an exact artifact, not install arbitrary dependencies during deployment.

### If SSH deployment remains

- dedicated deployment account;
- no interactive shell if possible;
- no general-purpose sudo;
- sudo rule limited to the exact service operation;
- separate deploy and application users;
- firewall SSH to GitHub Actions or a deployment network where possible;
- rotate deployment keys regularly;
- use host-key verification;
- record deployment audit logs;
- support rollback to the previous release.

---

## SEC-005 — Third-party GitHub Actions are not immutable

**Severity: HIGH**  
**Location:** `.github/workflows/*.yml`

Examples currently include:

```yaml
actions/checkout@v6
actions/setup-python@v6
pre-commit/action@v3.0.1
appleboy/ssh-action@v1.2.5
getsentry/action-release@v1.7.0
```

Version tags are not immutable references.

### Resolution

Pin third-party actions to full commit SHAs:

```yaml
uses: actions/checkout@<commit-sha> # v6
```

Do this especially for:

- SSH/deployment actions;
- actions with secrets;
- actions with write permissions;
- actions executed before security checks.

Use Dependabot/Renovate to update pinned SHAs automatically.

---

## SEC-006 — Application-wide BOLA/IDOR authorization risk

**Severity: HIGH**  
**Status: verify systematically**

The project contains explicit permission abstractions such as:

- `IsInGroup`
- `HasPerm`
- `IsRoot`
- `IsSubscriber`
- `CanView`
- `CanEdit`
- `IsOwner`

This is a good architectural foundation. The API documentation also explicitly distinguishes global and object-level permissions.

However, the application has enough modules and object identifiers that static inspection cannot prove that every endpoint consistently enforces object ownership/visibility.

### High-value targets

Test every route containing:

```text
/<id>
/<pk>
/user/<id>
/basket/<id>
/invoice/<id>
/file/<id>
/product/<id>
/subscription/<id>
/club/<id>
```

### Test methodology

Create at least three accounts:

```text
USER_A = ordinary user
USER_B = ordinary user
ADMIN = privileged user
```

For each object belonging to A:

1. authenticate as B;
2. request the object's GET endpoint;
3. attempt POST/PUT/PATCH;
4. attempt DELETE;
5. attempt export/download;
6. attempt API access;
7. repeat using guessed/sequential IDs.

Expected result: B must never obtain A's protected object merely by changing the identifier.

### Resolution

Enforce authorization at the queryset/object boundary, not only in templates.

Good pattern:

```python
self.get_object_or_exception(Model, pk=obj_id)
self.check_object_permissions(obj)
```

Better still, restrict the queryset itself where possible so unauthorized objects are never fetched.

---

## SEC-007 — Payment callback leaks internal exception information

**Severity: HIGH**  
**Location:** `eboutic/views.py`, `EtransactionAutoAnswer`

The payment callback currently returns:

```python
return HttpResponse(
    "Basket processing failed with error: " + repr(e),
    status=500,
)
```

This can expose internal implementation details to the payment provider/client and potentially to an attacker who can trigger exceptional paths.

### Resolution

Return a generic message:

```python
sentry_sdk.capture_exception(e)
return HttpResponse("Payment processing failed", status=500)
```

Log the detailed exception internally with a correlation identifier.

Example:

```text
Payment processing failed — reference: PAY-2026-000123
```

Never expose:

- SQL errors;
- filesystem paths;
- object representations;
- configuration values;
- stack traces;
- internal identifiers not required by the payment protocol.

---

## SEC-008 — Legacy SHA-1 payment signature verification

**Severity: HIGH**  
**Location:** `eboutic/views.py`

The callback verifies the payment signature using:

```python
PKCS1v15()
SHA1()
```

This is legacy cryptography.

### Important nuance

If this algorithm is dictated by the payment provider's protocol, replacing it unilaterally may break payment validation. The issue should therefore be treated as **provider/protocol-dependent**, not as an assertion that the current callback is trivially forgeable.

### Resolution

1. Confirm the payment provider's current supported signature algorithms.
2. Prefer RSA-PSS + SHA-256 or another provider-supported modern construction.
3. If SHA-1 is mandatory, isolate the legacy verification in one small adapter.
4. Document why SHA-1 remains required.
5. Monitor provider migration deadlines.
6. Add interoperability tests using official provider test vectors.

### Additional callback hardening

Parse the signed fields explicitly rather than assuming that `Sig` is the final query parameter:

```python
query = request.GET.copy()
signature = query.pop("Sig", None)
canonical_data = canonicalize_provider_fields(query)
```

The canonicalization must follow the payment provider specification exactly.

---

## SEC-009 — Monetary calculations use `float`

**Severity: HIGH**  
**Location:** `eboutic/models.py`

`Basket.total` converts an aggregate result to `float`:

```python
return float(
    self.items.aggregate(...)["total"]
)
```

This value is then used in payment-related calculations, including:

```python
int(self.total * 100)
```

### Why this matters

Binary floating point is not appropriate for financial invariants. Values such as `10.29` cannot necessarily be represented exactly.

Even if the current database field has fixed precision, converting to `float` introduces a second numeric representation and can create edge cases in payment amount comparisons.

### Resolution

Use `Decimal` end-to-end.

Example principle:

```python
from decimal import Decimal

ZERO = Decimal("0.00")
```

Keep currency fields as `Decimal` and convert to integer cents only at the payment-provider boundary:

```python
amount_cents = int((total * Decimal("100")).quantize(Decimal("1")))
```

Prefer a dedicated money abstraction if the project grows further.

### Add invariants

For every payment:

```text
basket total
==
provider amount
==
invoice total
==
sales total
```

All four should be tested against fractional prices, discounts, large quantities and concurrent requests.

---

## SEC-010 — File/media authorization must be audited end-to-end

**Severity: HIGH**  
**Status: verify**

The user model contains several file relationships:

- home directory;
- profile picture;
- avatar;
- scrub picture.

The application also defines a media root and exposes `/data/`.

### Main risk

Authorization implemented on an HTML page is not sufficient if the underlying file URL is directly accessible.

A private profile/document must remain private when its direct URL is known.

### Resolution

Classify files:

```text
PUBLIC
PRIVATE_USER
PRIVATE_GROUP
PRIVATE_ADMIN
TEMPORARY
```

Then enforce access before returning the file.

For private files:

```text
browser
  ↓
Django authorization
  ↓
short-lived signed URL or streaming response
  ↓
object storage/private filesystem
```

Avoid putting protected files directly under a public web-server directory.

### Tests

- authenticated A downloads A's private file: allowed;
- B downloads A's file: denied;
- anonymous download: denied;
- guessed ID/path: denied;
- deleted object URL: denied;
- renamed/moved object: old URL cannot bypass authorization.

---

## SEC-011 — Custom API-key authentication and permissions

**Severity: MEDIUM-HIGH**  
**Location:** `api/auth.py`, `api/models.py`, `api/permissions.py`

The API uses an `X-APIKey` header. The key is hashed before database lookup, which is a good practice.

The API client can also receive:

- groups;
- individual Django permissions.

This creates a powerful authorization system.

### Positive control

Only the hash is stored in `ApiKey`, and revoked keys are excluded from authentication.

### Risks to verify

- API keys may have excessive permissions;
- no visible expiration mechanism;
- no visible last-used timestamp;
- no visible per-key audit trail;
- compromised keys may remain valid indefinitely until revoked;
- client permission cache can become stale within an object lifetime;
- all controllers need explicit authentication/authorization review.

### Resolution

Add to `ApiKey`:

```text
created_at
expires_at
last_used_at
revoked_at
revoked_by
```

Optionally add:

```text
allowed_ips
purpose
```

Use key rotation and short-lived credentials for automation.

Log security events without logging the actual key:

```text
api_key_prefix
client_id
endpoint
user/owner
result
timestamp
request_id
```

### API policy

Default should be deny.

Every controller should explicitly state:

```text
anonymous allowed?
session allowed?
API key allowed?
required permission?
object permission?
```

---

## SEC-012 — Production installs dependencies directly on the host

**Severity: MEDIUM-HIGH**  
**Location:** `.github/workflows/deploy.yml`

The deployment executes:

```text
uv sync --group prod
npm install
```

on the production machine.

### Risks

- deployment behavior depends on server state;
- build is not identical to what CI tested;
- network/package availability can affect production deployment;
- compromised dependency infrastructure can affect deployment;
- rollback is more complicated;
- the production host performs build-like operations.

### Resolution

Build in CI:

```text
uv lock / npm lock
        ↓
CI build
        ↓
security scan
        ↓
artifact
        ↓
production
```

Use lockfiles consistently and fail if the lockfile is not respected.

Prefer `npm ci` rather than `npm install` for deterministic CI/deployment installs when the project uses npm lockfiles.

---

## SEC-013 — Missing dedicated security CI gates

**Severity: MEDIUM**

The inspected CI runs pre-commit and tests/coverage, but no dedicated security pipeline was visible.

### Resolution

Add a separate `security` job:

```text
secret scan
   ↓
SAST
   ↓
dependency scan
   ↓
IaC/workflow scan
   ↓
security tests
```

Recommended tooling:

- Gitleaks or equivalent secret scanner;
- Semgrep;
- `pip-audit` or equivalent for Python dependencies;
- npm lockfile audit;
- Trivy for container/filesystem scanning if containers are introduced;
- GitHub dependency review for pull requests.

### Failure policy

Block merge/deployment on:

- confirmed secret;
- critical dependency vulnerability;
- high-severity SAST issue without an accepted exception;
- failed security regression test.

---

## SEC-014 — GitHub Actions permissions should be explicit

**Severity: MEDIUM**

The inspected workflows do not define a restrictive top-level permissions policy.

### Resolution

Default to:

```yaml
permissions:
  contents: read
```

Then grant individual permissions only to jobs that require them.

For example, a deployment workflow should not automatically inherit write permissions to repository contents if it only needs to read code and use external deployment credentials.

Also separate deployment into a dedicated environment with approval rules.

---

## SEC-015 — Security headers are incomplete at application level

**Severity: MEDIUM**

The application has clickjacking protection and `SecurityMiddleware`, which is good.

However, a modern production baseline should explicitly verify:

```text
Strict-Transport-Security
Content-Security-Policy
Referrer-Policy
Permissions-Policy
Cache-Control on sensitive responses
X-Content-Type-Options
```

### Resolution

Prefer configuring stable infrastructure headers at the reverse proxy where appropriate, while keeping application-specific policy in Django.

### CSP migration strategy

Do not blindly add a restrictive CSP.

Start with report-only mode:

```text
Content-Security-Policy-Report-Only
```

Collect violations, remove unnecessary inline/eval behavior, then enforce the policy.

---

## SEC-016 — Historical secret/data exposure needs a dedicated scan

**Severity: MEDIUM**

The current `.env.example` contains a secret-shaped value that is documented as non-production. This is not itself evidence of a production secret leak.

However, because the repository is public, the following must be scanned:

```text
entire Git history
tags
releases
deleted files
fixtures
logs
SQL dumps
coverage artifacts
CI artifacts
documentation
example configuration
```

### Resolution

Run:

```text
gitleaks detect --redact
```

and a second independent scanner if possible.

If a real credential is found:

1. revoke/rotate it;
2. invalidate dependent sessions/tokens;
3. remove it from the repository;
4. clean historical exposure if required;
5. inspect CI artifacts and caches;
6. document the incident.

Removing the file from the latest commit is not enough.

---

## SEC-017 — Custom authentication middleware requires dedicated testing

**Severity: MEDIUM**

The application uses a custom authentication middleware and a custom Django authentication backend.

Custom authentication code increases the importance of regression testing around:

- login;
- logout;
- session rotation;
- password change;
- password reset;
- account disablement;
- staff/superuser transitions;
- group changes;
- anonymous requests;
- stale sessions after privilege changes.

### Resolution

Add security tests for privilege transitions.

Example:

```text
USER has normal rights
       ↓
grant admin group
       ↓
rights appear
       ↓
remove admin group
       ↓
old session/token no longer retains admin rights
```

This is especially important because permissions are cached in several custom properties.

---

## SEC-018 — Payment/basket concurrency and replay

**Severity: MEDIUM**

The payment callback already uses `select_for_update()` and deletes the basket after successful processing. This is a positive control against straightforward duplicate callback processing.

However, payment flows deserve explicit concurrency tests.

### Test cases

Run two identical successful callbacks simultaneously:

```text
callback A ─┐
            ├─ same BasketID
callback B ─┘
```

Expected:

- exactly one invoice;
- exactly one set of sales/refilling records;
- exactly one successful finalization;
- second callback handled safely and idempotently.

### Better design

Introduce a payment transaction entity:

```text
PaymentTransaction
------------------
id
provider
provider_transaction_id
basket
amount
currency
status
signature_verified_at
processed_at
created_at
```

Add a unique constraint on the provider transaction identifier.

This makes idempotency explicit rather than relying primarily on basket deletion.

---

## SEC-019 — Logging and error reporting privacy

**Severity: MEDIUM**

The settings contain logging to stdout and a dedicated `account_dump_mail.log`.

The application also uses Sentry.

### Risks to verify

Sensitive information can accidentally enter logs through:

- request bodies;
- query parameters;
- email addresses;
- billing information;
- exception representations;
- payment callback payloads;
- authentication failures;
- uploaded file paths.

### Resolution

Define a logging policy:

```text
NEVER log:
passwords
API keys
session cookies
payment secrets
full billing information
personal data unless necessary
```

Use structured logs and a request/correlation ID.

Configure Sentry scrubbing for:

```text
Authorization
Cookie
Set-Cookie
X-APIKey
password
secret
billing fields
```

Also define retention periods.

---

## SEC-020 — Dependency vulnerability state not independently verified

**Severity: MEDIUM**

The project has dependency management and Dependabot, but this audit did not execute a full resolved dependency vulnerability scan against the installed dependency graph.

### Resolution

Make the resolved dependency set auditable.

Recommended pipeline:

```text
lockfile
  ↓
audit
  ↓
SBOM
  ↓
vulnerability database
  ↓
policy
```

Generate an SBOM in CycloneDX or SPDX format if practical.

Track exceptions with:

```text
CVE
severity
reason
compensating control
owner
expiry date
```

Never allow permanent undocumented exceptions.

---

## SEC-021 — Realistic secret-shaped value in `.env.example`

**Severity: LOW-MEDIUM**

`.env.example` contains a long secret-shaped `SECRET_KEY` even though it states that it is not the production key.

### Resolution

Replace with:

```text
SECRET_KEY=replace-me-with-a-random-secret
```

or generate it automatically during setup.

This reduces confusion and secret-scanner noise.

---

## SEC-022 — API key lifecycle and observability

**Severity: LOW-MEDIUM**

The current API key model has creation and revocation, which is useful, but a mature credential-management model should include expiration, usage tracking and rotation.

### Resolution

Implement:

```text
create
show-once
use
expire
rotate
revoke
revoke-all
```

Never show an API key again after creation.

Use the prefix only for identification in the UI/logs.

---

## SEC-023 — Availability and resource exhaustion

**Severity: LOW-MEDIUM / VERIFY**

The application contains potentially expensive features:

- search/Xapian;
- image processing;
- PDF generation;
- file operations;
- formsets;
- e-commerce operations;
- Celery tasks.

The e-boutique formset is explicitly configured with `absolute_max=None`.

### Resolution

Put hard resource limits around user-controlled collections.

For example:

```text
maximum basket items
maximum quantity per item
maximum upload size
maximum image dimensions
maximum PDF generation workload
maximum request body size
maximum task runtime
```

Add application-level and reverse-proxy rate limiting for expensive endpoints.

Do not rely solely on frontend validation.

---

## SEC-024 — Database constraints and indexes

**Severity: LOW-MEDIUM / VERIFY**

Security-sensitive state should be enforced as much as possible at the database level.

### Recommended constraints

Payment:

```text
provider_transaction_id UNIQUE
```

API key:

```text
hashed_key UNIQUE
```

Business invariants:

```text
quantity > 0
amount >= 0 where appropriate
```

Authorization relationships should use foreign keys with deliberate `on_delete` semantics.

Add indexes for frequent security-sensitive lookups such as:

```text
revoked + hashed_key
user_id
owner_id
basket_id
invoice_id
subscription dates
```

Review indexes using real production query plans before adding them blindly.

---

# 4. Payment security deep review

Payment functionality deserves its own security boundary because a compromise can directly become a financial integrity incident.

## Required invariants

For every successful payment:

```text
1. provider signature is valid
2. provider transaction is authentic
3. provider amount == server basket amount
4. provider currency == expected currency
5. basket belongs to the expected customer
6. basket is payable
7. transaction has not already been processed
8. invoice is generated exactly once
9. sales/refilling records are generated exactly once
10. basket is finalized atomically
```

The current callback verifies the amount against the basket and uses a database transaction plus row locking. These are good controls.

### Recommended state machine

Replace implicit state with an explicit payment state machine:

```text
CREATED
   ↓
PAYMENT_STARTED
   ↓
AUTHORIZED
   ↓
PROCESSING
   ↓
COMPLETED
```

Failure states:

```text
FAILED
EXPIRED
CANCELLED
REJECTED
```

Transitions must be validated server-side.

Never allow:

```text
COMPLETED → AUTHORIZED
COMPLETED → CREATED
```

without an explicit administrative reconciliation process.

---

# 5. Authentication security test plan

## Account lifecycle

- [ ] login with valid credentials;
- [ ] login with invalid credentials;
- [ ] user enumeration resistance;
- [ ] password reset token expiration;
- [ ] password reset token single use;
- [ ] session rotation after login;
- [ ] logout invalidates session;
- [ ] password change invalidates old sessions if policy requires;
- [ ] disabled account cannot authenticate;
- [ ] deleted account cannot authenticate;
- [ ] privilege downgrade invalidates cached privileges.

## Session

- [ ] Secure flag in production;
- [ ] HttpOnly;
- [ ] SameSite policy appropriate to integrations;
- [ ] session fixation test;
- [ ] CSRF on all state-changing browser endpoints;
- [ ] session expiration;
- [ ] concurrent session policy if required.

---

# 6. Authorization test plan

For each role:

```text
anonymous
ordinary user
subscriber
old subscriber
club member
module administrator
root/superuser
API client
```

Build an authorization matrix:

| Resource | Anonymous | User | Subscriber | Admin | Root |
|---|---:|---:|---:|---:|---:|
| Public pages | R | R | R | R | R |
| Own profile | -/R | R/W | R/W | R/W | R/W |
| Other profile | - | policy | policy | R | R/W |
| Own basket | - | R/W | R/W | policy | R/W |
| Other basket | - | - | - | policy | R/W |
| Own invoice | - | R | R | policy | R/W |
| Other invoice | - | - | - | policy | R/W |
| Admin data | - | - | - | module | R/W |
| API administration | - | - | - | restricted | restricted |

The exact expected matrix must be confirmed with the business owners.

### Critical rule

A hidden button is **not** authorization.

Authorization must be enforced server-side for every read/write/export/delete operation.

---

# 7. XSS review strategy

The application uses Jinja with autoescaping enabled, which is positive.

Nevertheless, review every use of:

```text
|safe
mark_safe
format_html
HTML() / raw HTML construction
Markdown rendering
user-generated forum content
signatures
quotes
product descriptions
club pages
```

### Recommended architecture

User content should follow:

```text
raw input
 ↓
validation
 ↓
allowed markup parser/sanitizer
 ↓
stored canonical representation
 ↓
autoescaped rendering
```

Do not solve XSS with output escaping alone if the application intentionally permits HTML/Markdown.

---

# 8. CSRF review strategy

Django CSRF middleware is enabled.

Audit all state-changing routes, especially:

```text
POST
PUT
PATCH
DELETE
AJAX/fetch
fragment requests
payment initiation
profile changes
file operations
basket/payment operations
administrative actions
```

For each browser-authenticated endpoint, verify:

```text
no token → 403
invalid token → 403
valid token → allowed
```

Any endpoint intentionally exempted from CSRF must be explicitly documented and use another strong authentication mechanism.

---

# 9. SSRF / outbound request review

Because the application contains integrations and background jobs, perform a dedicated search for any feature where users can influence a URL.

Review:

```text
requests
httpx
urllib
urlopen
webhooks
image imports
remote file imports
avatar/profile imports
callback URLs
```

If a user-controlled URL is fetched server-side, block:

```text
127.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.169.254
::1
RFC1918 IPv6 equivalents
```

Also protect against DNS rebinding by resolving and validating the destination immediately before connection where applicable.

---

# 10. File upload review

For every upload endpoint, enforce:

```text
maximum byte size
maximum dimensions
allowed MIME types
allowed extensions
content sniffing
safe generated filenames
storage outside executable web roots
image re-encoding where appropriate
```

Do not trust:

```text
filename
Content-Type
extension
client-side validation
```

Pillow-based image handling should also have explicit decompression/resource limits where applicable.

---

# 11. SQL injection and ORM review

Django ORM provides strong SQL-injection protection when used normally.

Still audit all uses of:

```text
raw()
RawSQL()
extra()
cursor.execute()
SQL fragments
search query construction
ordering from user input
```

For dynamic ordering/filtering, use allow-lists rather than concatenating arbitrary SQL identifiers.

---

# 12. Command execution review

The application and deployment system should be reviewed for:

```text
subprocess
os.system
os.popen
shell=True
management command invocation
Celery tasks launching external binaries
PDF/image converters
Xapian utilities
```

The repository search performed during this audit did not establish a confirmed application-level command injection path, but this area remains important because the application has management commands and external tooling.

If command execution is necessary:

- never interpolate user input into shell strings;
- use argument arrays;
- use `shell=False`;
- allow-list executable paths;
- run under a restricted OS account;
- enforce timeouts;
- cap output/resource consumption.

---

# 13. CI/CD security target architecture

Current model:

```text
GitHub
  ↓
workflow
  ↓
SSH
  ↓
production host
  ↓
install/build/migrate
  ↓
restart service
```

Recommended model:

```text
Pull Request
   ↓
Lint
   ↓
Unit tests
   ↓
Integration tests
   ↓
SAST
   ↓
Secret scan
   ↓
Dependency scan
   ↓
Build immutable artifact
   ↓
Artifact scan
   ↓
Approval
   ↓
Deploy exact artifact
   ↓
DB migration strategy
   ↓
Health checks
   ↓
Smoke tests
   ↓
Promote
   ↓
Rollback capability
```

### Deployment principles

- build once;
- deploy the same artifact tested by CI;
- no `npm install` on production;
- no mutable dependency resolution on production;
- no arbitrary shell access from the application deployment process;
- explicit production approval;
- immutable release identifier;
- automatic health verification;
- documented rollback.

---

# 14. Recommended GitHub workflow hardening

Add:

```yaml
permissions:
  contents: read
```

Use SHA-pinned actions.

Separate security scanning from deployment.

Require the production environment for deployment and configure:

```text
required reviewers
deployment branch restrictions
secret separation
environment protection
```

Prefer short-lived credentials where the deployment platform supports them.

Never expose deployment credentials to pull-request code from untrusted forks.

---

# 15. Production configuration baseline

The following is a target baseline, not a copy/paste configuration:

```python
DEBUG = False

ALLOWED_HOSTS = [
    "ae.utbm.fr",
]

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

X_FRAME_OPTIONS = "DENY"  # use SAMEORIGIN only if the application requires framing
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
```

CSP should be designed from actual application dependencies rather than blindly copied.

---

# 16. Security regression suite to implement

Create a dedicated test package such as:

```text
security_tests/
├── test_authentication.py
├── test_authorization.py
├── test_csrf.py
├── test_host_header.py
├── test_security_headers.py
├── test_api_auth.py
├── test_api_bola.py
├── test_file_access.py
├── test_payment_integrity.py
├── test_payment_replay.py
├── test_payment_concurrency.py
├── test_money_precision.py
└── test_upload_security.py
```

## Minimum mandatory tests

### Host header

```text
unknown Host → 400
```

### Authorization

```text
A object + B credentials → 403/404
```

### API

```text
missing API key → 401/403
revoked API key → 401/403
wrong permission → 403
correct permission → success
```

### Payment

```text
invalid signature → rejected
wrong amount → rejected
wrong currency → rejected
replayed transaction → idempotent
concurrent callback → one financial result
```

### Money

```text
0.01 + 0.02 == 0.03
10.29 * 100 == 1029 cents
```

Do not test financial calculations through `float`.

---

# 17. Priority remediation roadmap

## P0 — Before treating production as hardened

- [ ] Remove `ALLOWED_HOSTS=["*"]`.
- [ ] Enforce `DEBUG=False` in production.
- [ ] Enforce HTTPS and secure cookies in production.
- [ ] Remove exception details from payment HTTP responses.
- [ ] Verify the complete payment callback security model.
- [ ] Perform an authorization/IDOR/BOLA test campaign.
- [ ] Audit direct/private file access.
- [ ] Scan full Git history for secrets.
- [ ] Rotate any credential found in history.
- [ ] Pin deployment actions to immutable SHAs.
- [ ] Restrict deployment SSH/sudo privileges.

## P1 — Security engineering

- [ ] Add dedicated security CI.
- [ ] Add SAST.
- [ ] Add dependency vulnerability scanning.
- [ ] Add secret scanning and push protection.
- [ ] Add security headers.
- [ ] Replace payment money `float` operations with `Decimal`.
- [ ] Introduce explicit payment transaction/idempotency records.
- [ ] Add API key expiration and rotation.
- [ ] Add security-event logging and Sentry scrubbing.
- [ ] Add authorization regression tests.

## P2 — Architecture hardening

- [ ] Move to immutable build artifacts.
- [ ] Remove dependency installation from production deployment.
- [ ] Add deployment health checks and rollback.
- [ ] Produce SBOMs.
- [ ] Implement CSP report-only then enforcement.
- [ ] Review file storage architecture.
- [ ] Add rate limits to expensive operations.
- [ ] Formalize data retention and privacy controls.

---

# 18. Suggested implementation order

The safest implementation sequence is:

```text
1. Production configuration hardening
        ↓
2. Payment response/error hardening
        ↓
3. Authorization test matrix
        ↓
4. File/media authorization audit
        ↓
5. Payment idempotency + Decimal
        ↓
6. CI security gates
        ↓
7. GitHub action SHA pinning
        ↓
8. Deployment privilege reduction
        ↓
9. Immutable artifact deployment
        ↓
10. Advanced headers/CSP/rate limiting
```

This order reduces the highest-risk exposure before larger architectural work.

---

# 19. Final assessment

## Current state

**HIGH RISK — not because the repository contains a confirmed trivial RCE, but because several high-value trust boundaries are weak or insufficiently verified.**

The most concerning boundaries are:

```text
Internet
   ↓
Django host/HTTPS configuration
   ↓
Authentication
   ↓
Object authorization
   ↓
Financial operations
   ↓
API credentials
   ↓
Private files
   ↓
Production deployment
```

The code already contains useful security abstractions. The main objective should therefore be to **make those controls mandatory, centrally enforced and regression-tested**, rather than adding isolated security checks throughout the codebase.

## Security maturity target

A realistic target architecture is:

```text
                ┌────────────────────┐
                │     Internet       │
                └─────────┬──────────┘
                          │ HTTPS
                          ▼
                ┌────────────────────┐
                │ Reverse proxy/WAF  │
                │ rate limits/headers│
                └─────────┬──────────┘
                          ▼
                ┌────────────────────┐
                │      Django        │
                │ auth + CSRF + ACL  │
                └──────┬─────┬───────┘
                       │     │
             ┌─────────┘     └──────────┐
             ▼                          ▼
      ┌─────────────┐            ┌─────────────┐
      │ PostgreSQL  │            │ Private file│
      │ constraints │            │ storage     │
      └─────────────┘            └─────────────┘
             │
             ▼
      ┌─────────────┐
      │ Audit logs  │
      │ + Sentry    │
      └─────────────┘

CI:

commit → tests → SAST → secrets → dependencies → build → scan → approve → deploy immutable artifact
```

The repository is in a good position to reach this target because authentication, object permissions, tests, dependency management and deployment automation already exist. The next step should be to turn the recommendations in this document into **security regression tests and small, reviewable pull requests**, starting with P0.

---

## Audit evidence reviewed

Key files reviewed directly during this audit:

- `sith/settings.py`
- `.env.example`
- `.gitignore`
- `pyproject.toml`
- `.github/workflows/ci.yml`
- `.github/workflows/deploy.yml`
- `api/auth.py`
- `api/models.py`
- `api/permissions.py`
- `api/urls.py`
- `core/auth/backends.py`
- `core/models.py`
- `eboutic/models.py`
- `eboutic/views.py`
- repository tree and application structure

### Evidence confidence

**Confirmed:** directly visible configuration/code behavior.  
**Verify:** requires complete endpoint traversal, runtime deployment access, production configuration or dedicated testing.  
**Recommendation:** architectural improvement rather than an asserted vulnerability.

---

## Conclusion

**Do not consider the application security-complete yet.**

The three areas that deserve the deepest engineering effort are:

1. **Authorization across every object and API endpoint.**
2. **Financial/payment integrity and idempotency.**
3. **Production/CI trust boundaries.**

Once these are covered by automated regression tests and production configuration checks, the remaining hardening work becomes much more manageable and measurable.
