# Security Audit — Sith

**Repository:** `GanaelDev/sith`  
**Branch audited:** `master`  
**Audit date:** 2026-09-08  
**Scope:** source tree, Django configuration, environment configuration, CI/CD workflows, dependency declarations, and repository-level security posture available through GitHub.

> **Important:** this is a repository/code audit, not a penetration test. Runtime infrastructure, production server configuration, GitHub secret values, database contents, network exposure, and historical objects that are not observable through the available repository APIs were not fully verified. Findings marked as "À confirmer" require runtime or privileged verification.

## 1. Executive summary

### Overall assessment

**Risk level: HIGH**

The application benefits from several good security foundations: Django's CSRF middleware is enabled, Jinja autoescaping is enabled, `SecurityMiddleware` and clickjacking protection are present, secrets are intended to come from environment variables, `.env` and SQLite databases are ignored by Git, and the project uses Dependabot plus automated tests/linting.

However, the current configuration contains several high-impact weaknesses, especially around production hardening:

1. `ALLOWED_HOSTS = ["*"]` removes Django's host-header restriction.
2. `SITH_DEBUG` is environment-controlled and there is no repository-level fail-closed production guard preventing a dangerous production configuration.
3. HTTPS security flags are conditional on `HTTPS`; the example environment explicitly sets `HTTPS=off`, making it easy to deploy an insecure configuration accidentally.
4. The production deployment executes remote shell commands through a GitHub Action and performs `git reset --hard`, package installation, migrations, and service restart directly on the production host. This is powerful and should be treated as a privileged deployment boundary.
5. GitHub Actions dependencies are not consistently pinned to immutable commit SHAs.
6. The repository is public, while the application appears to handle authentication, subscriptions, e-commerce/accounting, forum, student profiles, and other potentially sensitive data. This makes accidental disclosure of configuration, fixtures, logs, exports, or historical secrets particularly important to investigate.
7. The available static review could not establish that all authorization boundaries are correct across the application's many Django apps/API endpoints. This is the largest area requiring a dedicated authorization-focused review.

## 2. Findings by severity

| ID | Severity | Finding | Confidence |
|---|---|---|---|
| SEC-001 | **HIGH** | `ALLOWED_HOSTS = ["*"]` | Confirmed |
| SEC-002 | **HIGH** | Production security relies heavily on environment correctness; no fail-closed production configuration | Confirmed / architectural |
| SEC-003 | **HIGH** | HTTPS/session/CSRF hardening is conditional and example defaults to `HTTPS=off` | Confirmed |
| SEC-004 | **HIGH** | Privileged production deployment over SSH from GitHub Actions | Confirmed |
| SEC-005 | **MEDIUM-HIGH** | GitHub Actions use mutable version tags instead of immutable SHAs | Confirmed |
| SEC-006 | **MEDIUM** | Public repository + broad application scope increases impact of accidental secret/data exposure | Confirmed / risk assessment |
| SEC-007 | **MEDIUM** | Dependency security is not independently verified by this audit | Needs verification |
| SEC-008 | **MEDIUM** | No evidence from inspected workflows of dedicated SAST/secret scanning/dependency security gates | Confirmed for inspected CI |
| SEC-009 | **MEDIUM** | Security headers are only partially hardened | Confirmed / needs runtime verification |
| SEC-010 | **MEDIUM** | Authorization/API access control requires a dedicated endpoint-by-endpoint audit | Needs deeper review |
| SEC-011 | **LOW-MEDIUM** | `.env.example` contains a realistic-looking secret-shaped value despite being documented as non-production | Confirmed |
| SEC-012 | **LOW-MEDIUM** | CI executes with broad repository contents and should follow least-privilege workflow permissions | Needs verification |

---

## 3. Detailed findings

### SEC-001 — `ALLOWED_HOSTS = ["*"]`

**Severity:** HIGH  
**Status:** Confirmed  
**Location:** `sith/settings.py`

The Django configuration explicitly sets:

```python
ALLOWED_HOSTS = ["*"]
```

This disables Django's normal host allow-list protection. A production deployment should normally restrict hosts to the exact domains expected by the application.

### Impact

An attacker may be able to abuse an unexpected `Host` header. The exact exploitability depends on reverse-proxy configuration and how absolute URLs, redirects, password reset links, emails, caching, and other host-dependent behavior are implemented.

### Recommendation

Replace the wildcard with an environment-driven allow-list, for example:

```python
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=[])
```

Then configure production explicitly, e.g.:

```text
ALLOWED_HOSTS=ae.utbm.fr,www.ae.utbm.fr
```

Do not use `*` in production.

---

### SEC-002 — No fail-closed production security profile

**Severity:** HIGH  
**Status:** Confirmed / architectural  
**Location:** `sith/settings.py`, `.env.example`

The application reads security-sensitive settings from environment variables:

- `SECRET_KEY`
- `SITH_DEBUG`
- `HTTPS`
- `CSRF_TRUSTED_ORIGINS`
- `DATABASE_URL`
- cache/broker URLs

This is a good twelve-factor pattern, but the application does not appear to enforce a strong production security profile when these values are unsafe.

`DEBUG` defaults to `False`, which is good, but `HTTPS` defaults to `True` while the example explicitly changes it to `off`. More importantly, there is no visible invariant such as "production cannot start if DEBUG is enabled" or "production cannot start with wildcard hosts".

### Recommendation

Create explicit environment modes and fail fast in production:

```python
if not TESTING and not DEBUG:
    assert ALLOWED_HOSTS != ["*"]
```

Prefer a dedicated production settings layer or explicit startup checks rather than relying on operator discipline.

Add automated configuration tests asserting:

- `DEBUG=False` in production
- `ALLOWED_HOSTS` is non-empty and contains no wildcard
- HTTPS is enabled
- secure cookies are enabled
- HSTS is enabled when appropriate
- trusted origins are explicitly configured
- production database is not SQLite
- production email backend is not the dummy backend

---

### SEC-003 — HTTPS, session and CSRF security are conditional

**Severity:** HIGH  
**Status:** Confirmed  
**Location:** `sith/settings.py`, `.env.example`

The settings contain:

```python
HTTPS = env.bool("HTTPS", default=True)
CSRF_COOKIE_SECURE = HTTPS
SESSION_COOKIE_SECURE = HTTPS
```

This is logically coherent, but the repository's example configuration explicitly contains:

```text
HTTPS=off
```

For an application handling accounts and transactions, this creates a significant deployment foot-gun.

### Recommendation

For production, make HTTPS mandatory rather than configurable to insecure mode.

Recommended baseline:

```python
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

Only enable HSTS preload/includeSubDomains after verifying that every relevant subdomain is HTTPS-capable.

If TLS is terminated at a reverse proxy, correctly configure Django's proxy SSL handling and verify it with integration tests.

---

### SEC-004 — Privileged production deployment over GitHub Actions SSH

**Severity:** HIGH  
**Status:** Confirmed  
**Location:** `.github/workflows/deploy.yml`

The production workflow uses `appleboy/ssh-action` with secrets for a proxy and production server and executes commands directly on the host:

- `git fetch`
- `git reset --hard origin/master`
- `uv sync --group prod`
- `npm install`
- Xapian installation
- database migrations
- static collection
- message compilation
- `sudo systemctl restart uwsgi`

This is effectively a remote root-adjacent deployment capability because the workflow can invoke `sudo`.

### Main risks

- compromise of the GitHub workflow can become production compromise;
- mutable third-party actions increase supply-chain exposure;
- production state is directly modified from CI;
- `sudo systemctl restart uwsgi` means the deployment account has privileged local capabilities;
- `git reset --hard origin/master` makes the deployment process destructive to uncommitted server-side state;
- dependency installation happens directly on the production server.

### Recommendation

Prefer a build-once/deploy-artifact model:

1. Build a reproducible artifact/container in CI.
2. Run security and tests against the artifact.
3. Sign or checksum the artifact.
4. Deploy the exact immutable artifact.
5. Use a narrowly scoped deployment identity.
6. Restrict `sudo` to the exact required service command through `/etc/sudoers`.
7. Separate build credentials from deployment credentials.
8. Add deployment rollback support.

If SSH deployment remains, pin the SSH action to a commit SHA and harden the server-side deployment account.

---

### SEC-005 — Mutable GitHub Actions references

**Severity:** MEDIUM-HIGH  
**Status:** Confirmed  
**Location:** `.github/workflows/*.yml`

Examples include:

```yaml
uses: actions/checkout@v6
uses: actions/setup-python@v6
uses: pre-commit/action@v3.0.1
uses: appleboy/ssh-action@v1.2.5
uses: getsentry/action-release@v1.7.0
```

Version tags can move. A compromised or unexpectedly changed upstream tag could modify the code executed with repository/production privileges.

### Recommendation

Pin every third-party GitHub Action to an immutable commit SHA and document the corresponding release version in a comment.

Example pattern:

```yaml
uses: actions/checkout@<IMMUTABLE_COMMIT_SHA> # v6
```

Use Dependabot to propose updates while retaining SHA pinning.

---

### SEC-006 — Public repository and sensitive application scope

**Severity:** MEDIUM  
**Status:** Confirmed risk assessment

The repository is public. The README identifies the application as the source code for the UTBM student association website. fileciteturn6file0

The application contains numerous modules including authentication, subscriptions, e-commerce, accounting-related functionality, forum functionality, student profiles, API functionality, and administrative components.

A public repository is not inherently insecure, but the impact of any accidental secret, fixture containing personal data, production export, debug artifact, or private operational configuration is higher.

### Recommendation

Perform a dedicated historical secret/data scan covering:

- all Git history;
- tags/releases;
- deleted files;
- GitHub Actions artifacts;
- documentation examples;
- fixtures and test data;
- generated files;
- logs and database dumps.

Use GitHub secret scanning/push protection where available and complement it with a local scanner such as Gitleaks.

If any real credential has ever been committed, rotate it immediately; removing the file from the current tree is not sufficient.

---

### SEC-007 — Dependency security requires independent verification

**Severity:** MEDIUM  
**Status:** Needs verification

`pyproject.toml` pins dependency versions to ranges rather than fully locking every resolved package. The project uses modern dependencies including Django 5.2.x and several Django extensions. fileciteturn14file0

The repository also includes Dependabot configuration, which is a positive control, but this audit did not have access to a complete dependency vulnerability report.

### Recommendation

Add a CI security stage running at least:

- `uv audit` or an equivalent Python dependency vulnerability scanner;
- npm dependency audit appropriate to the frontend toolchain;
- OS/container scanning if containers are used;
- secret scanning;
- SAST.

Fail CI on critical vulnerabilities and define a remediation SLA for high-severity vulnerabilities.

---

### SEC-008 — No dedicated security gates visible in inspected CI

**Severity:** MEDIUM  
**Status:** Confirmed for inspected workflow

The inspected CI workflow runs pre-commit checks and tests/coverage. fileciteturn15file0

There is no visible dedicated job for:

- SAST;
- dependency vulnerability scanning;
- secret scanning;
- IaC scanning;
- security regression tests;
- container scanning.

### Recommendation

Add a dedicated `security` job with deterministic tools and explicit failure thresholds.

Suggested minimum stack:

```text
gitleaks
Semgrep
pip-audit / uv audit
npm audit or equivalent lockfile scanner
Trivy (if container/image deployment is introduced)
```

---

### SEC-009 — Security headers are only partially hardened

**Severity:** MEDIUM  
**Status:** Confirmed / needs runtime verification

The settings include:

```python
X_FRAME_OPTIONS = "SAMEORIGIN"
```

and Django's clickjacking middleware is enabled. `SecurityMiddleware` is also present. fileciteturn13file0

These are good foundations, but a production security baseline should also verify headers such as:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `Referrer-Policy`
- `Permissions-Policy`
- appropriate `Cache-Control` on sensitive responses

### Recommendation

Implement and test a deliberate header policy at the reverse proxy and/or Django layer. CSP deserves particular attention because the application uses a substantial server-rendered template surface.

Do not blindly deploy a restrictive CSP without testing all scripts, styles, images, fonts, and third-party integrations.

---

### SEC-010 — Authorization boundaries require a dedicated endpoint audit

**Severity:** MEDIUM  
**Status:** Needs deeper review

The application contains many Django apps and a dedicated API package. The settings show custom authentication components:

```python
AUTH_USER_MODEL = "core.User"
AUTHENTICATION_BACKENDS = ["core.auth.backends.SithModelBackend"]
```

There are also custom authorization helpers such as `can_edit_prop`, `can_edit`, and `can_view` exposed to templates. fileciteturn13file0

A repository-wide pattern search cannot establish whether every object access is correctly authorized.

### Priority audit targets

Review every endpoint involving:

- user profiles;
- subscriptions;
- payments/e-commerce;
- accounting;
- documents and uploaded files;
- forum moderation;
- club administration;
- election administration;
- student data;
- API endpoints;
- admin actions;
- object IDs supplied by users.

Specifically test for IDOR/BOLA vulnerabilities by changing object identifiers between users with different permissions.

---

### SEC-011 — Secret-shaped value in `.env.example`

**Severity:** LOW-MEDIUM  
**Status:** Confirmed

`.env.example` contains a long secret-looking `SECRET_KEY` value while explicitly stating that it is not the production key. fileciteturn11file0

This is not a confirmed credential leak, but it is unnecessarily realistic and can confuse developers or automated secret scanners.

### Recommendation

Use an obviously synthetic value, for example:

```text
SECRET_KEY=replace-with-a-random-secret
```

or generate a value during setup without committing one.

---

### SEC-012 — CI permissions should follow least privilege

**Severity:** LOW-MEDIUM  
**Status:** Needs verification

The inspected CI workflow does not declare a top-level `permissions:` policy. fileciteturn15file0

Explicitly declaring permissions prevents future workflow changes or GitHub defaults from granting more access than necessary.

### Recommendation

Start with:

```yaml
permissions:
  contents: read
```

Then grant write permissions only to the specific jobs that genuinely require them.

The production deployment job should be isolated and should receive only the permissions it requires.

---

## 4. Positive security controls already present

The audit found several good practices that should be retained:

- `DEBUG` defaults to `False`. fileciteturn13file0
- `SECRET_KEY` is loaded from the environment instead of hard-coded in application settings. fileciteturn13file0
- CSRF middleware is enabled. fileciteturn13file0
- Session and CSRF secure-cookie flags are available and tied to HTTPS. fileciteturn13file0
- Clickjacking protection is enabled through `XFrameOptionsMiddleware`. fileciteturn13file0
- Jinja autoescaping is enabled. fileciteturn13file0
- `.env`, SQLite databases, logs, virtual environments, node modules and several generated directories are ignored by Git. fileciteturn12file0
- Dependabot is configured in the repository. fileciteturn7file0
- CI executes automated tests and coverage. fileciteturn15file0
- The dependency file documents SHA-256 hashes for Xapian components to mitigate supply-chain attacks. fileciteturn14file0

These controls provide a useful baseline; the main issue is that production hardening is not sufficiently fail-closed.

---

## 5. Recommended remediation plan

### P0 — Immediate

- [ ] Replace `ALLOWED_HOSTS = ["*"]` with an explicit production allow-list.
- [ ] Confirm production has `DEBUG=False`.
- [ ] Force HTTPS in production.
- [ ] Confirm `SESSION_COOKIE_SECURE=True` and `CSRF_COOKIE_SECURE=True`.
- [ ] Audit the production reverse proxy for Host-header handling.
- [ ] Rotate any credential found during a complete Git-history scan.
- [ ] Verify the GitHub deployment key is dedicated to deployment and cannot obtain unnecessary privileges.
- [ ] Restrict the deployment user's `sudo` permissions to the minimum required command(s).

### P1 — Short term

- [ ] Pin every third-party GitHub Action to a commit SHA.
- [ ] Add `permissions: contents: read` by default to CI workflows.
- [ ] Add Gitleaks/secret scanning to CI.
- [ ] Add Python dependency vulnerability scanning.
- [ ] Add JavaScript dependency vulnerability scanning.
- [ ] Add SAST with Semgrep or equivalent.
- [ ] Add production configuration tests that fail CI when insecure settings are detected.
- [ ] Add HSTS and a deliberate security-header policy.
- [ ] Replace the secret-looking `.env.example` value with a clearly synthetic placeholder.

### P2 — Medium term

- [ ] Perform a complete authorization/IDOR/BOLA audit of all API and object-based views.
- [ ] Review file upload/download authorization and path handling.
- [ ] Review all administrative actions for privilege escalation.
- [ ] Review password-reset, email-verification, session, logout and account-recovery flows.
- [ ] Review rate limiting on login, password reset, CAPTCHA-protected endpoints and public APIs.
- [ ] Review sensitive response caching and browser cache headers.
- [ ] Review logging to ensure passwords, tokens, personal data and payment information are never logged.
- [ ] Move production deployment toward immutable artifacts instead of server-side dependency installation.

---

## 6. Security test matrix to add

| Area | Test |
|---|---|
| Host header | Reject unknown `Host` values |
| HTTPS | HTTP redirects to HTTPS; secure cookies remain enabled |
| CSRF | State-changing requests without valid CSRF token fail |
| Authentication | Brute-force/rate-limit behavior is bounded |
| Authorization | User A cannot read/modify User B objects |
| Privilege escalation | Normal user cannot invoke admin operations |
| IDOR/BOLA | Changing object IDs never bypasses permissions |
| File access | Private uploads cannot be accessed anonymously or by another user |
| Uploads | Dangerous extensions/content types are rejected or safely handled |
| XSS | User-controlled forum/profile/content fields remain escaped/sanitized |
| SQL injection | User input remains parameterized through Django ORM/raw SQL review |
| CSRF | API/session authentication combinations cannot bypass CSRF requirements |
| Session | Logout invalidates the expected session state |
| Password reset | Tokens expire, are single-use, and do not disclose account existence unnecessarily |
| Secrets | Repository and Git history contain no active credentials |
| CI/CD | Pull requests cannot obtain production deployment privileges unexpectedly |
| Dependencies | Known critical/high vulnerabilities fail security CI |
| Headers | HSTS/CSP/Referrer-Policy/etc. meet the documented baseline |
| Production config | Insecure configuration causes startup/CI failure |

---

## 7. Suggested secure baseline

A production baseline should converge toward:

```text
DEBUG=False
HTTPS=True
ALLOWED_HOSTS=<explicit production hosts>
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
CSRF_COOKIE_SECURE=True
SECURE_SSL_REDIRECT=True
SECURE_HSTS_SECONDS=<validated value>
SECURE_CONTENT_TYPE_NOSNIFF=True
X_FRAME_OPTIONS=SAMEORIGIN
```

In addition:

```text
GitHub Actions: immutable SHA-pinned actions
CI permissions: least privilege
Secrets: GitHub/environment secret store only
Deployment: immutable artifact
Production SSH: dedicated restricted identity
SAST: enabled
Secret scanning: enabled
Dependency scanning: enabled
Authorization tests: mandatory
```

---

## 8. Final verdict

**Do not consider the current repository configuration fully production-hardened.**

The most important immediate issue is the wildcard `ALLOWED_HOSTS`, followed by ensuring that production cannot accidentally run with insecure HTTP/cookie settings and by reducing the trust placed in the GitHub Actions → SSH → `sudo` deployment chain.

The next major security activity should be an **authorization and sensitive-data audit**, because the repository's breadth makes access-control mistakes potentially more damaging than classic framework misconfiguration.

### Priority order

1. **Fix `ALLOWED_HOSTS`.**
2. **Enforce HTTPS/security cookies in production.**
3. **Introduce fail-closed production security checks.**
4. **Harden GitHub Actions and pin third-party actions.**
5. **Audit/rotate secrets across Git history.**
6. **Add SAST + secret + dependency scanning.**
7. **Perform endpoint-by-endpoint authorization/IDOR testing.**
8. **Move toward immutable, least-privilege deployments.**

**Audit conclusion: HIGH risk until P0 findings are remediated; medium residual risk is expected afterward until authorization and runtime penetration testing are completed.**
