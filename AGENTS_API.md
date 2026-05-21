# AGENTS_API.md — API Reference for AI Coding Agents

> For build commands, code style, and general conventions, see [AGENTS.md](./AGENTS.md).

## Request Lifecycle

1. TLS termination (TLS 1.2+, cert from config)
2. OpenTelemetry handler wrapper (if tracing enabled)
3. `limitRequestSize` (100 KB max body)
4. `metricsMiddleware` (Prometheus request counter + duration)
5. `auditLoggingMiddleware` (logs failures + GET/HEAD successes)
6. `loggingMiddleware` (structured zap log per request)
7. `tracingMiddleware` (OpenTelemetry span per request, skips `/_next` and `/metrics`)
8. Route dispatch → `requirePermission` (JWT extraction + OpenFGA check) → handler
9. Handler calls DB, returns JSON via `writeResponse`

## Route Map

All `/api/v1` routes are prefixed. Root routes are unprefixed.

### Root Routes (no prefix)

| Method | Path       | Handler     | Auth | Description                                         |
| ------ | ---------- | ----------- | ---- | --------------------------------------------------- |
| POST   | `/login`   | `Login`     | None | Local password login, sets `user_token` cookie      |
| POST   | `/logout`  | `Logout`    | None | Clears `user_token` cookie                          |
| GET    | `/status`  | `GetStatus` | None | Returns `{initialized, version, oidc_enabled}`      |
| GET    | `/metrics` | Prometheus  | None | Prometheus metrics endpoint                         |
| \*     | `/`        | Frontend FS | None | Serves Next.js static files from embedded `ui/out/` |

### Certificate Requests (`/api/v1/certificate_requests`)

| Method | Path                                            | Handler                             | Auth           | Description                                   |
| ------ | ----------------------------------------------- | ----------------------------------- | -------------- | --------------------------------------------- |
| GET    | `/certificate_requests`                         | `ListCertificateRequests`           | allRoles       | List all CSRs (requestors see only their own) |
| POST   | `/certificate_requests`                         | `CreateCertificateRequest`          | requestorRoles | Submit a new CSR (PEM)                        |
| GET    | `/certificate_requests/{id}`                    | `GetCertificateRequest`             | allRoles       | Get one CSR (requestors restricted to own)    |
| DELETE | `/certificate_requests/{id}`                    | `DeleteCertificateRequest`          | managerRoles   | Delete a CSR                                  |
| POST   | `/certificate_requests/{id}/reject`             | `RejectCertificateRequest`          | managerRoles   | Reject a CSR                                  |
| POST   | `/certificate_requests/{id}/sign`               | `SignCertificateRequest`            | managerRoles   | Sign CSR via CA or ACME                       |
| POST   | `/certificate_requests/{id}/certificate`        | `PostCertificateRequestCertificate` | managerRoles   | Upload a certificate chain to a CSR           |
| DELETE | `/certificate_requests/{id}/certificate`        | `DeleteCertificate`                 | managerRoles   | Delete certificate from a CSR                 |
| POST   | `/certificate_requests/{id}/certificate/revoke` | `RevokeCertificate`                 | managerRoles   | Revoke a certificate (adds to CRL)            |

### Certificate Authorities (`/api/v1/certificate_authorities`)

| Method | Path                                        | Handler                                 | Auth         | Description                           |
| ------ | ------------------------------------------- | --------------------------------------- | ------------ | ------------------------------------- |
| GET    | `/certificate_authorities`                  | `ListCertificateAuthorities`            | readerRoles  | List all CAs                          |
| POST   | `/certificate_authorities`                  | `CreateCertificateAuthority`            | managerRoles | Create a CA (self-signed or CSR-only) |
| GET    | `/certificate_authorities/{id}`             | `GetCertificateAuthority`               | readerRoles  | Get one CA                            |
| PUT    | `/certificate_authorities/{id}`             | `UpdateCertificateAuthority`            | managerRoles | Enable/disable a CA                   |
| DELETE | `/certificate_authorities/{id}`             | `DeleteCertificateAuthority`            | managerRoles | Delete a CA                           |
| POST   | `/certificate_authorities/{id}/sign`        | `SignCertificateAuthority`              | managerRoles | Sign an intermediate CA CSR           |
| POST   | `/certificate_authorities/{id}/certificate` | `PostCertificateAuthorityCertificate`   | managerRoles | Upload cert chain to a CA             |
| GET    | `/certificate_authorities/{id}/crl`         | `GetCertificateAuthorityCRL`            | **None**     | Get CA's CRL (public endpoint)        |
| POST   | `/certificate_authorities/{id}/revoke`      | `RevokeCertificateAuthorityCertificate` | managerRoles | Revoke a CA certificate               |

### Accounts (`/api/v1/accounts`)

| Method | Path                             | Handler                 | Auth             | Description                               |
| ------ | -------------------------------- | ----------------------- | ---------------- | ----------------------------------------- |
| GET    | `/accounts`                      | `ListAccounts`          | adminOnly        | List all user accounts                    |
| POST   | `/accounts`                      | `CreateAccount`         | firstUserOrAdmin | Create account (no auth if 0 users exist) |
| GET    | `/accounts/{id}`                 | `GetAccount`            | adminOnly        | Get one account by ID                     |
| GET    | `/accounts/me`                   | `GetMyAccount`          | allRoles         | Get current user's account                |
| DELETE | `/accounts/{id}`                 | `DeleteAccount`         | adminOnly        | Delete an account                         |
| POST   | `/accounts/{id}/change_password` | `ChangeAccountPassword` | adminOnly        | Admin changes any user's password         |
| PUT    | `/accounts/{id}/role`            | `UpdateAccountRole`     | adminOnly        | Change a user's role                      |
| POST   | `/accounts/me/change_password`   | `ChangeMyPassword`      | allRoles         | User changes own password                 |

### OIDC (conditional — only if `AuthnRepository != nil`)

| Method | Path                     | Handler        | Auth | Description                             |
| ------ | ------------------------ | -------------- | ---- | --------------------------------------- |
| GET    | `/api/v1/oauth/login`    | `LoginOIDC`    | None | Redirect to OIDC provider               |
| GET    | `/api/v1/oauth/callback` | `CallbackOIDC` | None | OIDC callback, sets `user_token` cookie |

### Config

| Method | Path             | Handler            | Auth     | Description                                    |
| ------ | ---------------- | ------------------ | -------- | ---------------------------------------------- |
| GET    | `/api/v1/config` | `GetConfigContent` | allRoles | Returns port, logging, encryption, ACME status |

## Middleware Chain

Applied in this order (first = outermost):

| #   | Middleware               | What it does                                                        |
| --- | ------------------------ | ------------------------------------------------------------------- |
| 1   | `limitRequestSize(100)`  | Rejects bodies > 100 KB with 413                                    |
| 2   | `metricsMiddleware`      | Records Prometheus request count + duration                         |
| 3   | `auditLoggingMiddleware` | Logs all failures + successful GET/HEAD to audit log                |
| 4   | `loggingMiddleware`      | Logs method, path, status to zap (skips `/_next`)                   |
| 5   | `tracingMiddleware`      | Creates OpenTelemetry span per request (skips `/_next`, `/metrics`) |

## Auth Model

### Authentication

- **Local**: Password login via `POST /login`. JWT (HMAC-SHA256) stored in `user_token` HttpOnly Secure SameSite=Strict cookie. Expires in 1 hour.
- **OIDC**: Redirect flow via `/oauth/login` → `/oauth/callback`. Auto-provisions new users. First OIDC user gets admin role.
- **Token verification**: `getClaimsFromCookie()` → `getClaimsFromJWT()` → `authentication.Verifier.VerifyToken()`. Supports both local and OIDC tokens.

### Authorization (OpenFGA)

- Object: `"system:notary"`
- Roles (RoleID): admin (0), certificate_manager (1), certificate_requestor (2), reader (3)
- `requirePermission(allowedRoles, env, handler)` checks each role via `AuthzRepository.Check()`.
- `firstUserOrAdmin` allows unauthenticated access when 0 users exist (first-run setup), then falls back to adminOnly.
- If `AuthzRepository == nil`, all `requirePermission` calls return 403.

### Role Groupings

| Group            | Roles                                                     |
| ---------------- | --------------------------------------------------------- |
| `allRoles`       | admin, certificate_manager, certificate_requestor, reader |
| `managerRoles`   | admin, certificate_manager                                |
| `requestorRoles` | admin, certificate_manager, certificate_requestor         |
| `readerRoles`    | admin, certificate_manager, reader                        |
| `adminOnly`      | admin                                                     |

## Handler Patterns

Every handler follows this pattern. Use this as a template for new handlers.

### Function Signature

```go
func MyHandler(env *HandlerDependencies) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // implementation
    }
}
```

### Standard Handler Body (from `CreateCertificateRequest`)

```go
// 1. Decode JSON body
var params CreateCertificateRequestParams
if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
    writeResponse(w, http.StatusBadRequest, "invalid JSON format", nil, env.SystemLogger)
    return
}

// 2. Validate
valid, err := params.IsValid()
if !valid {
    writeResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err), nil, env.SystemLogger)
    return
}

// 3. Extract JWT claims
claims, cookieErr := getClaimsFromCookie(r, env.Database.JWTSecret, env.AuthnRepository)
if cookieErr != nil {
    writeResponse(w, http.StatusUnauthorized, "unauthorized", nil, env.SystemLogger)
    return
}

// 4. Read path params
id := r.PathValue("id")
idNum, err := strconv.ParseInt(id, 10, 64)

// 5. Call DB
result, err := env.Database.SomeMethod(...)
if err != nil {
    if errors.Is(err, db.ErrNotFound) {
        writeResponse(w, http.StatusNotFound, "not found", nil, env.SystemLogger)
        return
    }
    env.SystemLogger.Error("failed to do thing", zap.Error(err))
    writeResponse(w, http.StatusInternalServerError, "", nil, env.SystemLogger)
    return
}

// 6. Audit log
env.AuditLogger.SomeEvent(...)

// 7. Return response
writeResponse(w, http.StatusCreated, "", map[string]int64{"id": newID}, env.SystemLogger)
```

### Response Helper

```go
// writeResponse(w, statusCode, message, data, logger)
// Returns JSON: {"message": "...", "data": ...}
// message is optional (use "" for no message)
// data is optional (use nil for no data)
writeResponse(w, http.StatusOK, "", myData, env.SystemLogger)
```

### Key Dependencies Available via `env`

| Field                      | Type                             | Use                              |
| -------------------------- | -------------------------------- | -------------------------------- |
| `env.Database`             | `*db.Database`                   | All DB operations                |
| `env.SystemLogger`         | `*zap.Logger`                    | Structured logging               |
| `env.AuditLogger`          | `*log.AuditLogger`               | Audit event logging              |
| `env.AuthnRepository`      | `*authentication.OIDCRepository` | OIDC config (nil if disabled)    |
| `env.AuthzRepository`      | `authorization.Repository`       | OpenFGA checks (nil if disabled) |
| `env.ACMERepository`       | ACME interface                   | ACME signing (nil if disabled)   |
| `env.EncryptionRepository` | Encryption backend               | Key encryption                   |
| `env.TracingRepository`    | `*tracing.TracingRepository`     | OpenTelemetry                    |
| `env.Port`                 | `int`                            | Server port                      |
| `env.ExternalHostname`     | `string`                         | External hostname for certs      |

## Notes for Agents

- **`GET /certificate_authorities/{id}/crl` has NO auth** — it's the only API route without `requirePermission`. This is intentional (CRLs are public).
- **`POST /accounts` uses `firstUserOrAdmin`** — allows unauthenticated access when 0 users exist. After first user is created, requires admin.
- **`GET /accounts/me` vs `GET /accounts/{id}`** — `/me` uses JWT claims, `/{id}` requires admin. `/me` must be registered BEFORE `/{id}` in the router or it won't match.
- **Certificate requestors are scoped** — `ListCertificateRequests` and `GetCertificateRequest` filter results to the requestor's own email when `RoleID == RoleCertificateRequestor`.
- **CA CSR collision check** — handlers check `GetCertificateAuthority(db.ByCertificateAuthorityCSRID(idNum))` before operating on a CSR to ensure it's not a CA's CSR. Uses `rowFound()` / `realError()` helpers.
- **Signing supports two methods** — `SignCertificateRequest` accepts `signing_method: "ca"` (default) or `"acme"`. ACME requires `env.ACMERepository != nil`.
- **Pebble notifications** — if `env.ShouldEnablePebbleNotifications`, certificate mutations trigger `pebble notify` commands.
- **Default admin protection** — `UpdateAccountRole` refuses to change the role of user ID 1 (the default admin).
- **OIDC auto-provisioning** — `CallbackOIDC` creates users on first login. First OIDC user gets admin. Subsequent users get reader. Email is optional (OIDC subject is the primary identifier).
- **Account deletion guard** — Cannot delete the last user account unless OIDC is enabled.
