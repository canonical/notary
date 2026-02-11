# Agent Notes (Notary)

Repo layout:
- Backend: Go (`go.mod` module `github.com/canonical/notary`, Go `1.24.4`)
- Frontend: Next.js + TypeScript in `ui/` (Vitest, ESLint, Prettier)
- Docs: Sphinx in `docs/`

Agent rules:
- Cursor: no `.cursor/rules/` or `.cursorrules` found.
- Copilot: no `.github/copilot-instructions.md` found.

## Folders

- `.github/`: CI workflows, PR templates, automation.
- `artifacts/`: local build output (binary, config, TLS material, sqlite db); don’t commit.
- `cmd/`: Cobra CLI commands (`notary start`, `notary migrate`, `notary version`).
- `docs/`: Sphinx site sources.
- `docs/explanation/`: conceptual/background docs.
- `docs/how-to/`: task-oriented guides.
- `docs/reference/`: API/config/roles/metrics reference.
- `docs/tutorials/`: step-by-step tutorials.
- `internal/`: backend implementation (not imported by other modules).
- `internal/auth/`: JWT/OIDC claim types and helpers.
- `internal/config/`: config parsing/validation, logger/tracing/encryption initialization.
- `internal/db/`: SQLite access layer, filters, validation, migrations, sentinel errors.
- `internal/encryption/`: encryption primitives used by DB/backends.
- `internal/encryption_backend/`: Vault/PKCS#11/no-op backends.
- `internal/hashing/`: password hashing/verification.
- `internal/logging/`: audit logging and security event helpers.
- `internal/metrics/`: Prometheus metrics subsystem.
- `internal/server/`: HTTP router, middleware, handlers, response helpers.
- `internal/testutils/`: shared test fixtures/helpers.
- `internal/tracing/`: OpenTelemetry/tracing wiring.
- `service/`: snap/service runtime files (default config, wrapper scripts).
- `snap/`: snap packaging definition and install hooks.
- `ui/`: Next.js app; edit source in `ui/src/`.
- `ui/src/`: frontend code (components, hooks, pages, API client).
- `ui/out/`, `ui/.next/`: generated build output; don’t edit/commit.
- `version/`: embedded version string (`version/VERSION` + helper).

## Build / Lint / Test

Backend build (also builds UI to `ui/out`):
```bash
make notary
```

Backend only:
```bash
go build -o artifacts/notary
```

Run server (after build):
```bash
artifacts/notary start --config artifacts/config.yaml
```

Go tests:
```bash
go test ./...
go test ./internal/server
go test ./internal/server -run '^TestLogin$' -count=1
go test ./internal/db -run 'CertificateAuthority' -count=1
```
Go lint/vet (CI uses golangci-lint):
```bash
golangci-lint run ./...
go vet ./...
```

Go note: SQLite is `github.com/mattn/go-sqlite3` (CGO); local dev may require `CGO_ENABLED=1`.

CI note: PR titles are validated with Semantic Pull Requests (`.github/workflows/pr-lint.yml`).

Frontend (run from repo root):
```bash
npm install --prefix ui
npm run dev --prefix ui
npm run build --prefix ui
npm run lint --prefix ui
npm run format --prefix ui
npx --prefix ui prettier -c src/
npm run test --prefix ui
npm run test --prefix ui -- src/app/(notary)/certificate_requests/table.test.tsx
npm run test --prefix ui -- -t 'CertificateRequestsPage'
```

Tip: keep using `--prefix ui` (the lockfile lives in `ui/`).

Docs:
```bash
make -C docs install
make -C docs run
make -C docs html
make -C docs spelling
make -C docs woke
make -C docs linkcheck
```

Optional packaging:
```bash
make rock
make deploy
```

## Code Style

General:
- Keep changes small; follow existing patterns and API shapes.
- Don’t commit generated/local artifacts: `artifacts/`, `ui/out/`, `ui/.next/`, `*.db`, local `.env`.

Go (backend):
- Formatting: run `gofmt` on changed files.
- Imports: standard gofmt grouping; avoid dot imports; alias only when clarity demands.
- Errors: wrap with `%w`; check sentinels with `errors.Is`; use `internal/db/errors.go` sentinels for expected cases.
- HTTP: responses are JSON envelopes (`result` or `error`) via `internal/server/response.go`; avoid bespoke JSON.
- Status codes: `400` invalid input, `401` auth, `403` denied, `404` not found, `500` internal.
- AuthZ: use router-level `requirePermission(...)` (`internal/server/router.go`) and enforce per-resource ownership in handlers.
- Logging: structured `zap` fields; security events via `internal/logging/*`; never log secrets/PEMs/tokens.
- Panics: avoid in request paths; ok only for impossible invariants in internal helpers.

TypeScript / Next.js (frontend in `ui/`):
- Formatting: Prettier; lint via `npm run lint --prefix ui`.
- TS config: ESM (`"type": "module"`), `strict: true`, path alias `@/*` -> `ui/src/*`.
- Imports: prefer `@/…`; keep `"use client";` as the first statement in client components.
- Types: define/export API shapes in `ui/src/types.ts`; avoid `any` and broad `eslint-disable` (tighten types instead).
- Data fetching: API helpers in `ui/src/queries.ts`; on non-`ok`, throw with backend `error` message preserved.
- Naming: components `PascalCase`, hooks `useX`, vars/functions `camelCase`, constants `UPPER_SNAKE_CASE`.
- Tests: Vitest + Testing Library; assert on user-visible output (role/text) over implementation details.

Docs:
- Keep changes consistent with existing MyST/Sphinx patterns in `docs/`.
- For prose changes, run `make -C docs spelling` and `make -C docs woke`.

## Useful Pointers

Backend entrypoints:
- CLI commands: `cmd/root.go`, `cmd/start.go`
- HTTP router/middleware: `internal/server/router.go`, `internal/server/middleware.go`
- API response helpers: `internal/server/response.go`
- DB sentinel errors: `internal/db/errors.go`

Frontend pointers:
- API client wrappers: `ui/src/queries.ts`
- Shared types: `ui/src/types.ts`
- Example test: `ui/src/app/(notary)/certificate_requests/table.test.tsx`
