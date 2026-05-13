# Agent Development Guide

> **⚠️ Read this first.** This file is the authoritative source for all conventions, build commands, code style, and common pitfalls.
> For API details see [AGENTS_API.md](./AGENTS_API.md). For database details see [AGENTS_DB.md](./AGENTS_DB.md).
> **Read these context files before exploring source files — they exist to save you context.**

This guide provides coding agents with essential information for working in the Notary codebase.

## Project Overview

Notary is a TLS certificate management application with:

- **Backend**: Go 1.24.4 with HTTP API (Cobra CLI framework)
- **Frontend**: Next.js (TypeScript/React)
- **Database**: SQLite with migrations
- **Distribution**: Snap packages and OCI containers (Rockcraft)

## Build & Test Commands

### Backend (Go)

**Build**:

```bash
make notary                    # Build complete application (backend + frontend)
go build -o artifacts/notary   # Build backend only
```

**Test**:

```bash
go test ./...                  # Run all tests
go test -cover ./...           # Run tests with coverage
go test ./internal/db          # Run tests in specific package
go test -v -run TestLoginEndToEnd ./internal/server  # Run single test
```

**Lint & Format**:

```bash
golangci-lint run ./...        # Lint Go code (v1.64.5)
go vet ./...                   # Static analysis
```

### Frontend (TypeScript/React)

**Build**:

```bash
npm run build --prefix ui      # Production build
npm run dev --prefix ui        # Development server
```

**Test**:

```bash
npm run test --prefix ui       # Run all tests (Vitest)
npm run test-live --prefix ui  # Watch mode
```

**Lint & Format**:

```bash
npm run lint --prefix ui       # ESLint check
npm run format --prefix ui     # Prettier format (auto-fix)
npx prettier -c src/ --prefix ui  # Prettier check only
```

### Running the Application

```bash
make notary                    # Build everything
artifacts/notary start --config artifacts/config.yaml  # Start server
# Access UI at https://localhost:2111
```

## Code Style Guidelines

### Go (Backend)

**Imports**:

- Standard library imports first
- Blank line separator
- Third-party imports second
- Blank line separator
- Internal imports last (use `github.com/canonical/notary/internal/...`)
- Use import aliases for clarity: `tu "github.com/canonical/notary/internal/testutils"`
- Backend encryption import: `eb "github.com/canonical/notary/internal/encryption_backend"`

**Naming Conventions**:

- Package names: lowercase, single word (e.g., `package config`, `package server`)
- Exported functions: PascalCase (e.g., `CreateAppContext`, `ValidateConfig`)
- Unexported functions: camelCase (e.g., `initializeLogger`, `validateServerConfig`)
- Test files: `*_test.go` with `_test` package suffix (e.g., `package server_test`)
- Constants: PascalCase or ALL_CAPS for exported

**Error Handling**:

- Wrap errors with context: `fmt.Errorf("failed to initialize config: %w", err)`
- Return errors, don't panic (except in init or main for fatal issues)
- Check errors immediately: `if err != nil { return nil, err }`
- Use `errors.New()` for simple errors without formatting

**Testing**:

- Table-driven tests preferred
- Use subtests: `t.Run("descriptive name", func(t *testing.T) {...})`
- Test file pattern: `func TestFunctionName(t *testing.T)`
- Use `internal/testutils` package (aliased as `tu`) for common test utilities
- Always check status codes: `if statusCode != http.StatusOK { t.Fatalf(...) }`

**Functions**:

- Document exported functions with comments starting with function name
- Keep functions focused and single-purpose
- Prefer returning errors over panic

**Types**:

- Use strict typing, avoid `interface{}` unless necessary
- Prefer explicit types over type inference for clarity in complex code

### TypeScript/React (Frontend)

**Imports**:

- React/Next.js imports first
- Third-party library imports
- Blank line separator
- Internal imports using `@/` alias (maps to `./src/*`)
- Example order: React, external libs, `@/components`, `@/hooks`, `@/types`

**Naming Conventions**:

- Components: PascalCase (e.g., `NotaryLayout`, `CertificateRequestsTable`)
- Files: Match component name (e.g., `NotaryLayout.tsx`)
- Hooks: camelCase with `use` prefix (e.g., `useLoginRedirect`)
- Types/Interfaces: PascalCase (e.g., `CSREntry`, `LoginParams`)

**TypeScript**:

- Strict mode enabled - all code must be type-safe
- No implicit `any` - always provide explicit types
- Use interfaces for object shapes
- Use `type` for unions, intersections, or mapped types
- Prefer `Readonly<>` for immutable props

**React Patterns**:

- Use functional components with hooks
- Mark client components with `"use client"` directive at top of file
- Use React Query (`@tanstack/react-query`) for data fetching
- Keep components small and focused

**Formatting**:

- Prettier enforced (defaults used)
- ESLint configuration: Next.js + TypeScript recommended + prettier compatibility
- Double quotes for strings (Prettier default)
- 2-space indentation
- Semicolons required

**Testing**:

- Use Vitest with `@testing-library/react`
- Test file pattern: `*.test.tsx` or `*.test.ts`
- Import test functions: `import { expect, test } from "vitest"`
- Import render utilities: `import { render, screen } from "@testing-library/react"`
- Wrap components needing React Query in `QueryClientProvider`

## Project Structure

```
/
├── cmd/                       # CLI commands (start, backup, migrate, version)
├── internal/                  # Internal application code
│   ├── auth/                 # Authentication logic
│   ├── config/               # Configuration management
│   ├── db/                   # Database layer (SQLite)
│   ├── encryption/           # Encryption utilities
│   ├── encryption_backend/   # HSM/Vault backend support
│   ├── server/               # HTTP server and handlers
│   ├── testutils/            # Testing utilities
│   ├── metrics/              # Prometheus metrics
│   ├── tracing/              # OpenTelemetry tracing
│   └── logging/              # Logging utilities
├── ui/                       # Next.js frontend
│   ├── src/
│   │   ├── app/             # Next.js app directory (routes)
│   │   ├── components/      # React components
│   │   ├── hooks/           # Custom React hooks
│   │   └── types.ts         # TypeScript type definitions
│   ├── package.json
│   └── tsconfig.json
├── main.go                   # Application entry point
├── Makefile                  # Build automation
└── artifacts/                # Build outputs (gitignored)
```

## Key Technologies

- **Logging**: zap (structured logging)
- **Database**: SQLite with custom migration system
- **API**: Standard net/http with custom handlers
- **Auth**: JWT + OIDC support
- **Metrics**: Prometheus
- **Tracing**: OpenTelemetry + Jaeger
- **Frontend State**: React Query
- **Testing**: Go testing (backend), Vitest (frontend)

## Best Practices

1. **Always run tests** after making changes
2. **Lint before committing**: Both Go and TypeScript
3. **Use semantic commit messages**: CI enforces this
4. **Database migrations**: Never modify existing migrations, always add new ones
5. **Error logging**: Use structured logging (zap), include context
6. **Security**: Never commit secrets; use config files in artifacts/ (gitignored)
7. **Dependencies**: Go modules for backend, npm for frontend

## Reference Documentation

- [Go Best Practices](https://docs.google.com/document/d/1IbFXyeXYlfQ5GUEEScGS7pP335Cei-5cFBdAoR973pQ/edit?tab=t.0)
- [Online Documentation](https://canonical-notary.readthedocs-hosted.com/)
- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [AGENTS_API.md](./AGENTS_API.md) — API routes, middleware, auth model, handler patterns
- [AGENTS_DB.md](./AGENTS_DB.md) — Database schema, tables, query patterns

## Common Pitfalls & Gotchas

- **Database migrations**: Never modify existing migration files. Always create a new migration file for schema changes. Modifying old migrations will break existing deployments.
- **Config files**: Never commit real secrets or production config. Use `artifacts/config.yaml` (gitignored) for local development.
- **Encryption backends**: When testing HSM/Vault integration, always verify the backend is reachable before running certificate operations. Fallback to software encryption only for local dev.
- **Frontend state**: React Query caches aggressively. After mutating data (POST/PUT/DELETE), always invalidate relevant queries to avoid stale UI.
- **Error wrapping**: Always wrap errors with context using `%w`. Bare `return err` loses valuable debugging information.
- **Test isolation**: Database tests use a shared test DB. Use `t.Parallel()` carefully and clean up test data in each subtest.
- **ACME feature** (in development on `acme-hackathon` branch): ACME account management and certificate issuance flows are still evolving. Check `internal/acme/` and related handlers before making changes.
- **Import order**: Go imports must follow the exact order documented above. `golangci-lint` will fail the build on incorrect grouping.

## Database Migrations

- All migrations live in `internal/db/migrations/`.
- Never edit or delete an existing migration file.
- To make schema changes, create a new timestamped migration file following the existing naming pattern.
- After adding a migration, run `go test ./internal/db/...` to verify the migration applies cleanly.
- The migration system is custom (not a third-party library). Study `internal/db/db_init.go` and `sql_stmts.go` before writing new migrations.

## Maintaining This Guide

This file (`AGENTS.md`) is the primary source of truth for AI coding agents.
It must stay accurate as the codebase evolves.

**When to update this file:**

- Adding a new major feature or package (e.g., ACME support, new encryption backend, new frontend module)
- Discovering a new common pitfall, gotcha, or anti-pattern
- Changing build/test/lint commands or introducing new tooling
- Modifying import conventions, naming rules, or error-handling patterns
- Adding or changing database migration rules

**How to update:**

1. Add relevant entries to the **Project Structure** section.
2. Document new patterns in the appropriate **Code Style Guidelines** subsection.
3. Add new items to **Common Pitfalls & Gotchas**.
4. Update the **Key Technologies** list if new dependencies are introduced.
5. For large features (like ACME), consider adding a short dedicated subsection under Project Overview or Pitfalls.

**Example:** When implementing the ACME feature, the PR should also update the "Common Pitfalls & Gotchas" section with any ACME-specific warnings and mention the `internal/acme/` package in the structure.

Keep the file concise but authoritative. If a topic grows too large, extract it into a dedicated file under `docs/` and link to it from here.
