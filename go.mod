module github.com/NX1X/Egret-Nest-Dashboard

go 1.25.12

// Dependencies are intentionally minimal (see docs/DEPENDENCIES.md).
// Run `go mod tidy` (or `make tidy`) to populate the require block + go.sum.
// It resolves, from the imports:
//   - modernc.org/sqlite      (pure-Go SQLite, no CGO) + its modernc.org/* deps
//   - golang.org/x/crypto     (argon2id password hashing)
// Both are permissive-licensed and vetted in docs/DEPENDENCIES.md.

require (
	github.com/coreos/go-oidc/v3 v3.19.0
	golang.org/x/crypto v0.53.0
	golang.org/x/oauth2 v0.36.0
	modernc.org/sqlite v1.53.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.46.0 // indirect
	modernc.org/libc v1.73.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
