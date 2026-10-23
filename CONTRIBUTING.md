# Contributing to keyload

Thanks for your interest! Bug reports, docs fixes and pull requests are all welcome.
Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development

Requirements: Go 1.24 or newer, `make` and
[golangci-lint](https://golangci-lint.run/welcome/install/) v2.

```sh
make check      # everything CI checks, except the long fuzz runs
make            # lint and test both modules
make race       # tests with the race detector
make cover      # coverage of library code; must be 90% or more
make doccheck   # every function, method and package has a doc comment
make vuln       # govulncheck on both modules
make bench      # benchmarks
make fuzz       # fuzz every target for 30s (FUZZTIME=1m to change)
```

Try the examples with throwaway certificates:

```sh
go run ./examples/gencerts -dir /tmp/keyload
go run ./examples/server -dir /tmp/keyload
go run ./examples/gencerts -dir /tmp/keyload -rotate   # watch the server reload
```

## Layout

```
*.go                 the keyload package (standard library only)
grpccreds/           grpc-go transport credentials (its own module)
examples/            runnable example programs, each with a test
internal/testpki/    certificate generation for tests and examples
site/                the docs site (one static page)
```

## Guidelines

- Keep keyload small. The core module has **no third-party dependencies**;
  anything that needs one belongs in its own module, like `grpccreds`.
- Leave certificate verification to crypto/tls. `ClientConfig` is the only
  exception; changes to it need a matching case in
  `TestConfigModeMatchesStdlib`.
- Add tests for behaviour changes; `go test -race ./...` must pass and
  coverage must stay at or above 90%.
- The handshake path must not allocate (`TestHotPathAllocations`).
- Run `gofmt`. CI rejects unformatted code, and `golangci-lint` findings.
- Every function and method, exported or not, has a doc comment starting
  with its name (`make doccheck`).
- Update `README.md`, the site and `CHANGELOG.md` for user-visible changes.
- Every example in `examples/` has a README: what it shows, how to run it,
  real output, and how it works. Keep the output current when behavior changes.

## Critical paths

These need a benchmark, and the ones that take outside input need a fuzz
target or property test. Add to the list when you add code like this.

| Path | Code | Benchmark | Fuzz or property test |
| --- | --- | --- | --- |
| Parsing PEM material | `parseMaterial`, `parseBundle`, `checkPEMKey` (`parse.go`) | `BenchmarkReload` | `FuzzParseMaterial` |
| Chain verification | `verifyChain` (`parse.go`), `verifyServer` (`client.go`) | `BenchmarkVerify` | `TestConfigModeMatchesStdlib` (2,000 generated chains against crypto/tls) |
| Reload | `Reloader.reload`, `build`, `diffSnapshots` (`reloader.go`) | `BenchmarkReload` | `FuzzParseMaterial` covers its input |
| Handshake hot path | `Current`, `ServerConfig`, `ClientConfig`, `DialTLSContext` | `BenchmarkCurrent`, `BenchmarkServerHandshakeConfig`, `BenchmarkDialerConfig` | none: no outside input; allocations gated by `TestHotPathAllocations` |
| Metrics output | `writeMetrics`, `escapeLabel` (`metrics.go`) | `BenchmarkWriteMetrics` | `FuzzEscapeLabel`, `FuzzWriteMetrics` |

## The website

The docs site is `site/index.html`, one static page with no build step. The
Pages workflow deploys it when it changes on `main`. Preview it with
`make site-serve`.

## Releases

The repository has two modules, released together with the same version:
`github.com/rossedman/keyload` (tag `vX.Y.Z`) and
`github.com/rossedman/keyload/grpccreds` (tag `grpccreds/vX.Y.Z`).

1. Rename `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z] - YYYY-MM-DD`
   (it becomes the release notes), add a fresh `[Unreleased]` section, run
   `make bump VERSION=vX.Y.Z` to point `grpccreds/go.mod` at the new version,
   and merge.
2. Run `make release VERSION=vX.Y.Z`. It checks `origin/main`, creates both
   tags on it and pushes them.

Pushing the tags starts the **Release** workflow, which runs the tests and
publishes the GitHub release with the changelog section as its notes.
pkg.go.dev picks up the new version on its own.

Tags are created locally rather than by the workflow because the repository's
tag ruleset only lets the maintainer create tags, and a personal repository's
ruleset can't exempt GitHub Actions. Don't create releases in the GitHub UI:
that makes only the `vX.Y.Z` tag, so the workflow stops and asks for
`make release`.
