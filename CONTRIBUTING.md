# Contributing to keyload

Thanks for your interest! Bug reports, docs fixes and pull requests are all welcome.
Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development

Requirements: Go 1.24 or newer, and `make`.

```sh
make            # lint and test both modules
make race       # tests with the race detector
make cover      # coverage; CI requires 90% or more
make bench      # benchmarks
make fuzz       # fuzz the PEM parsing for a minute
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
- Run `gofmt`. CI rejects unformatted code.
- Update `README.md`, the site and `CHANGELOG.md` for user-visible changes.

## The website

The docs site is `site/index.html`, one static page with no build step. The
Pages workflow deploys it when it changes on `main`. Preview it with
`make site-serve`.

## Releases

The repository has two modules, released together with the same version:
`github.com/rossedman/keyload` (tag `vX.Y.Z`) and
`github.com/rossedman/keyload/grpccreds` (tag `grpccreds/vX.Y.Z`).

1. Rename `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z] - YYYY-MM-DD`
   (it becomes the release notes) and add a fresh `[Unreleased]` section.
2. Set `require github.com/rossedman/keyload vX.Y.Z` in `grpccreds/go.mod`
   (`make bump VERSION=vX.Y.Z` does this), and merge.
3. Either push a tag (`git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`)
   or run the **Release** workflow from the Actions tab with the version,
   which tags the branch head for you.

The workflow checks the changelog and `grpccreds/go.mod`, runs the tests,
creates both tags, and publishes a GitHub release with the changelog
section as its notes. pkg.go.dev picks up the new version on its own.
