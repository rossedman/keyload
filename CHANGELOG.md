# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may
change the API.

## [Unreleased]

## [0.1.0] - 2026-10-13

The first release: reload TLS certificates, keys and CA bundles while a
server or client keeps running.

### Added

- `keyload.New(keyload.Files{...})` loads, validates and watches certificate,
  key and CA bundle files, and keeps the last good material when a reload is
  bad.
- Validation: key matches certificate, validity window, `MinRemaining`,
  optional `RequireChain`, non-empty CA bundles, truncated PEM. Half-written
  files are retried before a reload is rejected.
- File watching with inotify that handles the Kubernetes Secret volume
  `..data` symlink swap, with a 30-second polling fallback on NFS, FUSE and
  non-Linux systems. Reloads also on `OnSignal`, `PollEvery` and `Reload`.
- `ServerConfig` for any crypto/tls server; `ConfigureTransport` and
  `DialTLSContext` for HTTP clients and raw dials; `ClientConfig` (Config
  mode) for libraries that only accept a `*tls.Config`.
- `github.com/rossedman/keyload/grpccreds` module with transport credentials
  for grpc-go.
- `OverlapWindow` keeps removed CAs trusted for a while during a CA rotation.
- `OnReload` events, `Stats`, and Prometheus metrics via `MetricsHandler`.
- Runnable examples, a docs site, benchmarks, differential tests of Config
  mode against crypto/tls, and fuzzing.

[Unreleased]: https://github.com/rossedman/keyload/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rossedman/keyload/releases/tag/v0.1.0
