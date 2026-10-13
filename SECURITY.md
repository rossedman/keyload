# Security policy

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/rossedman/keyload/security/advisories/new)
for this repository. You should get a response within a few days. Once a fix
is released you will be credited in the advisory unless you prefer otherwise.

## Supported versions

Security fixes go into the latest release.

## Where verification happens

keyload leaves certificate verification to crypto/tls everywhere except
Config mode:

- `ServerConfig`, `DialTLSContext`, `ConfigureTransport` and the `grpccreds`
  module hand crypto/tls an ordinary `tls.Config` built from the current
  files.
- `ClientConfig` (Config mode) sets `InsecureSkipVerify` and verifies the
  server itself in `VerifyConnection` (`verifyServer` in `client.go`). This is
  the only custom verification path.

Config mode:

1. Refuses to build without `ServerName`, so the hostname is always checked.
2. Calls `x509.Certificate.Verify` with the current roots, the peer's
   intermediates, `DNSName = ServerName`, `KeyUsages = ServerAuth` and the
   config's clock: the options crypto/tls uses.
3. Runs on every handshake, including resumed sessions.
4. Runs the caller's own `VerifyConnection` after it.
5. Leaves `ConnectionState.VerifiedChains` empty, because crypto/tls did not
   verify.

`TestConfigModeMatchesStdlib` checks Config mode against crypto/tls on 2,000
generated chains in CI and fails on any disagreement.

Config mode has **not** had an external security review yet. One is planned
before 1.0 and will be published here.

## Deployment notes

- Events and errors name files and certificate subjects and serials. They
  never contain key material.
- Mount private keys read-only and readable only by the service's user.
