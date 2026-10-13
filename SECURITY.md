# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/rossedman/keyload/security/advisories/new)
rather than in a public issue.

## Where verification happens

keyload leaves certificate verification to `crypto/tls` in every mode except
one:

- `Reloader.ServerConfig`, `Reloader.DialTLSContext`,
  `Reloader.ConfigureTransport` and the `grpccreds` module hand crypto/tls an
  ordinary `tls.Config` built from the current snapshot.
- `Reloader.ClientConfig` ("Config mode") sets `InsecureSkipVerify` and
  verifies the server itself in `VerifyConnection`
  (`verifyServer` in `client.go`). This is the only custom verification path
  and the part that most needs review.

Config mode rules:

1. It refuses to build if `ServerName` is empty, so a hostname is always
   checked.
2. It calls `x509.Certificate.Verify` with the snapshot's roots, the peer's
   intermediates, `DNSName = ServerName`, `KeyUsages = ServerAuth` and the
   config's clock: the options crypto/tls uses.
3. It runs on every handshake, including resumed sessions.
4. The caller's own `VerifyConnection` runs after it.
5. `ConnectionState.VerifiedChains` is empty, because crypto/tls did not
   verify.

`TestConfigModeMatchesStdlib` checks Config mode against crypto/tls on
generated chains and fails on any disagreement.

## Review status

Config mode has **not** had an external security review yet. One is planned
before v1.0 and will be published in this repository.
