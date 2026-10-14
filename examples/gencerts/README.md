# gencerts

Writes a throwaway CA and a certificate for `localhost` to a directory, laid out like a cert-manager Secret, so you can try keyload and the other examples. With `-rotate` it issues a new certificate from the same CA, the way a renewal would.

These certificates are for demos and tests only.

## Run it

No clone needed:

```sh
go run github.com/rossedman/keyload/examples/gencerts@latest -dir /tmp/keyload
```

Or from a clone of this repository:

```sh
go run ./examples/gencerts -dir /tmp/keyload                    # CA and certificate
go run ./examples/gencerts -dir /tmp/keyload -rotate            # a new certificate from the same CA
go run ./examples/gencerts -dir /tmp/keyload -rotate -ttl 30m   # a short-lived one
```

## What you'll see

```
wrote /tmp/keyload/tls.crt (serial 71F6D420B035AF3D, expires 2026-10-15T13:21:32Z)
```

The directory then holds:

| File | Contents |
|---|---|
| `ca.crt` | The CA certificate. Use it as `Roots` and `ClientCAs`. |
| `ca.key` | The CA's private key, kept so `-rotate` can issue from the same CA. |
| `tls.crt` | A certificate for `localhost` and `127.0.0.1`, valid for both server and client auth. |
| `tls.key` | Its private key. |

| Flag | Default | |
|---|---|---|
| `-dir` | `keyload-certs` | Directory to write to. |
| `-rotate` | off | Issue a new certificate from the existing CA instead of creating a new CA. |
| `-ttl` | `24h` | Lifetime of the certificate. Try `-ttl 30m` with `keyload.MinRemaining(time.Hour)`. |

## How it works

`tls.crt` and `tls.key` are each written to a temporary file and renamed into place, as certificate managers do. The two files are still replaced one after the other, so for a moment the new certificate sits next to the old key. keyload retries that briefly instead of rejecting it, which you can watch in the [server](../server) example.

Each certificate gets a random serial number, so rotations never reuse one.

## Test

```sh
go test ./examples/gencerts
```

Source: [`main.go`](main.go)
