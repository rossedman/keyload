# metrics

Serves Prometheus metrics for a keyload `Reloader` and logs every reload as structured JSON. Use it to alert before a certificate expires, and when bad files are being pushed.

## Run it

```sh
go run ./examples/gencerts -dir /tmp/keyload
go run ./examples/metrics -dir /tmp/keyload
```

Without a clone, use `go run github.com/rossedman/keyload/examples/<name>@latest` instead of `go run ./examples/<name>`.

In another terminal:

```sh
curl localhost:9090/metrics
echo oops > /tmp/keyload/tls.key && curl -s localhost:9090/metrics | grep reload_total
```

| Flag | Default | |
|---|---|---|
| `-dir` | `keyload-certs` | Directory with `tls.crt`, `tls.key` and `ca.crt`. |
| `-addr` | `:9090` | Address for `/metrics`. |

## What you'll see

```
# HELP keyload_generation Generation of the TLS snapshot in service.
# TYPE keyload_generation gauge
keyload_generation{reloader="api"} 1
# HELP keyload_reload_total Reload attempts by result. Reloads of unchanged material are not counted.
# TYPE keyload_reload_total counter
keyload_reload_total{reloader="api",result="success"} 1
keyload_reload_total{reloader="api",result="invalid"} 0
keyload_reload_total{reloader="api",result="read_error"} 0
# HELP keyload_cert_not_after_seconds Expiry of the leaf chain and of the earliest-expiring CA in each bundle, as a Unix timestamp.
# TYPE keyload_cert_not_after_seconds gauge
keyload_cert_not_after_seconds{reloader="api",role="leaf"} 1.792070543e+09
keyload_cert_not_after_seconds{reloader="api",role="roots"} 1.823520143e+09
# HELP keyload_last_success_timestamp_seconds Time of the last successful reload, as a Unix timestamp.
# TYPE keyload_last_success_timestamp_seconds gauge
keyload_last_success_timestamp_seconds{reloader="api"} 1.7919841432235692e+09
```

After the broken key, `keyload_reload_total{reloader="api",result="invalid"}` is `1` and `keyload_generation` stays at `1`.

The log has one JSON line per reload, naming the certificates that were added and removed. It never contains key material:

```json
{"level":"INFO","msg":"tls reload","generation":1,"trigger":"initial","result":"success","added":[{"not_after":"2026-10-15T13:23:16Z","role":"leaf","serial":"0b2c9ea53bbb602a","subject":"CN=localhost"},{"not_after":"2027-10-14T13:23:16Z","role":"roots","serial":"4489178c4bd6cacb","subject":"CN=keyload example CA"}]}
{"level":"INFO","msg":"tls reload","generation":2,"trigger":"watch","result":"success","added":[{"not_after":"2026-10-15T13:23:17Z","role":"leaf","serial":"1cd921fd97a42384","subject":"CN=localhost"}],"removed":[{"not_after":"2026-10-15T13:23:16Z","role":"leaf","serial":"0b2c9ea53bbb602a","subject":"CN=localhost"}]}
{"level":"ERROR","msg":"tls reload rejected","generation":2,"trigger":"watch","result":"invalid","err":"keyload: invalid material (key /tmp/keyload/tls.key): truncated or malformed PEM block"}
```

## Alerting rules

```yaml
groups:
  - name: keyload
    rules:
      - alert: CertificateExpiresSoon
        expr: keyload_cert_not_after_seconds - time() < 7 * 86400
      - alert: CertificateReloadFailing
        expr: increase(keyload_reload_total{result!="success"}[15m]) > 0
```

`CertificateExpiresSoon` catches a certificate that stopped renewing; `CertificateReloadFailing` catches bad files being pushed. `keyload_last_success_timestamp_seconds` shows when the material last changed.

## How it works

```go
r, err := keyload.New(files,
	keyload.Name("api"), // adds reloader="api" to every series
	keyload.OnReload(func(ev keyload.Event) { /* log ev */ }),
)
mux.Handle("/metrics", keyload.MetricsHandler(r))
```

`MetricsHandler` writes the Prometheus text format without a client library. Pass several reloaders, each with its own `Name`, to serve them from one endpoint. `r.Stats()` returns the same numbers for other metrics systems.

## Test

```sh
go test ./examples/metrics
```

Source: [`main.go`](main.go)
