# Examples

Small programs that each show one way to use keyload. Every Go example has a README, commands to try it at the top of its `main.go`, and tests (`go test ./examples/...`).

Start with `gencerts` for certificates to try them with:

```sh
go run ./examples/gencerts -dir /tmp/keyload
```

Without a clone, use `go run github.com/rossedman/keyload/examples/<name>@latest` instead of `go run ./examples/<name>`.

| Example | Shows |
|---|---|
| [gencerts](gencerts) | A throwaway CA and certificate for `localhost`, and rotating it |
| [quickstart](quickstart) | The README quick start as a program, and how to test code that uses keyload |
| [server](server) | An HTTPS server with mutual TLS, reloading its certificate and client CAs, with `SIGHUP` for on-demand reloads |
| [client](client) | An HTTPS client with mutual TLS, reloading its certificate and trusted CAs |
| [proxy](proxy) | An HTTPS client behind an HTTP proxy, using Config mode |
| [metrics](metrics) | Prometheus metrics, structured reload logs and alerting rules |
| [kubernetes](kubernetes) | A cert-manager `Certificate` mounted into a Deployment |

The gRPC example is in the `grpccreds` module: [`grpccreds/example_test.go`](../grpccreds/example_test.go).
