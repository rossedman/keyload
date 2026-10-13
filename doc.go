// Package keyload hot-reloads TLS material in both directions: leaf
// certificates and keys, and the CA bundles used to verify peers.
//
// Every reload is validated before it is used. A reload that fails keeps the
// last good material in service and reports the failure, so a bad rotation
// never takes a service down and never needs a restart.
//
// All material lives in one immutable [Snapshot] that is swapped atomically.
// Handshakes read the current snapshot; reloads build a new one off to the
// side and swap it in only after it passes validation. Nothing is mutated in
// place, so there is no data race on [x509.CertPool].
//
// # Integration modes
//
// The guiding rule is to let crypto/tls verify certificates whenever
// possible:
//
//   - [Reloader.ServerConfig]: any crypto/tls server. Uses GetConfigForClient
//     to hand out a config built from the current snapshot. Stdlib
//     verification.
//   - [Reloader.DialTLSContext] and [Reloader.ConfigureTransport]: HTTP
//     clients and raw TLS dials. Builds a fresh tls.Config per connection
//     with the current roots. Stdlib verification.
//   - The grpccreds module: grpc-go clients and servers. Stdlib verification.
//   - [Reloader.ClientConfig]: for libraries that only accept a *tls.Config.
//     Sets InsecureSkipVerify and verifies in VerifyConnection against the
//     current roots, with the same options crypto/tls uses. This is the only
//     place keyload performs verification itself.
//
// # Sources and triggers
//
// Material comes from a [Source]. [FromFiles] reads PEM files and watches
// their directories, which handles the Kubernetes Secret volume ..data
// symlink swap. Reloads can also be triggered by a signal ([OnSignal]), a
// timer ([PollEvery]) or a direct call to [Reloader.Reload].
package keyload
