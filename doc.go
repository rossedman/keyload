// Package keyload reloads TLS certificates, keys and CA bundles while a
// server or client keeps running, so certificate rotation never needs a
// restart.
//
// A Reloader loads TLS material from a [Source] (usually [Files]), validates
// it and keeps it in an immutable [Snapshot]. When the files change, it
// validates the new material and swaps it in atomically. If the new material
// is bad (an expired certificate, a key that doesn't match, a half-written
// file), the last good snapshot stays in service and the failure is reported
// through [OnReload] and the metrics.
//
//	r, err := keyload.New(keyload.Files{
//		Cert: "/tls/tls.crt", Key: "/tls/tls.key",
//		Roots: "/tls/ca.crt", ClientCAs: "/tls/ca.crt",
//	})
//
//	// Servers: certificate and client CAs follow reloads.
//	srv := &http.Server{TLSConfig: r.ServerConfig(nil)}
//
//	// Clients: every connection uses the current roots and certificate.
//	tr := &http.Transport{}
//	err = r.ConfigureTransport(tr, nil)
//
// The grpccreds module does the same for grpc-go, and
// [Reloader.ClientConfig] covers libraries that only accept a *tls.Config.
// Every mode except ClientConfig leaves certificate verification to
// crypto/tls.
package keyload
