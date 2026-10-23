package grpccreds_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/rossedman/keyload"
	"github.com/rossedman/keyload/grpccreds"
	"github.com/rossedman/keyload/internal/testpki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// setup writes tls.crt, tls.key and ca.crt for localhost to a temporary
// directory, the way cert-manager writes a Secret.
func setup() *testpki.Dir {
	dir, err := os.MkdirTemp("", "grpccreds-example")
	if err != nil {
		log.Fatal(err)
	}
	return testpki.NewDir(testpki.NoTest, dir)
}

func Example() {
	dir := setup()
	defer os.RemoveAll(dir.Path)

	r, err := keyload.New(keyload.Files{
		Cert:      dir.File("tls.crt"),
		Key:       dir.File("tls.key"),
		Roots:     dir.File("ca.crt"),
		ClientCAs: dir.File("ca.crt"),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	// Server: presents the current certificate and requires client
	// certificates from the current client CAs.
	srv := grpc.NewServer(grpc.Creds(grpccreds.New(r, grpccreds.WithTLSConfig(&tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
	}))))
	healthpb.RegisterHealthServer(srv, health.NewServer())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()

	// Client: presents its certificate and verifies the server with the
	// current roots.
	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(
		grpccreds.New(r, grpccreds.WithTLSConfig(&tls.Config{ServerName: "localhost"}))))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	resp, err := healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resp.Status)
	// Output:
	// SERVING
}
