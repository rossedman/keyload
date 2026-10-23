package keyload_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/rossedman/keyload"
	"github.com/rossedman/keyload/internal/testpki"
)

// setup writes tls.crt, tls.key and ca.crt for localhost to a temporary
// directory, the way cert-manager writes a Secret.
func setup() *testpki.Dir {
	dir, err := os.MkdirTemp("", "keyload-example")
	if err != nil {
		log.Fatal(err)
	}
	return testpki.NewDir(testpki.NoTest, dir)
}

func files(dir *testpki.Dir) keyload.Files {
	return keyload.Files{
		Cert:      dir.File("tls.crt"),
		Key:       dir.File("tls.key"),
		Roots:     dir.File("ca.crt"),
		ClientCAs: dir.File("ca.crt"),
	}
}

func Example() {
	dir := setup()
	defer os.RemoveAll(dir.Path)

	r, err := keyload.New(keyload.Files{
		Cert:  dir.File("tls.crt"),
		Key:   dir.File("tls.key"),
		Roots: dir.File("ca.crt"),
	})
	if err != nil {
		log.Fatal(err) // the first load must be valid
	}
	defer r.Close()
	fmt.Println("serving generation", r.Current().Generation)

	// cert-manager writes a new certificate. The file watcher picks it up
	// within moments; Reload just makes it immediate.
	dir.Rotate(testpki.NoTest, testpki.LeafOptions{})
	_ = r.Reload(context.Background())
	fmt.Println("serving generation", r.Current().Generation)

	// Someone writes a broken key. It is rejected, and the last good
	// certificate keeps serving.
	testpki.WriteFile(testpki.NoTest, dir.File("tls.key"), []byte("oops"))
	err = r.Reload(context.Background())
	var re *keyload.ReloadError
	if errors.As(err, &re) {
		fmt.Println("rejected:", re.Result, re.Role)
	}
	fmt.Println("serving generation", r.Current().Generation)
	// Output:
	// serving generation 1
	// serving generation 2
	// rejected: invalid key
	// serving generation 2
}

func ExampleReloader_ServerConfig() {
	dir := setup()
	defer os.RemoveAll(dir.Path)
	r, err := keyload.New(files(dir))
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "hello over %s", req.Proto)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = r.ServerConfig(&tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"h2", "http/1.1"}, // for HTTP/2, set NextProtos here
	})
	srv.StartTLS()
	defer srv.Close()

	// A client using the same reloader for its own certificate and roots.
	tr := &http.Transport{ForceAttemptHTTP2: true}
	if err := r.ConfigureTransport(tr, nil); err != nil {
		log.Fatal(err)
	}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	// Output:
	// hello over HTTP/2.0
}

func ExampleReloader_ConfigureTransport() {
	dir := setup()
	defer os.RemoveAll(dir.Path)

	// A server whose certificate comes from dir's CA.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{dir.Leaf.TLS(testpki.NoTest)}}
	srv.StartTLS()
	defer srv.Close()

	// A client that only needs the CA bundle.
	r, err := keyload.New(keyload.Files{Roots: dir.File("ca.crt")})
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	tr := &http.Transport{}
	if err := r.ConfigureTransport(tr, nil); err != nil {
		log.Fatal(err) // keyload.ErrProxyConfigured if tr would use an HTTPS proxy
	}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()
	fmt.Println(resp.Status)
	// Output:
	// 200 OK
}

func ExampleReloader_ClientConfig() {
	dir := setup()
	defer os.RemoveAll(dir.Path)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{dir.Leaf.TLS(testpki.NoTest)}}
	srv.StartTLS()
	defer srv.Close()

	r, err := keyload.New(keyload.Files{Roots: dir.File("ca.crt")})
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	// For libraries that take a *tls.Config and nothing else. ServerName is
	// required: it is the hostname the server's certificate is checked for.
	cfg, err := r.ClientConfig(&tls.Config{ServerName: "localhost"})
	if err != nil {
		log.Fatal(err)
	}
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Println("verified", conn.ConnectionState().PeerCertificates[0].DNSNames[0])
	// Output:
	// verified localhost
}

func ExampleOnReload() {
	dir := setup()
	defer os.RemoveAll(dir.Path)

	r, err := keyload.New(files(dir), keyload.DisableWatch(), keyload.OnReload(func(ev keyload.Event) {
		if ev.Err != nil {
			fmt.Printf("%s reload rejected (%s), still serving generation %d\n", ev.Trigger, ev.Result, ev.Generation)
			return
		}
		fmt.Printf("%s reload: generation %d, %d certificates added\n", ev.Trigger, ev.Generation, len(ev.Added))
	}))
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	testpki.WriteFile(testpki.NoTest, dir.File("ca.crt"), nil) // an empty CA bundle
	_ = r.Reload(context.Background())
	// Output:
	// initial reload: generation 1, 3 certificates added
	// manual reload rejected (invalid), still serving generation 1
}
