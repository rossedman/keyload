package keyload

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/rossedman/keyload/internal/testpki"
)

// TestConfigModeMatchesStdlib generates certificate chains and checks that
// Config mode ([Reloader.ClientConfig]) accepts exactly the servers that
// crypto/tls's own verification accepts. Any disagreement fails the build.
func TestConfigModeMatchesStdlib(t *testing.T) {
	n := 2000
	if testing.Short() {
		n = 150
	}
	g := newChainGen(t, 1)
	var accepted, rejected int
	for i := 0; i < n; i++ {
		c := g.next(t)
		stdCfg := &tls.Config{RootCAs: pool(c.roots...), ServerName: c.serverName, Time: c.now}
		_, stdErr := handshake(t, stdCfg, c.server)

		r := newReloader(t, &memSource{m: Material{Roots: testpki.CertPEM(c.roots...)}}, DisableWatch())
		ourCfg, err := r.ClientConfig(&tls.Config{ServerName: c.serverName, Time: c.now})
		if err != nil {
			t.Fatal(err)
		}
		_, ourErr := handshake(t, ourCfg, c.server)
		r.Close()

		if (stdErr == nil) != (ourErr == nil) {
			t.Fatalf("case %d (%s): stdlib err = %v, Config mode err = %v", i, c.desc, stdErr, ourErr)
		}
		if stdErr == nil {
			accepted++
		} else {
			rejected++
		}
	}
	// Guard against a generator that only produces one kind of case.
	if accepted < n/20 || rejected < n/20 {
		t.Fatalf("unbalanced cases: %d accepted, %d rejected", accepted, rejected)
	}
	t.Logf("%d cases: %d accepted, %d rejected, no disagreements", n, accepted, rejected)
}

type chainCase struct {
	desc       string
	roots      []*x509.Certificate
	server     *tls.Config
	serverName string
	now        func() time.Time
}

type chainGen struct {
	rng    *rand.Rand
	keys   []*ecdsa.PrivateKey
	serial int64
	base   time.Time
}

func newChainGen(t testing.TB, seed int64) *chainGen {
	g := &chainGen{rng: rand.New(rand.NewSource(seed)), base: time.Now().Truncate(time.Hour)}
	for i := 0; i < 6; i++ {
		g.keys = append(g.keys, testpki.NewKey(t))
	}
	return g
}

func (g *chainGen) pick(s ...string) string { return s[g.rng.Intn(len(s))] }

func (g *chainGen) key() *ecdsa.PrivateKey { return g.keys[g.rng.Intn(len(g.keys))] }

func (g *chainGen) validity() (time.Time, time.Time, string) {
	switch g.rng.Intn(12) {
	case 0:
		return g.base.Add(-48 * time.Hour), g.base.Add(-time.Hour), "expired"
	case 1:
		return g.base.Add(time.Hour), g.base.Add(48 * time.Hour), "not-yet-valid"
	default:
		return g.base.Add(-time.Hour), g.base.Add(48 * time.Hour), "valid"
	}
}

func (g *chainGen) cert(t testing.TB, tmpl, parent *x509.Certificate, key, signer *ecdsa.PrivateKey) *x509.Certificate {
	g.serial++
	tmpl.SerialNumber = big.NewInt(g.serial)
	if parent == nil {
		parent = tmpl
	}
	return testpki.Sign(t, tmpl, parent, key.Public(), signer)
}

func (g *chainGen) next(t testing.TB) chainCase {
	desc := ""
	add := func(s string) { desc += s + " " }

	// Root, optionally name-constrained.
	rootKey := g.key()
	rootTmpl := &x509.Certificate{
		Subject: pkix.Name{CommonName: "root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:  x509.KeyUsageCertSign,
		NotBefore: g.base.Add(-72 * time.Hour), NotAfter: g.base.Add(72 * time.Hour),
	}
	switch g.rng.Intn(5) {
	case 0:
		rootTmpl.PermittedDNSDomains = []string{"example.com"}
		add("root:permit=example.com")
	case 1:
		rootTmpl.ExcludedDNSDomains = []string{"bad.example.com"}
		add("root:exclude=bad.example.com")
	case 2:
		_, ipnet, _ := net.ParseCIDR("10.0.0.0/8")
		rootTmpl.PermittedIPRanges = []*net.IPNet{ipnet}
		add("root:permit-ip=10/8")
	}
	root := g.cert(t, rootTmpl, nil, rootKey, rootKey)

	roots := []*x509.Certificate{root}
	if g.rng.Intn(6) == 0 {
		other := g.key()
		roots = []*x509.Certificate{g.cert(t, &x509.Certificate{
			Subject: pkix.Name{CommonName: "untrusted"}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign, NotBefore: rootTmpl.NotBefore, NotAfter: rootTmpl.NotAfter,
		}, nil, other, other)}
		add("roots:untrusted")
	}

	// Optional intermediate.
	issuer, issuerKey := root, rootKey
	var chain []*x509.Certificate
	if g.rng.Intn(3) > 0 {
		ik := g.key()
		nb, na, v := g.validity()
		it := &x509.Certificate{
			Subject: pkix.Name{CommonName: "intermediate"}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign, NotBefore: nb, NotAfter: na,
		}
		add("int:" + v)
		switch g.rng.Intn(6) {
		case 0:
			it.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			add("int:eku=client")
		case 1:
			it.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			add("int:eku=server")
		case 2:
			it.IsCA = false
			add("int:not-ca")
		case 3:
			it.MaxPathLenZero = true
			add("int:pathlen=0")
		}
		issuer = g.cert(t, it, root, ik, rootKey)
		issuerKey = ik
		if g.rng.Intn(8) > 0 {
			chain = append(chain, issuer)
		} else {
			add("int:omitted")
		}
	}

	// Leaf.
	lk := g.key()
	nb, na, v := g.validity()
	add("leaf:" + v)
	lt := &x509.Certificate{
		Subject: pkix.Name{CommonName: g.pick("example.com", "leaf")}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	for _, name := range []string{"example.com", "api.example.com", "*.example.com", "bad.example.com", "other.org"} {
		if g.rng.Intn(3) == 0 {
			lt.DNSNames = append(lt.DNSNames, name)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1"} {
		if g.rng.Intn(4) == 0 {
			lt.IPAddresses = append(lt.IPAddresses, net.ParseIP(ip))
		}
	}
	switch g.rng.Intn(6) {
	case 0:
		lt.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		add("leaf:eku=client")
	case 1:
		// no EKU: any usage
		add("leaf:eku=none")
	case 2:
		lt.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		add("leaf:eku=any")
	default:
		lt.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	add("leaf:dns=" + join(lt.DNSNames))
	leaf := g.cert(t, lt, issuer, lk, issuerKey)

	tc := tls.Certificate{PrivateKey: lk, Leaf: leaf, Certificate: [][]byte{leaf.Raw}}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Raw)
	}
	serverName := g.pick("example.com", "api.example.com", "foo.example.com", "a.b.example.com",
		"bad.example.com", "other.org", "EXAMPLE.COM", "example.com.", "127.0.0.1", "10.0.0.1", "::1", "10.0.0.2")
	// Half the time, ask for a name the leaf has, so accepting paths get
	// as much coverage as rejecting ones.
	var names []string
	names = append(names, lt.DNSNames...)
	for _, ip := range lt.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) > 0 && g.rng.Intn(2) == 0 {
		serverName = g.pick(names...)
		if serverName == "*.example.com" {
			serverName = "www.example.com"
		}
	}
	add("sni=" + serverName)

	now := g.base
	return chainCase{
		desc:       desc,
		roots:      roots,
		server:     &tls.Config{Certificates: []tls.Certificate{tc}},
		serverName: serverName,
		now:        func() time.Time { return now },
	}
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
