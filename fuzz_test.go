package keyload

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rossedman/keyload/internal/testpki"
)

func FuzzParseMaterial(f *testing.F) {
	ca := testpki.NewCA(f, "ca")
	inter := ca.Intermediate(f, "inter")
	leaf := inter.Issue(f, testpki.LeafOptions{})
	f.Add(leaf.CertPEM, leaf.KeyPEM, ca.PEM())
	f.Add(leaf.CertPEM[:len(leaf.CertPEM)/2], leaf.KeyPEM, ca.PEM())
	f.Add(leaf.CertPEM, leaf.KeyPEM[:30], []byte{})
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n"), []byte("junk"), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))

	f.Fuzz(func(t *testing.T, cert, key, roots []byte) {
		m := &Material{Cert: cert, Key: key, Roots: roots}
		p, err := parseMaterial(m, buildOptions{now: time.Now()})
		if err != nil {
			if _, ok := err.(*ReloadError); !ok {
				t.Fatalf("error is %T, want *ReloadError", err)
			}
			return
		}
		// Anything accepted must be usable.
		if p.cert == nil || p.cert.Leaf == nil || len(p.chain) == 0 || len(p.roots) == 0 {
			t.Fatalf("accepted material is incomplete: %+v", p)
		}
		if !p.cert.Leaf.Equal(p.chain[0]) {
			t.Fatal("tls.Certificate leaf differs from parsed chain")
		}
		if _, err := x509.ParseCertificate(p.cert.Certificate[0]); err != nil {
			t.Fatal(err)
		}
	})
}

// labelSeeds are realistic certificate subjects and hostile label values.
var labelSeeds = []string{
	"",
	"api",
	"CN=api.example.com,O=Example Corp,C=US",
	`CN=evil",role="leaf"} 1` + "\nkeyload_generation 999\n#",
	`O=Back\\slash\`,
	`"quoted"`,
	"line1\nline2\r\n",
	"CN=münchen.example,O=Ünïcødé 証明書 🔐",
	"\\n literal backslash-n",
}

// unescapeLabel decodes a label value per the Prometheus text exposition
// format, which defines exactly three escapes: \\, \" and \n. It reports
// false for any other escape, a dangling backslash, a bare quote or a raw
// newline.
func unescapeLabel(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\n':
			return "", false
		case '\\':
			if i+1 == len(s) {
				return "", false
			}
			i++
			switch s[i] {
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			case 'n':
				b.WriteByte('\n')
			default:
				return "", false
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

func FuzzEscapeLabel(f *testing.F) {
	for _, s := range labelSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		out := escapeLabel(in)
		// A raw CR is legal in a quoted label value; only LF ends a line.
		if strings.Contains(out, "\n") {
			t.Fatalf("escapeLabel(%q) = %q contains a raw newline", in, out)
		}
		if !utf8.ValidString(out) {
			t.Fatalf("escapeLabel(%q) = %q is not valid UTF-8", in, out)
		}
		got, ok := unescapeLabel(out)
		if !ok {
			t.Fatalf("escapeLabel(%q) = %q is not a valid Prometheus label value (unescaped quote or backslash, or an escape other than \\\\, \\\" and \\n)", in, out)
		}
		if utf8.ValidString(in) && got != in {
			t.Fatalf("escapeLabel(%q) = %q unescapes to %q", in, out, got)
		}
	})
}

// parseSample parses a Prometheus text-format sample line,
// name{label="value",...} value, and returns its labels unescaped.
func parseSample(line string) (name string, labels map[string]string, err error) {
	isName := func(c byte, first, colon bool) bool {
		return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || colon && c == ':' || !first && c >= '0' && c <= '9'
	}
	i := 0
	for i < len(line) && isName(line[i], i == 0, true) {
		i++
	}
	if i == 0 {
		return "", nil, fmt.Errorf("no metric name")
	}
	name, labels = line[:i], map[string]string{}
	if i < len(line) && line[i] == '{' {
		i++
		for {
			j := i
			for j < len(line) && isName(line[j], j == i, false) {
				j++
			}
			if j == i || j+1 >= len(line) || line[j] != '=' || line[j+1] != '"' {
				return "", nil, fmt.Errorf("bad label name at %d", i)
			}
			key := line[i:j]
			i = j + 2
			j = i
			for j < len(line) && line[j] != '"' {
				if line[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(line) {
				return "", nil, fmt.Errorf("unterminated label value")
			}
			v, ok := unescapeLabel(line[i:j])
			if !ok {
				return "", nil, fmt.Errorf("bad label value %q", line[i:j])
			}
			if _, dup := labels[key]; dup {
				return "", nil, fmt.Errorf("duplicate label %q", key)
			}
			labels[key] = v
			i = j + 1
			if i < len(line) && line[i] == ',' {
				i++
				continue
			}
			if i < len(line) && line[i] == '}' {
				i++
				break
			}
			return "", nil, fmt.Errorf("expected , or } at %d", i)
		}
	}
	if i >= len(line) || line[i] != ' ' {
		return "", nil, fmt.Errorf("no space before value")
	}
	if _, err := strconv.ParseFloat(line[i+1:], 64); err != nil {
		return "", nil, fmt.Errorf("bad value: %w", err)
	}
	return name, labels, nil
}

// FuzzWriteMetrics drives writeMetrics with a fuzzed Reloader name — the only
// caller-controlled label value — and a fuzzed certificate subject, and
// checks the output is well-formed exposition text that neither can break.
func FuzzWriteMetrics(f *testing.F) {
	ca := testpki.NewCA(f, "ca")
	for _, s := range labelSeeds {
		f.Add(s, s)
	}

	f.Fuzz(func(t *testing.T, name, subject string) {
		// x509 cannot encode invalid UTF-8 in a subject.
		leaf := ca.Issue(t, testpki.LeafOptions{CommonName: strings.ToValidUTF8(subject, "?")})
		r, err := New(&memSource{m: leafMaterial(leaf, ca.PEM(), ca.PEM())}, DisableWatch(), Name(name))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		var buf bytes.Buffer
		if err := r.WriteMetrics(&buf); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if !utf8.ValidString(out) {
			t.Fatalf("output is not valid UTF-8:\n%s", out)
		}
		if !strings.HasSuffix(out, "\n") {
			t.Fatalf("output does not end in a newline:\n%s", out)
		}
		samples := 0
		for line := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n") {
			if strings.HasPrefix(line, "# HELP ") || strings.HasPrefix(line, "# TYPE ") {
				continue
			}
			metric, labels, err := parseSample(line)
			if err != nil {
				t.Fatalf("malformed sample line %q: %v\n%s", line, err, out)
			}
			if !strings.HasPrefix(metric, "keyload_") {
				t.Fatalf("unexpected metric %q in line %q", metric, line)
			}
			if got, ok := labels["reloader"]; ok != (name != "") || (utf8.ValidString(name) && got != name) {
				t.Fatalf("line %q: reloader label = %q (present %v), want %q", line, got, ok, name)
			}
			samples++
		}
		// generation, 3 reload results, leaf/roots/client CA expiry, last success.
		if samples != 8 {
			t.Fatalf("got %d samples, want 8 — a label value injected or removed lines:\n%s", samples, out)
		}
	})
}
