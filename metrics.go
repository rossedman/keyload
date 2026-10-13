package keyload

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

type stats struct {
	success, invalid, readError atomic.Uint64
	lastSuccess                 atomic.Int64 // unix nanoseconds
}

func (s *stats) recordSuccess(snap *Snapshot) {
	s.success.Add(1)
	s.lastSuccess.Store(snap.LoadedAt.UnixNano())
}

func (s *stats) recordFailure(r Result) {
	if r == ResultInvalid {
		s.invalid.Add(1)
	} else {
		s.readError.Add(1)
	}
}

// Stats is a point-in-time view of a Reloader's counters.
type Stats struct {
	Generation  uint64
	Success     uint64 // reloads that swapped in a new snapshot, including the first load
	Invalid     uint64 // reloads rejected by validation
	ReadError   uint64 // reloads that could not read their source
	LastSuccess time.Time

	LeafNotAfter      time.Time // earliest expiry in the leaf chain; zero without a leaf
	RootsNotAfter     time.Time // earliest expiry among the roots; zero without roots
	ClientCAsNotAfter time.Time // earliest expiry among the client CAs; zero without client CAs
}

// Stats returns the Reloader's counters and the expiry times of the material
// in service.
func (r *Reloader) Stats() Stats {
	snap := r.Current()
	return Stats{
		Generation:        snap.Generation,
		Success:           r.stats.success.Load(),
		Invalid:           r.stats.invalid.Load(),
		ReadError:         r.stats.readError.Load(),
		LastSuccess:       time.Unix(0, r.stats.lastSuccess.Load()),
		LeafNotAfter:      snap.NotAfter,
		RootsNotAfter:     earliestExpiry(snap.RootCerts),
		ClientCAsNotAfter: earliestExpiry(snap.ClientCACerts),
	}
}

func earliestExpiry(certs []*x509.Certificate) time.Time {
	var t time.Time
	for _, c := range certs {
		if t.IsZero() || c.NotAfter.Before(t) {
			t = c.NotAfter
		}
	}
	return t
}

// WriteMetrics writes the Reloader's metrics to w in the Prometheus text
// exposition format:
//
//	keyload_generation                          current snapshot generation
//	keyload_reload_total{result}                success, invalid, read_error
//	keyload_cert_not_after_seconds{role}        expiry of the leaf and earliest CA per bundle
//	keyload_last_success_timestamp_seconds      time of the last successful reload
//
// With the [Name] option every series also carries reloader="name". To serve
// several Reloaders from one endpoint, use [MetricsHandler].
func (r *Reloader) WriteMetrics(w io.Writer) error {
	return writeMetrics(w, []*Reloader{r})
}

// MetricsHandler serves the metrics of the given Reloaders in the Prometheus
// text exposition format. Give each Reloader a distinct [Name] when passing
// more than one.
func MetricsHandler(rs ...*Reloader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = writeMetrics(w, rs)
	})
}

func writeMetrics(out io.Writer, rs []*Reloader) error {
	w := bufio.NewWriter(out)
	type sample struct {
		labels string
		value  float64
	}
	family := func(name, typ, help string, samples func(r *Reloader, base string) []sample) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		for _, r := range rs {
			base := ""
			if r.opts.name != "" {
				base = `reloader="` + escapeLabel(r.opts.name) + `"`
			}
			for _, s := range samples(r, base) {
				fmt.Fprintf(w, "%s%s %s\n", name, s.labels, strconv.FormatFloat(s.value, 'g', -1, 64))
			}
		}
	}
	labels := func(base string, kv ...string) string {
		l := base
		for i := 0; i < len(kv); i += 2 {
			if l != "" {
				l += ","
			}
			l += kv[i] + `="` + kv[i+1] + `"`
		}
		if l == "" {
			return ""
		}
		return "{" + l + "}"
	}

	family("keyload_generation", "gauge", "Generation of the TLS snapshot in service.", func(r *Reloader, base string) []sample {
		return []sample{{labels(base), float64(r.Current().Generation)}}
	})
	family("keyload_reload_total", "counter", "Reload attempts by result. Reloads of unchanged material are not counted.", func(r *Reloader, base string) []sample {
		return []sample{
			{labels(base, "result", string(ResultSuccess)), float64(r.stats.success.Load())},
			{labels(base, "result", string(ResultInvalid)), float64(r.stats.invalid.Load())},
			{labels(base, "result", string(ResultReadError)), float64(r.stats.readError.Load())},
		}
	})
	family("keyload_cert_not_after_seconds", "gauge", "Expiry of the leaf chain and of the earliest-expiring CA in each bundle, as a Unix timestamp.", func(r *Reloader, base string) []sample {
		st := r.Stats()
		var s []sample
		for _, e := range []struct {
			role Role
			t    time.Time
		}{{RoleLeaf, st.LeafNotAfter}, {RoleRoots, st.RootsNotAfter}, {RoleClientCAs, st.ClientCAsNotAfter}} {
			if !e.t.IsZero() {
				s = append(s, sample{labels(base, "role", string(e.role)), float64(e.t.Unix())})
			}
		}
		return s
	})
	family("keyload_last_success_timestamp_seconds", "gauge", "Time of the last successful reload, as a Unix timestamp.", func(r *Reloader, base string) []sample {
		return []sample{{labels(base), float64(r.stats.lastSuccess.Load()) / 1e9}}
	})
	return w.Flush()
}

func escapeLabel(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}
