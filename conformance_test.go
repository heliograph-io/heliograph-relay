package relay_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	relay "github.com/heliograph-io/heliograph-relay"
	"github.com/heliograph-io/heliograph-relay/conformance"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func estates() *relay.StaticAuth {
	auth := relay.NewStaticAuth()
	auth.SetControl("e1", "ctl")
	auth.SetStation("e1", "stn")
	auth.SetControl("e2", "other-ctl")
	auth.SetStation("e2", "other-stn")
	return auth
}

// The Go server must pass the contract. The Cloudflare Worker in edge/ runs the
// same suite against `wrangler dev` in CI, so the two implementations cannot
// drift without one of them going red.
func TestGoServerPassesTheContract(t *testing.T) {
	// Wrapped so leases are read and verified against the contract's published
	// key. The suite signs with the matching seed; this relay holds only the
	// public half and provably cannot produce a signature of its own.
	srv := httptest.NewServer(relay.NewAuthorisingServer(relay.NewStore(),
		&relay.AuthorityAuth{Inner: relay.FromAuth(estates()), Verify: contractVerifier(t)},
		quietLog()).Routes())
	t.Cleanup(srv.Close)

	rs := conformance.Run(conformance.Target{
		BaseURL: srv.URL, Estate: "e1", Station: "st1",
		Control: "ctl", StationTok: "stn",
		OtherEstate: "e2", OtherControl: "other-ctl",
		SignLease: contractSigner(t),
	})
	if !conformance.Report(os.Stdout, "go server", rs) {
		t.Fatal("the Go server does not satisfy the relay contract")
	}
}

// The same contract, with the decision fetched rather than held.
//
// RemoteAuth is the seam the hosted service lives behind, and a seam nobody has
// run the contract through is a seam that will drift from the one everybody
// runs. This pass also supplies the lever the outage section needs, so
// "a control-plane outage is not a bad credential" is asserted over HTTP rather
// than only in a unit test. heliograph-io/heliograph-cloud#7.
func TestTheGoServerPassesTheContractBehindARemoteAuthoriser(t *testing.T) {
	cp := newContractControlPlane(t)
	auth := relay.NewRemoteAuth(cp.url())
	// Long enough that a decision taken before the outage is still good during
	// it, which is the property the section is there to assert.
	auth.Positive = time.Minute

	// Hosted, because the per-station isolation section needs a relay that
	// refuses estate-wide credentials, and because that is the configuration
	// the hosted service actually runs. WithLeases is the composition main.go
	// serves with, so this pass runs the binary's order rather than one chosen
	// here.
	srv := httptest.NewServer(relay.NewAuthorisingServer(relay.NewStore(),
		relay.WithLeases(auth, contractVerifier(t), true),
		slog.New(slog.NewTextHandler(io.Discard, nil))).Routes())
	t.Cleanup(srv.Close)

	rs := conformance.Run(conformance.Target{
		BaseURL: srv.URL, Estate: "e1", Station: "st1",
		Control: "ctl", StationTok: "stn",
		OtherEstate: "e2", OtherControl: "other-ctl",
		ControlPlane:  cp.lever,
		AuthoriserSaw: cp.saw,
		Tenancy:       true,
		SignLease:     contractSigner(t),
	})
	if !conformance.Report(os.Stdout, "go server behind a remote authoriser", rs) {
		t.Fatal("the Go server behind RemoteAuth does not satisfy the relay contract")
	}
}

// swappable is one HTTP surface in front of a server that can be replaced
// underneath it, so a restart can be forced without the base URL changing.
type swappable struct {
	mu sync.RWMutex
	h  http.Handler
}

func (s *swappable) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	h := s.h
	s.mu.RUnlock()
	h.ServeHTTP(w, r)
}

func (s *swappable) swap(h http.Handler) {
	s.mu.Lock()
	s.h = h
	s.mu.Unlock()
}

// And the durability half of the contract, which needs a way to lose the
// server's memory without losing its address.
//
// The disruptor here throws the whole Store away and builds a new one over the
// same spool directory, which is what a new process does. It is not a process
// restart: CI runs the same suite against the real binary being killed and
// restarted (scripts/restart-go-relay.sh), and against `wrangler dev` likewise.
// This one runs in `go test`, on every commit, with no processes to manage.
func TestGoServerPassesTheContractWhenDurable(t *testing.T) {
	dir := t.TempDir()
	front := &swappable{}
	open := func() {
		store := relay.NewStore()
		if _, err := store.OpenSpool(dir); err != nil {
			t.Fatalf("OpenSpool(%q): %v", dir, err)
		}
		// The same wrapper the other passes use, verifier included. Durability
		// does not change how a lease is read and must not skip it.
		front.swap(relay.NewAuthorisingServer(store,
			&relay.AuthorityAuth{Inner: relay.FromAuth(estates()), Verify: contractVerifier(t)},
			quietLog()).Routes())
	}
	open()
	srv := httptest.NewServer(front)
	t.Cleanup(srv.Close)

	rs := conformance.Run(conformance.Target{
		BaseURL: srv.URL, Estate: "e1", Station: "st1",
		Control: "ctl", StationTok: "stn",
		OtherEstate: "e2", OtherControl: "other-ctl",
		SignLease: contractSigner(t),
		Disrupt: func() error {
			open()
			return nil
		},
	})
	if !conformance.Report(os.Stdout, "go server, durable", rs) {
		t.Fatal("the Go server does not satisfy the relay contract when given a spool")
	}
}

// contractControlPlane answers decisions for the contract's own estates, and
// can be taken away.
//
// It listens on a fixed-for-its-lifetime address rather than using httptest,
// because the outage has to be reversible: httptest.Server cannot be reopened
// once closed, and an outage nobody recovers from proves only half the point.
type contractControlPlane struct {
	ln  net.Listener
	srv *http.Server
	mu  sync.Mutex
	// seen is every byte this control plane has been sent, unmodified, so the
	// contract can assert that no message body was ever among them.
	seen []byte
}

func (c *contractControlPlane) saw() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.seen...)
}

func newContractControlPlane(t *testing.T) *contractControlPlane {
	t.Helper()
	cp := &contractControlPlane{}
	if err := cp.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cp.stop)
	return cp
}

func (c *contractControlPlane) url() string { return "http://" + c.ln.Addr().String() }

func (c *contractControlPlane) start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	addr := "127.0.0.1:0"
	if c.ln != nil {
		addr = c.ln.Addr().String()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	c.ln = ln
	c.srv = &http.Server{Handler: http.HandlerFunc(c.decide), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = c.srv.Serve(ln) }()
	return nil
}

func (c *contractControlPlane) stop() {
	c.mu.Lock()
	srv := c.srv
	c.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

func (c *contractControlPlane) lever() func() {
	c.stop()
	return func() { _ = c.start() }
}

var contractTokens = map[string][2]string{
	"e1": {"ctl", "stn"},
	"e2": {"other-ctl", "other-stn"},
}

func (c *contractControlPlane) decide(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.seen = append(c.seen, raw...)
	c.mu.Unlock()

	var in struct {
		Credential string `json:"credential"`
		Estate     string `json:"estate"`
		Station    string `json:"station"`
		Dir        string `json:"dir"`
		Op         string `json:"op"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	// The tenancy credentials are answered first, because each is bound to one
	// station and an ordinary estate lookup would not see that.
	if sc, ok := scopeFor(in.Credential, in.Estate, in.Station, in.Dir, in.Op); ok {
		reply(w, true, "", sc)
		return
	}
	if _, bound := tenancy[in.Credential]; bound {
		reply(w, false, "out-of-scope", nil)
		return
	}

	allow, reason := false, "bad-credential"
	pair, known := contractTokens[in.Estate]
	switch {
	case in.Credential == "":
		reason = "no-credential"
	case !known:
		// An estate nobody configured refuses. Treating an absent entry as a
		// match would authorise everybody.
	case in.Op == "read":
		allow = in.Credential == pair[0] || in.Credential == pair[1]
	case in.Op == "write" && in.Dir == "c2s":
		if in.Credential == pair[1] {
			reason = "wrong-direction"
		}
		allow = in.Credential == pair[0]
	case in.Op == "write" && in.Dir == "s2c":
		if in.Credential == pair[0] {
			reason = "wrong-direction"
		}
		allow = in.Credential == pair[1]
	}
	if !allow {
		reply(w, false, reason, nil)
		return
	}
	// Station-scoped, for the station being asked about. A per-request
	// authoriser grants exactly one station at a time, and saying so is what
	// lets a hosted relay tell a narrow grant from a wide one.
	read, write := []string{"s2c"}, []string{"c2s"}
	if in.Credential == pair[1] {
		read, write = []string{"c2s"}, []string{"s2c"}
	}
	reply(w, true, "", stationScope(in.Estate, in.Station, read, write))
}

// reply writes one decision.
func reply(w http.ResponseWriter, allow bool, reason string, scope map[string]any) {
	out := map[string]any{"allow": allow, "reason": reason}
	if scope != nil {
		out["scope"] = scope
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// tenancy is the two-customer policy the contract's per-station section needs.
//
// Two customers under ONE estate identifier, each credential bound to its own
// station. That binding is the whole point: a relay that granted whatever
// station was asked for would pass the isolation section without enforcing
// anything.
var tenancy = map[string]struct {
	station string
	read    []string
	write   []string
}{
	conformance.TenantAlphaStation: {conformance.TenantAlpha, []string{"c2s"}, []string{"s2c"}},
	conformance.TenantAlphaControl: {conformance.TenantAlpha, []string{"s2c"}, []string{"c2s"}},
	conformance.TenantBravoStation: {conformance.TenantBravo, []string{"c2s"}, []string{"s2c"}},
	conformance.TenantBravoControl: {conformance.TenantBravo, []string{"s2c"}, []string{"c2s"}},
}

// scopeFor answers the scope half of a decision.
//
// Ordinary estates are answered station-scoped for the station being asked
// about, which is what a per-request authoriser genuinely grants. The tenancy
// credentials are answered from their binding, and TenantWide is answered
// estate-wide on purpose so a hosted relay has something to refuse.
func scopeFor(credential, estate, station, dir, op string) (map[string]any, bool) {
	if credential == conformance.TenantWide {
		return map[string]any{
			"estate": estate, "stations": []string{}, "allStations": true,
			"read": []string{"c2s", "s2c"}, "write": []string{"c2s", "s2c"},
		}, true
	}
	if t, ok := tenancy[credential]; ok {
		if estate != conformance.TenantEstate || station != t.station {
			return nil, false
		}
		allowed := t.read
		if op == "write" {
			allowed = t.write
		}
		if !slices.Contains(allowed, dir) {
			return nil, false
		}
		return map[string]any{
			"estate": estate, "stations": []string{t.station}, "allStations": false,
			"read": t.read, "write": t.write,
		}, true
	}
	return nil, false
}

// stationScope narrows an ordinary estate decision to the station asked about.
func stationScope(estate, station string, read, write []string) map[string]any {
	return map[string]any{
		"estate": estate, "stations": []string{station}, "allStations": false,
		"read": read, "write": write,
	}
}

// The contract's keypair: the relay under test verifies with the public half,
// and the suite signs with the private one.
//
// The relay never holds the seed. TestTheRelayBinaryCannotSignALease reads the
// built binary's symbol table and fails if any route to an ed25519 private key
// is linked into it, so this split is enforced rather than described.
func contractVerifier(t *testing.T) relay.AuthorityVerifier {
	t.Helper()
	pub, err := relay.ParseEd25519PublicKey(conformance.LeaseKey)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Ed25519Verifier(pub)
}

func contractSigner(t *testing.T) func(payload string) []byte {
	t.Helper()
	seed, err := hex.DecodeString(conformance.LeaseSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("the contract seed is not a %d-byte hex seed: %v", ed25519.SeedSize, err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return func(payload string) []byte { return ed25519.Sign(priv, []byte(payload)) }
}
