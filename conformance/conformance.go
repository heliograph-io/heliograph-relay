// Package conformance is the executable form of the relay contract.
//
// There are two implementations of this server: the Go one in this repository,
// and the Cloudflare Worker in edge/. That is a deliberate second
// implementation, taken on because the shapes genuinely differ - a Durable
// Object is how you hold state at the edge, and a Go binary is how you run this
// anywhere else - and the cost of it is drift.
//
// Drift is only dangerous when it is untested. So the contract lives here,
// asserted over HTTP against a base URL, and both implementations run it. The
// same reasoning, and the same shape, as the capture conformance suite in
// heliograph-skill: one specification, several implementations, and an
// unproven implementation is not permitted.
//
// Nothing in this package may import the Go server. The moment it does it
// stops being a specification and becomes a second copy of one implementation.
//
// # What this suite cannot assert, and it is not a gap that can be closed here
//
// Every assertion is made over HTTP, so it can only reach what a client can
// reach. A STORAGE MODEL is not one of those things. A relay that holds a
// message in memory and a relay that writes it to disk answer every request
// below identically, so nothing here can tell them apart.
//
// That is not hypothetical. The two implementations diverged on exactly this -
// the Worker persisted every message to Durable Object storage while the README
// said neither did - and both passed this suite the whole time
// (heliograph-io/heliograph-cloud#47).
//
// So storage claims are NOT conformance-enforced and must not be assumed
// covered because this suite is green. Each implementation asserts its own, in
// its own tests, with access this suite does not have:
//
//	storage_test.go                    the Go server
//	edge/test/storage-model.test.ts    the Worker, reading Durable Object storage
//
// Report says so on every run, so a green result does not read as broader than
// it is.
//
// # Durability is a different thing, and this suite does assert it
//
// Whether a message is written to disk is invisible here. Whether an accepted
// message SURVIVES is not: it is exactly what a sender cares about, and it is
// observable as soon as somebody can restart the relay between the put and the
// take. The suite cannot do that itself - a suite able to restart its target
// could be pointed at somebody's production relay - so Target.Disrupt is
// supplied by the harness and the assertions live here.
//
// With no disruptor those assertions are reported as SKIPPED rather than quietly
// omitted, because "this relay is durable" and "nobody asked" must not look the
// same in the output.
package conformance

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Target is a running relay and the credentials to talk to it.
type Target struct {
	BaseURL    string
	Estate     string
	Station    string
	Control    string // the control token
	StationTok string // the station token
	// OtherEstate and its control token, for the isolation checks. A relay
	// with one estate configured cannot prove it keeps two apart.
	OtherEstate  string
	OtherControl string
	Client       *http.Client

	// ControlPlane, when set, takes the relay's authoriser away and returns a
	// function that puts it back.
	//
	// A relay under test cannot be asked to break its own authoriser over HTTP,
	// and the distinction between "your credential is wrong" and "I could not
	// ask" is only assertable if the suite can cause the outage. So the harness
	// supplies the lever and this package says what must be true while it is
	// pulled. Leaving it nil skips the section and says so, rather than
	// reporting a pass nobody earned.
	ControlPlane func() (restore func())

	// Tenancy says the relay under test is a hosted tenant whose authoriser
	// knows the credentials named by the Tenant constants below.
	//
	// Setting it turns on the per-station isolation section. Leaving it unset
	// skips that section and says so, rather than reporting a pass nobody
	// earned.
	Tenancy bool

	// SignLease, when set, signs a lease payload with the key the relay under
	// test was configured to verify against.
	//
	// The harness supplies it rather than this package doing it, for the same
	// reason the outage lever is supplied: signing needs a private key, and a
	// specification that held one would be a specification that could mint.
	// Leaving it nil skips the signed-lease section and says so.
	SignLease func(payload string) []byte

	// AuthoriserSaw returns everything the harness's control plane has been
	// sent since the run began, concatenated and unmodified.
	//
	// The strongest sentence this product has is that the thing which is not
	// readable never touches your ciphertext. This is how that is checked
	// against a running relay rather than against its source: put a
	// recognisable pattern of bytes through, then look at every byte the
	// authoriser was given and fail if the pattern is in there.
	AuthoriserSaw func() []byte

	// Disrupt loses whatever the relay was holding in memory and returns when it
	// is answering again. Nil means the durability assertions are skipped and
	// reported as skipped.
	//
	// The same reasoning as ControlPlane, for a different lever: no client can
	// restart the relay it is talking to, and a suite that could would be a suite
	// somebody eventually points at a production relay. So the caller supplies
	// the mechanism and this package supplies the assertions - see
	// cmd/conformance's -restart, and the scripts/ directory.
	Disrupt Disrupt
}

// The tenancy this contract uses when a harness supplies one.
//
// Two customers under ONE estate identifier, which is the case that breaks an
// estate-wide credential: an account can hold more than one customer, and a
// station identifier is a name in a URL rather than a secret. Named here rather
// than in each harness so the two implementations are configured from one
// source and cannot quietly disagree about what is being tested.
//
// heliograph-io/heliograph-cloud#71.
const (
	TenantEstate       = "e-tenancy"
	TenantAlpha        = "alpha-01"
	TenantBravo        = "bravo-07"
	TenantAlphaControl = "alpha-control-credential"
	TenantAlphaStation = "alpha-station-credential"
	TenantBravoControl = "bravo-control-credential"
	TenantBravoStation = "bravo-station-credential"
	// TenantWide is a credential the authoriser answers estate-wide for. A
	// hosted tenant must refuse it, and must say that is why.
	TenantWide = "estate-wide-credential"
)

// The keypair this contract signs authorisation leases with.
//
// PUBLISHED ON PURPOSE, AND NOT A SECRET. It exists so that a relay under test
// can be started with LeaseKey and the suite can then mint leases it will
// accept. A relay configured with this key trusts anybody holding this file,
// which is every reader: it is a test fixture and must never be deployed.
//
// Derived from a fixed seed so both implementations are configured from one
// number and cannot quietly disagree about which key they trust.
//
// heliograph-io/heliograph-cloud#75.
const (
	// LeaseSeed is the 32-byte Ed25519 seed, hex. The harness signs with it.
	LeaseSeed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	// LeaseKey is the public half, hex. The relay under test verifies with it.
	LeaseKey = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
)

// Lease builds a lease in the wire format, signed by sign.
//
// The format is written out here rather than imported from the Go server,
// because this package is the specification and importing one implementation
// would make it a second copy of that implementation instead. A second encoder
// is the point: if the two disagree about a byte, one of them is wrong and this
// is where it shows.
//
//	hl1.<base64url(payload)>.<base64url(signature)>
func Lease(sign func(payload string) []byte, estate string, stations, read, write []string, notBefore, expires time.Time, epoch int64) string {
	return lease(sign, estate, stations, false, read, write, notBefore, expires, epoch)
}

// estateWideLease is a lease that says it covers every station in an estate,
// which is what a hosted tenant must refuse.
func estateWideLease(sign func(payload string) []byte, estate string, read, write []string, notBefore, expires time.Time) string {
	return lease(sign, estate, nil, true, read, write, notBefore, expires, 0)
}

func lease(sign func(payload string) []byte, estate string, stations []string, all bool, read, write []string, notBefore, expires time.Time, epoch int64) string {
	payload := map[string]any{
		"e": estate, "nbf": notBefore.Unix(), "exp": expires.Unix(),
	}
	if all {
		payload["a"] = true
	}
	if len(stations) > 0 {
		payload["s"] = stations
	}
	if len(read) > 0 {
		payload["r"] = read
	}
	if len(write) > 0 {
		payload["w"] = write
	}
	if epoch != 0 {
		payload["ep"] = epoch
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	return "hl1." + body + "." + base64.RawURLEncoding.EncodeToString(sign(body))
}

// refusal is what a relay says when it says no.
//
// Two fields, on purpose: the sentence is for a person and the reason is for a
// program. A client that has to match on English prose breaks when the prose
// improves.
type refusal struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

// Disrupt makes the relay lose its in-memory state without touching whatever it
// holds durably, and returns once it is serving again.
type Disrupt func() error

// Result is one assertion.
type Result struct {
	Name string
	OK   bool
	Why  string
	// Skipped means it was not attempted, which is neither a pass nor a failure.
	// It is a separate field rather than OK=true with a note, because a check
	// that prints as a pass while asserting nothing is how a claim ends up with
	// no test at all. Two of those have been found in heliograph already.
	Skipped bool
}

func (t Target) client() *http.Client {
	if t.Client != nil {
		return t.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (t Target) url(estate, station, dir, q string) string {
	u := fmt.Sprintf("%s/v1/%s/%s/%s", strings.TrimRight(t.BaseURL, "/"), estate, station, dir)
	if q != "" {
		u += "?" + q
	}
	return u
}

func (t Target) do(method, url, tok string, body []byte) (*http.Response, []byte, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return nil, nil, err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b, nil
}

func (t Target) put(estate, station, dir, tok string, seq uint64, body []byte) (int, error) {
	code, _, err := t.putR(estate, station, dir, tok, seq, body)
	return code, err
}

// putR is put, and also the refusal, for the assertions about WHY.
func (t Target) putR(estate, station, dir, tok string, seq uint64, body []byte) (int, refusal, error) {
	payload, _ := json.Marshal(map[string]any{"seq": seq, "body": body})
	resp, b, err := t.do("POST", t.url(estate, station, dir, ""), tok, payload)
	if err != nil {
		return 0, refusal{}, err
	}
	var why refusal
	_ = json.Unmarshal(b, &why)
	return resp.StatusCode, why, nil
}

type msg struct {
	// ID is stable for the life of the message, including across a redelivery,
	// which is what a collector deduplicates on.
	ID   string `json:"id"`
	Seq  uint64 `json:"seq"`
	Body []byte `json:"body"`
}

func (t Target) take(estate, station, dir, tok string) (int, []msg, error) {
	resp, b, err := t.do("GET", t.url(estate, station, dir, "wait=0"), tok, nil)
	if err != nil {
		return 0, nil, err
	}
	var out []msg
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out, nil
}

// Run executes every assertion and returns them in order.
//
// It uses a fresh station name per run, so a suite run twice against the same
// relay does not read its own leftovers and report a pass it did not earn.
func Run(t Target) []Result {
	var out []Result
	ok := func(name string, cond bool, why string) {
		out = append(out, Result{Name: name, OK: cond, Why: why})
	}
	uniq := fmt.Sprintf("%s-%d", t.Station, time.Now().UnixNano())

	base := strings.TrimRight(t.BaseURL, "/")

	// --- health ---------------------------------------------------------
	//
	// /health answers the three questions a monitoring check actually has, and
	// they are different questions. The VERSION is the commit a deployment
	// believes it is, which is a claim it makes about itself. The HASH is of
	// the artefact that is serving - the Worker bundle, or the binary on
	// disk - and that is a number anybody can arrive at independently by
	// building the same tag, which is the only form of "the relay in the path
	// is the relay you read" that does not end in trusting whoever deployed
	// it. See https://heliograph.dbhq.uk/provenance.
	//
	// DURABLE is the third, and it is the same kind of answer as the hash: it
	// turns a documented promise into a value somebody can read. A published
	// claim about storage was once false for the implementation actually
	// deployed and nobody could tell by asking
	// (heliograph-io/heliograph-cloud#47).
	resp, hbody, err := t.do("GET", base+"/health", "", nil)
	ok("health answers without a token", err == nil && resp != nil && resp.StatusCode == 200,
		fmt.Sprintf("err=%v", err))
	health := struct {
		OK      bool   `json:"ok"`
		Version string `json:"version"`
		Hash    string `json:"hash"`
		// A pointer, because the assertion is that the field is PRESENT. Its
		// value is a fact about the deployment rather than about the
		// implementation, and either value is correct: a self-hoster with no
		// spool configured is honestly not durable.
		Durable *bool `json:"durable"`
	}{}
	healthParsed := err == nil && json.Unmarshal(hbody, &health) == nil
	ok("health still says ok", healthParsed && health.OK,
		fmt.Sprintf("body=%s", string(hbody)))
	// Never blank, for the same reason /version is never blank: a deployment
	// nobody stamped must SAY it does not know, because an empty field reads
	// as a bug in whatever asked.
	ok("health names the version that is serving", healthParsed && health.Version != "",
		fmt.Sprintf("version=%q", health.Version))
	ok("health names the hash of what is serving", healthParsed && health.Hash != "",
		fmt.Sprintf("hash=%q", health.Hash))
	ok("health says whether this deployment is durable",
		healthParsed && health.Durable != nil,
		fmt.Sprintf("body=%s", string(hbody)))

	// --- identity, and the two endpoints a human reaches for -------------
	// Both are unauthenticated on purpose. "The relay you are talking to is
	// the relay you read" is not checkable if you need a credential to ask
	// which relay it is, and the answer reveals nothing a reader of the
	// public source does not already have.
	for _, path := range []string{"/", "/version"} {
		resp, body, err := t.do("GET", base+path, "", nil)
		got := struct {
			Service        string `json:"service"`
			Implementation string `json:"implementation"`
			Version        string `json:"version"`
			Source         string `json:"source"`
		}{}
		parsed := err == nil && json.Unmarshal(body, &got) == nil
		ok(path+" answers without a token", err == nil && resp != nil && resp.StatusCode == 200,
			fmt.Sprintf("err=%v", err))
		ok(path+" names the service and the implementation",
			parsed && got.Service == "heliograph-relay" && got.Implementation != "",
			fmt.Sprintf("service=%q implementation=%q", got.Service, got.Implementation))
		// Never blank. A build nobody stamped must say "unknown" rather than
		// return an empty string, because a blank field reads as a broken
		// client where "unknown" is a true answer somebody can act on.
		ok(path+" reports a version that is never blank", parsed && got.Version != "",
			fmt.Sprintf("version=%q", got.Version))
		ok(path+" points at the source", parsed && got.Source != "",
			fmt.Sprintf("source=%q", got.Source))
	}

	// A browser must get a page, not a download. / used to answer
	// {"error":"no such route"} with a JSON content type, and mobile Safari
	// offered that as a 25-byte file rather than showing it - which is what
	// somebody who pasted the hostname into a phone actually got.
	{
		req, _ := http.NewRequest("GET", base+"/", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
		resp, err := t.client().Do(req)
		ct := ""
		if resp != nil {
			ct = resp.Header.Get("Content-Type")
			_ = resp.Body.Close()
		}
		ok("/ gives a browser HTML rather than a file to download",
			err == nil && strings.HasPrefix(ct, "text/html"),
			fmt.Sprintf("content-type=%q err=%v", ct, err))
	}

	// --- a message goes in and comes back unchanged ----------------------
	// Bytes that are not valid UTF-8 and not valid JSON, because the body is
	// ciphertext and the relay must never interpret it.
	want := []byte{0x00, 0xff, 0x7b, 0x22, 0x10, 'c', 'i', 'p', 'h', 'e', 'r', 0xfe}
	code, err := t.put(t.Estate, uniq, "c2s", t.Control, 1, want)
	ok("a control token may queue a request", code == 202, fmt.Sprintf("got %d %v", code, err))

	code, got, err := t.take(t.Estate, uniq, "c2s", t.StationTok)
	ok("a station token may collect it", code == 200, fmt.Sprintf("got %d %v", code, err))
	ok("exactly one message came back", len(got) == 1, fmt.Sprintf("got %d", len(got)))
	if len(got) == 1 {
		ok("the body is byte-for-byte what was sent", bytes.Equal(got[0].Body, want),
			fmt.Sprintf("got %v", got[0].Body))
		ok("the sequence number is unchanged", got[0].Seq == 1,
			fmt.Sprintf("got %d", got[0].Seq))
	}

	// --- collecting removes it ------------------------------------------
	_, got, _ = t.take(t.Estate, uniq, "c2s", t.StationTok)
	ok("a collected message is not delivered twice", len(got) == 0, fmt.Sprintf("got %d", len(got)))

	// --- the scope split, which is the one that matters ------------------
	// A station credential sits on a machine nobody can reach and cannot be
	// rotated quickly. It must not be able to queue a request.
	code, _ = t.put(t.Estate, uniq, "c2s", t.StationTok, 2, []byte("evil"))
	ok("a station token may NOT queue a request", code != 202, fmt.Sprintf("got %d", code))

	code, _ = t.put(t.Estate, uniq, "s2c", t.Control, 2, []byte("fake status"))
	ok("a control token may NOT publish a status", code != 202, fmt.Sprintf("got %d", code))

	code, _ = t.put(t.Estate, uniq, "s2c", t.StationTok, 1, []byte("real status"))
	ok("a station token may publish a status", code == 202, fmt.Sprintf("got %d", code))

	code, got, _ = t.take(t.Estate, uniq, "s2c", t.Control)
	ok("a control token may read a status", code == 200 && len(got) == 1,
		fmt.Sprintf("got %d, %d messages", code, len(got)))

	// --- no credential ---------------------------------------------------
	code, _ = t.put(t.Estate, uniq, "c2s", "", 3, []byte("x"))
	ok("a put with no token is refused", code == 401, fmt.Sprintf("got %d", code))
	code, _, _ = t.take(t.Estate, uniq, "c2s", "")
	ok("a get with no token is refused", code == 401, fmt.Sprintf("got %d", code))

	code, _ = t.put(t.Estate, uniq, "c2s", "definitely-not-the-token", 3, []byte("x"))
	ok("a put with a wrong token is refused", code == 401, fmt.Sprintf("got %d", code))

	// --- every refusal says why, in a field a program can read -------------
	// A relay that answers only a status code makes the caller guess, and the
	// guess an operator makes about a 401 is "the token is wrong" - which sends
	// them to a machine they cannot reach even when the fault is ours.
	{
		_, none, _ := t.putR(t.Estate, uniq, "c2s", "", 3, []byte("x"))
		_, wrong, _ := t.putR(t.Estate, uniq, "c2s", "definitely-not-the-token", 3, []byte("x"))
		_, dirn, _ := t.putR(t.Estate, uniq, "c2s", t.StationTok, 3, []byte("x"))

		ok("a refusal names a machine-readable reason",
			none.Reason != "" && wrong.Reason != "" && dirn.Reason != "",
			fmt.Sprintf("none=%q wrong=%q direction=%q", none.Reason, wrong.Reason, dirn.Reason))
		ok("a missing credential and a wrong one are told apart",
			none.Reason != wrong.Reason,
			fmt.Sprintf("both said %q", none.Reason))
		// A station credential writing c2s is a good credential used wrongly.
		// Reporting it as a bad credential is what gets a station rotated on a
		// machine nobody can reach, for nothing.
		ok("a good credential in the wrong direction is not reported as a bad one",
			dirn.Reason != wrong.Reason,
			fmt.Sprintf("both said %q", dirn.Reason))
		ok("a refusal still carries a sentence for a person",
			none.Error != "" && wrong.Error != "" && dirn.Error != "",
			fmt.Sprintf("none=%q wrong=%q direction=%q", none.Error, wrong.Error, dirn.Error))
	}

	// --- the authoriser is down, which is not the same as a bad credential --
	// heliograph-io/heliograph-cloud#7. The worst failure this product has is a
	// management-plane outage reported as a credential problem, because the
	// person who reads a 401 goes to the far side of the gap and the fault is
	// on this side.
	if t.ControlPlane != nil {
		// A route decided while the authoriser was up.
		warm := uniq + "-warm"
		code, _ = t.put(t.Estate, warm, "c2s", t.Control, 1, []byte("before"))
		ok("the authoriser answers before the outage", code == 202, fmt.Sprintf("got %d", code))

		restore := t.ControlPlane()

		code, why, _ := t.putR(t.Estate, warm, "c2s", t.Control, 2, []byte("during"))
		ok("a decision made before the outage still works during it", code == 202,
			fmt.Sprintf("got %d %q", code, why.Reason))

		// A route that was never decided cannot be answered from anything held
		// locally, so this is the outage path itself.
		cold := uniq + "-cold"
		code, why, _ = t.putR(t.Estate, cold, "c2s", t.Control, 1, []byte("x"))
		ok("an outage does NOT answer 401", code != 401, fmt.Sprintf("got %d %q", code, why.Reason))
		ok("an outage answers 503", code == 503, fmt.Sprintf("got %d %q", code, why.Reason))
		ok("an outage names itself as the authoriser being unreachable",
			why.Reason == "authoriser-unavailable", fmt.Sprintf("reason=%q", why.Reason))

		restore()

		// And it recovers. An outage cached is an outage extended past its own
		// end, which is the opposite of what a cache is for.
		code, why, _ = t.putR(t.Estate, cold, "c2s", t.Control, 1, []byte("after"))
		ok("the relay works again as soon as the authoriser does", code == 202,
			fmt.Sprintf("got %d %q", code, why.Reason))
	} else {
		ok("SKIPPED: the authoriser outage section needs a lever this harness did not supply",
			true, "")
	}

	// --- the authoriser never sees a message body -------------------------
	// heliograph-io/heliograph-cloud#68. The claim is that the thing which is
	// not readable never touches ciphertext, and a rule saying an authoriser
	// must not look is worth nothing. Put a recognisable pattern through and
	// read back every byte the authoriser was handed.
	if t.AuthoriserSaw != nil {
		sentinel := []byte("SENTINEL-0xFEEDFACE-no-authoriser-may-see-this")
		body := uniq + "-sentinel"
		code, _ = t.put(t.Estate, body, "c2s", t.Control, 1, sentinel)
		ok("the sentinel message was accepted", code == 202, fmt.Sprintf("got %d", code))
		_, _, _ = t.take(t.Estate, body, "c2s", t.StationTok)

		saw := t.AuthoriserSaw()
		leaked := ""
		for _, form := range []string{
			string(sentinel),
			base64.StdEncoding.EncodeToString(sentinel),
			base64.URLEncoding.EncodeToString(sentinel),
			hex.EncodeToString(sentinel),
		} {
			if bytes.Contains(saw, []byte(form)) {
				leaked = form
			}
		}
		ok("the authoriser is never sent a message body", leaked == "",
			fmt.Sprintf("found %q in %d bytes the authoriser was sent", leaked, len(saw)))
		ok("the authoriser was asked something, so the check above means anything",
			len(saw) > 0, fmt.Sprintf("the authoriser was sent %d bytes", len(saw)))
	} else {
		ok("SKIPPED: the authoriser body check needs a control plane this harness did not supply",
			true, "")
	}

	// --- one account, two customers ---------------------------------------
	// heliograph-io/heliograph-cloud#71. An estate-wide credential is correct
	// for a self-hoster, where one estate is one customer, and is a tenant
	// boundary failure the moment an account holds two. This section is the
	// test that tries: every combination of the two customers' identifiers,
	// station names and directions, with alpha's credentials.
	if t.Tenancy {
		crossed := ""
		wrongReason := ""
		for _, c := range []struct{ cred, station, dir string }{
			// alpha's station credential, against bravo.
			{TenantAlphaStation, TenantBravo, "c2s"},
			{TenantAlphaStation, TenantBravo, "s2c"},
			// alpha's control credential, against bravo. Scoping only the
			// station side leaves the half that can queue a COMMAND unbounded,
			// and a command is code execution inside somebody else's estate.
			{TenantAlphaControl, TenantBravo, "c2s"},
			{TenantAlphaControl, TenantBravo, "s2c"},
			// and bravo's, against alpha, because a hole is rarely one-sided.
			{TenantBravoStation, TenantAlpha, "c2s"},
			{TenantBravoStation, TenantAlpha, "s2c"},
			{TenantBravoControl, TenantAlpha, "c2s"},
		} {
			where := fmt.Sprintf("%s %s/%s", c.cred, c.station, c.dir)
			code, why, _ := t.putR(TenantEstate, c.station, c.dir, c.cred, 1, []byte("forged"))
			if code == 202 {
				crossed = "WROTE " + where
			} else if why.Reason != "out-of-scope" {
				wrongReason = where + " refused as " + why.Reason
			}
			code, _, _ = t.take(TenantEstate, c.station, c.dir, c.cred)
			if code == 200 {
				crossed = "READ " + where
			}
		}
		ok("a credential from one customer cannot reach another's queues", crossed == "", crossed)
		ok("crossing a customer boundary is refused as out-of-scope, not as a bad credential",
			wrongReason == "", wrongReason)

		// And each customer still does its own work, or the section above
		// proves only that everything is broken.
		code, _ = t.put(TenantEstate, TenantAlpha, "c2s", TenantAlphaControl, 1, []byte("alpha's own"))
		ok("a control credential still queues for its own station", code == 202, fmt.Sprintf("got %d", code))
		code, got, _ = t.take(TenantEstate, TenantAlpha, "c2s", TenantAlphaStation)
		ok("a station credential still collects its own requests", code == 200 && len(got) == 1,
			fmt.Sprintf("got %d with %d messages", code, len(got)))
		code, _ = t.put(TenantEstate, TenantAlpha, "s2c", TenantAlphaStation, 1, []byte("alpha's status"))
		ok("a station credential still publishes its own status", code == 202, fmt.Sprintf("got %d", code))

		// The direction asymmetry survives scoping. A station credential must
		// still not queue a request, even for its own station.
		code, _ = t.put(TenantEstate, TenantAlpha, "c2s", TenantAlphaStation, 1, []byte("evil"))
		ok("a station credential still may NOT queue a request for its own station",
			code != 202, fmt.Sprintf("got %d", code))

		// The estate-wide credential, which is the one #71 is named after.
		code, why, _ := t.putR(TenantEstate, TenantAlpha, "c2s", TenantWide, 1, []byte("x"))
		ok("a hosted tenant refuses an estate-wide credential", code != 202, fmt.Sprintf("got %d", code))
		ok("and says estate-wide is why, rather than reporting a bad credential",
			why.Reason == "estate-wide-credential", fmt.Sprintf("reason=%q", why.Reason))
	} else {
		ok("SKIPPED: the per-station isolation section needs a tenancy this harness did not supply",
			true, "")
	}

	// --- an authorisation lease nothing can verify -------------------------
	// heliograph-io/heliograph-cloud#75. A lease is a bounded, scoped, signed
	// grant a relay validates with no network call, so that a control-plane
	// outage is not a transport outage.
	//
	// This is the half BOTH implementations can be held to, and it is the one
	// that matters most if it is wrong: a relay with no verifier configured
	// must refuse every lease rather than accept one. Accepting an unverified
	// lease means accepting a forged one, and the forger chooses the scope.
	//
	// Neither implementation ships a verifier. The Go server publishes the seam
	// and refuses until an operator fills it; the Worker cannot have one at all,
	// because cryptography at the edge is forbidden. That difference is real and
	// the README states it rather than averaging over it. What is asserted here
	// is the behaviour they share.
	{
		// A syntactically valid lease, minted by nobody. The payload decodes to
		// {"e":"e1","s":["st1"],"r":["c2s"],"w":["s2c"],"nbf":1,"exp":9999999999}
		const forged = "hl1.eyJlIjoiZTEiLCJzIjpbInN0MSJdLCJyIjpbImMycyJdLCJ3IjpbInMyYyJdLCJuYmYiOjEsImV4cCI6OTk5OTk5OTk5OX0.bm90LWEtc2lnbmF0dXJl"

		code, why, _ := t.putR(t.Estate, uniq+"-lease", "s2c", forged, 1, []byte("x"))
		ok("a lease nothing can verify is refused", code != 202, fmt.Sprintf("got %d", code))
		ok("and the refusal names the lease rather than the credential",
			why.Reason == "authority-unverifiable",
			fmt.Sprintf("reason=%q", why.Reason))

		code, _, _ = t.take(t.Estate, uniq+"-lease", "c2s", forged)
		ok("a lease nothing can verify cannot collect either", code != 200,
			fmt.Sprintf("got %d", code))

		// And something merely lease-shaped is not mistaken for one. A relay
		// that read every dotted credential as a lease would refuse ordinary
		// tokens that happen to contain a full stop.
		code, _ = t.put(t.Estate, uniq+"-dotted", "c2s", t.Control, 1, []byte("x"))
		ok("an ordinary credential is still not read as a lease", code == 202,
			fmt.Sprintf("got %d", code))
	}

	// --- a lease the relay can actually verify ------------------------------
	// The other half of heliograph-io/heliograph-cloud#75, and the half that
	// makes the feature worth having: a relay honours a lease the control plane
	// signed, with no network call, so a control-plane outage is not a transport
	// outage. Both implementations verify, and NEITHER can sign.
	if t.SignLease != nil {
		leaseStation := uniq + "-leased"
		now := time.Now()
		live := Lease(t.SignLease, t.Estate, []string{leaseStation},
			[]string{"c2s"}, []string{"s2c"}, now.Add(-time.Minute), now.Add(10*time.Minute), 0)

		code, why, _ := t.putR(t.Estate, leaseStation, "s2c", live, 1, []byte("status"))
		ok("a lease signed by the control plane is honoured", code == 202,
			fmt.Sprintf("got %d %q", code, why.Reason))

		// The control credential queues, and the leased station collects, so the
		// lease is doing real work rather than being accepted and ignored.
		code, _ = t.put(t.Estate, leaseStation, "c2s", t.Control, 1, []byte("a request"))
		ok("a control credential can queue for a leased station", code == 202,
			fmt.Sprintf("got %d", code))
		code, got, _ = t.take(t.Estate, leaseStation, "c2s", live)
		ok("a leased station collects its own requests", code == 200 && len(got) == 1,
			fmt.Sprintf("got %d with %d messages", code, len(got)))

		// The asymmetry survives leasing.
		code, _ = t.put(t.Estate, leaseStation, "c2s", live, 1, []byte("evil"))
		ok("a leased station still may NOT queue a request for itself", code != 202,
			fmt.Sprintf("got %d", code))

		// Out of its own scope.
		code, _ = t.put(t.Estate, uniq+"-elsewhere", "s2c", live, 1, []byte("x"))
		ok("a lease does not reach a station it does not name", code != 202,
			fmt.Sprintf("got %d", code))

		// Expired.
		expired := Lease(t.SignLease, t.Estate, []string{leaseStation},
			[]string{"c2s"}, []string{"s2c"}, now.Add(-20*time.Minute), now.Add(-10*time.Minute), 0)
		code, why, _ = t.putR(t.Estate, leaseStation, "s2c", expired, 1, []byte("x"))
		ok("an expired lease is refused", code != 202, fmt.Sprintf("got %d", code))
		ok("and says it expired rather than blaming the credential",
			why.Reason == "authority-expired", fmt.Sprintf("reason=%q", why.Reason))

		// Signed by somebody else. The signature is the right length and the
		// payload is well formed, so only the key tells them apart.
		forged := Lease(func(payload string) []byte {
			s := make([]byte, 64)
			copy(s, payload)
			return s
		}, t.Estate, []string{leaseStation}, []string{"c2s"}, []string{"s2c"},
			now.Add(-time.Minute), now.Add(10*time.Minute), 0)
		code, why, _ = t.putR(t.Estate, leaseStation, "s2c", forged, 1, []byte("x"))
		ok("a lease signed by the wrong key is refused", code != 202, fmt.Sprintf("got %d", code))
		ok("and the refusal names the lease rather than the credential",
			why.Reason == "authority-unverifiable", fmt.Sprintf("reason=%q", why.Reason))

		// A payload edited after signing. Same signature, wider scope: this is
		// the attack the signature exists to stop, and it must fail because the
		// signature covers the ENCODED payload rather than the decoded fields.
		parts := strings.Split(live, ".")
		if len(parts) == 3 {
			wide := Lease(t.SignLease, t.Estate, nil, []string{"c2s", "s2c"},
				[]string{"c2s", "s2c"}, now.Add(-time.Minute), now.Add(10*time.Minute), 0)
			tampered := strings.Split(wide, ".")[0] + "." + strings.Split(wide, ".")[1] + "." + parts[2]
			code, _ = t.put(t.Estate, leaseStation, "c2s", tampered, 1, []byte("x"))
			ok("a lease widened after signing no longer verifies", code != 202,
				fmt.Sprintf("got %d", code))
		}
	} else {
		ok("SKIPPED: the signed-lease section needs a signing key this harness did not supply",
			true, "")
	}

	// --- a hosted tenant and an estate-wide lease ---------------------------
	// A lease is a credential, so a hosted tenant refuses one that covers every
	// station in an estate, exactly as it refuses an estate-wide token. Both
	// implementations once answered a valid lease before the tenant rule was
	// applied, and this section is what holds them to the same answer.
	if t.Tenancy && t.SignLease != nil {
		now := time.Now()
		wide := estateWideLease(t.SignLease, TenantEstate,
			[]string{"c2s"}, []string{"s2c"}, now.Add(-time.Minute), now.Add(10*time.Minute))
		code, why, _ := t.putR(TenantEstate, TenantAlpha, "s2c", wide, 1, []byte("x"))
		ok("a hosted tenant refuses a lease covering every station in an estate", code != 202,
			fmt.Sprintf("got %d", code))
		ok("and says estate-wide is why, rather than blaming the lease",
			why.Reason == "estate-wide-credential", fmt.Sprintf("reason=%q", why.Reason))
		code, _, _ = t.take(TenantEstate, TenantAlpha, "c2s", wide)
		ok("an estate-wide lease cannot collect from a hosted tenant either", code != 200,
			fmt.Sprintf("got %d", code))

		// And a lease naming its station still works, or the refusal above
		// proves only that leasing is broken under hosting.
		scoped := Lease(t.SignLease, TenantEstate, []string{TenantAlpha},
			[]string{"c2s"}, []string{"s2c"}, now.Add(-time.Minute), now.Add(10*time.Minute), 0)
		code, why, _ = t.putR(TenantEstate, TenantAlpha, "s2c", scoped, 1, []byte("alpha's status"))
		ok("a hosted tenant still honours a lease scoped to named stations", code == 202,
			fmt.Sprintf("got %d %q", code, why.Reason))
	} else {
		ok("SKIPPED: the hosted-lease section needs a tenancy and a signing key this harness did not both supply",
			true, "")
	}

	// --- estates are isolated --------------------------------------------
	if t.OtherEstate != "" {
		code, _ = t.put(t.OtherEstate, uniq, "c2s", t.Control, 1, []byte("x"))
		ok("one estate's token cannot write into another", code != 202, fmt.Sprintf("got %d", code))
		code, _, _ = t.take(t.OtherEstate, uniq, "c2s", t.StationTok)
		ok("one estate's token cannot read another", code == 401, fmt.Sprintf("got %d", code))
	}

	// --- an estate that was never configured ------------------------------
	// The zero value of a hash must not match. That would authorise everybody.
	code, _ = t.put("estate-that-does-not-exist", uniq, "c2s", t.Control, 1, []byte("x"))
	ok("an unconfigured estate is refused", code != 202, fmt.Sprintf("got %d", code))

	// --- a direction that is not one --------------------------------------
	code, _ = t.put(t.Estate, uniq, "sideways", t.Control, 1, []byte("x"))
	ok("a direction other than c2s or s2c is refused", code != 202, fmt.Sprintf("got %d", code))

	// --- the body is never interpreted -------------------------------------
	// If the relay ever started refusing bodies for their shape, it would be
	// reading them.
	allOK := true
	for i, body := range [][]byte{{}, {0}, []byte("{not json"), bytes.Repeat([]byte{0xff}, 4096)} {
		c, _ := t.put(t.Estate, fmt.Sprintf("%s-body%d", uniq, i), "c2s", t.Control, 1, body)
		if c != 202 {
			allOK = false
		}
	}
	ok("any body is accepted, including one that is not JSON or UTF-8", allOK, "")

	// --- ordering is the recipient's job -----------------------------------
	// Seq is carried but never enforced here: it is signed end to end, and a
	// hostile relay cannot lie about it. Enforcing it here would look like a
	// safety feature and be worth nothing.
	seqStation := uniq + "-seq"
	_, _ = t.put(t.Estate, seqStation, "c2s", t.Control, 99, []byte("a"))
	_, _ = t.put(t.Estate, seqStation, "c2s", t.Control, 1, []byte("b"))
	_, got, _ = t.take(t.Estate, seqStation, "c2s", t.StationTok)
	carried := len(got) == 2
	if carried {
		sort.Slice(got, func(a, b int) bool { return got[a].Seq < got[b].Seq })
		carried = got[0].Seq == 1 && got[1].Seq == 99
	}
	ok("sequence numbers are carried, not rewritten", carried, fmt.Sprintf("got %+v", got))

	// --- the long poll ------------------------------------------------------
	pollStation := uniq + "-poll"
	done := make(chan int, 1)
	go func() {
		resp, b, err := t.do("GET", t.url(t.Estate, pollStation, "c2s", ""), t.StationTok, nil)
		if err != nil || resp.StatusCode != 200 {
			done <- -1
			return
		}
		var m []msg
		_ = json.Unmarshal(b, &m)
		done <- len(m)
	}()
	time.Sleep(400 * time.Millisecond)
	_, _ = t.put(t.Estate, pollStation, "c2s", t.Control, 1, []byte("wake up"))
	select {
	case n := <-done:
		ok("a long poll wakes when a message arrives", n == 1, fmt.Sprintf("woke with %d", n))
	case <-time.After(40 * time.Second):
		ok("a long poll wakes when a message arrives", false, "it never returned")
	}

	// --- wait=0 returns immediately ------------------------------------------
	start := time.Now()
	_, _, _ = t.take(t.Estate, uniq+"-empty", "c2s", t.StationTok)
	ok("wait=0 returns immediately rather than holding the line",
		time.Since(start) < 5*time.Second, time.Since(start).String())

	out = append(out, t.leasing(uniq)...)
	out = append(out, t.durability(uniq)...)
	return out
}

// leaseReply is the answer to a collection that asked for a lease. A different
// shape from a plain collection, and deliberately so: a client that has to
// acknowledge needs something to acknowledge with, and a bare array has nowhere to
// put it.
type leaseReply struct {
	Lease    string `json:"lease"`
	Until    string `json:"until"`
	Messages []msg  `json:"messages"`
}

func (t Target) takeLeased(estate, station, dir, tok, lease string) (int, leaseReply, error) {
	resp, b, err := t.do("GET", t.url(estate, station, dir, "wait=0&lease="+lease), tok, nil)
	if err != nil {
		return 0, leaseReply{}, err
	}
	var out leaseReply
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out, nil
}

func (t Target) ack(estate, station, dir, tok, lease string) (int, int, error) {
	payload, _ := json.Marshal(map[string]string{"lease": lease})
	u := fmt.Sprintf("%s/v1/%s/%s/%s/ack", strings.TrimRight(t.BaseURL, "/"), estate, station, dir)
	resp, b, err := t.do("POST", u, tok, payload)
	if err != nil {
		return 0, 0, err
	}
	var out struct {
		Deleted int `json:"deleted"`
	}
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out.Deleted, nil
}

// leasing asserts the collection semantics that close the loss window.
//
// Delete-on-collection hands the message over and forgets it in the same breath,
// so the gap between the relay's delete and the collector's durable write is a
// place a message can be lost - and on this transport it is frequently the only
// copy of a capture from a machine nobody can log into. A lease holds the message
// until the collector says it has it.
//
// Every assertion here is observable to a client, which is why they belong in the
// contract rather than in one implementation's tests. What is NOT here: whether a
// lease survives the relay being torn down. The Worker keeps leases in Durable
// Object storage and they do; the Go server keeps them in memory and they do not.
// Both satisfy the contract, because both fail towards redelivery rather than
// towards loss, and the stable message id is what makes redelivery safe.
func (t Target) leasing(uniq string) []Result {
	var out []Result
	ok := func(name string, cond bool, why string) {
		out = append(out, Result{Name: name, OK: cond, Why: why})
	}

	// --- the compatibility guarantee, first, because it is the load-bearing one
	// Every station already deployed fetches without ?lease= and parses a bare
	// array. If that changed, this suite passing would mean nothing.
	plain := uniq + "-plain"
	if code, err := t.put(t.Estate, plain, "c2s", t.Control, 1, []byte("plain")); code != 202 {
		ok("a collection without a lease is unchanged", false, fmt.Sprintf("put %d %v", code, err))
		return out
	}
	code, got, err := t.take(t.Estate, plain, "c2s", t.StationTok)
	ok("a collection without a lease answers with a bare array of messages",
		code == 200 && len(got) == 1 && bytes.Equal(got[0].Body, []byte("plain")),
		fmt.Sprintf("got %d, %d messages (err %v)", code, len(got), err))
	_, again, _ := t.take(t.Estate, plain, "c2s", t.StationTok)
	ok("a collection without a lease still deletes what it returned", len(again) == 0,
		fmt.Sprintf("got %d", len(again)))
	ok("every message carries an id, leased or not", len(got) == 1 && got[0].ID != "",
		fmt.Sprintf("got %+v", got))

	// lease=0 means what its absence means, so a client building a query string
	// from a variable does not change semantics by leaving it empty.
	zero := uniq + "-zero"
	_, _ = t.put(t.Estate, zero, "c2s", t.Control, 1, []byte("zero"))
	code, got, err = t.take(t.Estate, zero, "c2s", t.StationTok) // take() sends no lease
	okZero := code == 200 && len(got) == 1
	resp, b, err2 := t.do("GET", t.url(t.Estate, zero, "c2s", "wait=0&lease=0"), t.StationTok, nil)
	var arr []msg
	parsedArray := err2 == nil && resp != nil && json.Unmarshal(b, &arr) == nil
	ok("lease=0 answers as a collection with no lease at all", okZero && parsedArray,
		fmt.Sprintf("plain %d/%d err=%v, lease=0 body=%s", code, len(got), err, string(b)))

	// --- a lease holds the message ------------------------------------------
	held := uniq + "-held"
	want := []byte{0x00, 0xff, 'l', 'e', 'a', 's', 'e', 0xfe}
	if code, err := t.put(t.Estate, held, "c2s", t.Control, 3, want); code != 202 {
		ok("a leased collection holds the message", false, fmt.Sprintf("put %d %v", code, err))
		return out
	}
	code, lease, err := t.takeLeased(t.Estate, held, "c2s", t.StationTok, "30s")
	leased := code == 200 && lease.Lease != "" && lease.Until != "" && len(lease.Messages) == 1
	ok("a leased collection answers with a lease id, a deadline and the messages", leased,
		fmt.Sprintf("got %d, lease=%q until=%q, %d messages (err %v)",
			code, lease.Lease, lease.Until, len(lease.Messages), err))
	if !leased {
		return out
	}
	ok("a leased message is byte for byte what was sent", bytes.Equal(lease.Messages[0].Body, want),
		fmt.Sprintf("got %v", lease.Messages[0].Body))
	ok("a leased message carries an id", lease.Messages[0].ID != "", "")

	// Nobody else may have it, with or without asking for a lease of their own.
	_, second, _ := t.takeLeased(t.Estate, held, "c2s", t.StationTok, "30s")
	ok("a message under a live lease is not handed to a second collector",
		len(second.Messages) == 0, fmt.Sprintf("got %d", len(second.Messages)))
	// And an empty leased collection says so in BOTH fields, identically on both
	// implementations. The Go server marshalled its zero time here and the Worker
	// sent an empty string, which is drift in a field a client reads: a collector
	// that trusted `until` would have been handed year 1 by one relay and nothing
	// by the other. Found by driving them with curl rather than by a test, which
	// is why there is now a test.
	ok("an empty leased collection says so in both fields",
		second.Lease == "" && second.Until == "",
		fmt.Sprintf("lease=%q until=%q", second.Lease, second.Until))
	_, plainSteal, _ := t.take(t.Estate, held, "c2s", t.StationTok)
	ok("a message under a live lease is not handed to a collection with no lease",
		len(plainSteal) == 0, fmt.Sprintf("got %d", len(plainSteal)))

	// --- acknowledging deletes it -------------------------------------------
	code, deleted, err := t.ack(t.Estate, held, "c2s", t.StationTok, lease.Lease)
	ok("acknowledging a lease deletes what it held", code == 200 && deleted == 1,
		fmt.Sprintf("got %d, deleted %d (err %v)", code, deleted, err))
	_, after, _ := t.take(t.Estate, held, "c2s", t.StationTok)
	ok("an acknowledged message is not delivered again", len(after) == 0,
		fmt.Sprintf("got %d", len(after)))

	// A repeat of an acknowledgement that already worked, which is what a
	// collector retrying a request whose response it never saw sends. 410: the
	// route exists and the lease is what is gone.
	code, _, _ = t.ack(t.Estate, held, "c2s", t.StationTok, lease.Lease)
	ok("an acknowledgement the relay is not holding is refused with 410", code == 410,
		fmt.Sprintf("got %d", code))
	code, _, _ = t.ack(t.Estate, held, "c2s", t.StationTok, "definitely-not-a-lease")
	ok("an acknowledgement of a lease that never existed is refused with 410", code == 410,
		fmt.Sprintf("got %d", code))
	code, _, _ = t.ack(t.Estate, held, "c2s", "", lease.Lease)
	ok("an acknowledgement with no token is refused", code == 401, fmt.Sprintf("got %d", code))
	if t.OtherEstate != "" {
		code, _, _ = t.ack(t.OtherEstate, held, "c2s", t.StationTok, lease.Lease)
		ok("one estate's token cannot acknowledge another's lease", code == 401,
			fmt.Sprintf("got %d", code))
	}

	// --- an abandoned lease comes back --------------------------------------
	// The assertion the whole change exists for: a collector that dies before
	// acknowledging does not take the message with it.
	dying := uniq + "-dying"
	_, _ = t.put(t.Estate, dying, "c2s", t.Control, 9, []byte("an hour of capture"))
	_, short, _ := t.takeLeased(t.Estate, dying, "c2s", t.StationTok, "1s")
	if len(short.Messages) != 1 {
		ok("an unacknowledged lease returns the messages when it expires", false,
			fmt.Sprintf("the first collection got %d messages", len(short.Messages)))
		return out
	}
	// No acknowledgement. The collector is gone.
	time.Sleep(1500 * time.Millisecond)
	_, back, _ := t.takeLeased(t.Estate, dying, "c2s", t.StationTok, "30s")
	ok("an unacknowledged lease returns the messages when it expires",
		len(back.Messages) == 1, fmt.Sprintf("got %d", len(back.Messages)))
	if len(back.Messages) == 1 {
		// The same id, which is what lets a collector recognise a retry rather
		// than spooling the same capture twice. Without it, deduplication at the
		// collector has nothing to key on.
		ok("a redelivered message keeps the id it had", back.Messages[0].ID == short.Messages[0].ID,
			fmt.Sprintf("%q then %q", short.Messages[0].ID, back.Messages[0].ID))
		ok("a redelivered message is under a new lease", back.Lease != short.Lease,
			fmt.Sprintf("both %q", back.Lease))
	}

	// --- the long poll, under a lease ---------------------------------------
	// The combination a real collector uses: wait for a message and hold it. Both
	// halves are asserted separately above and in the poll section, and a relay
	// that woke from the poll and then answered as though no lease had been asked
	// for would pass both of those and still lose the message.
	poll := uniq + "-leasepoll"
	woke := make(chan leaseReply, 1)
	go func() {
		resp, b, err := t.do("GET", t.url(t.Estate, poll, "c2s", "lease=30s"), t.StationTok, nil)
		if err != nil || resp.StatusCode != 200 {
			woke <- leaseReply{}
			return
		}
		var got leaseReply
		_ = json.Unmarshal(b, &got)
		woke <- got
	}()
	time.Sleep(400 * time.Millisecond)
	_, _ = t.put(t.Estate, poll, "c2s", t.Control, 1, []byte("wake up"))
	select {
	case got := <-woke:
		ok("a long poll that asked for a lease wakes holding one",
			got.Lease != "" && len(got.Messages) == 1,
			fmt.Sprintf("woke with lease=%q and %d messages", got.Lease, len(got.Messages)))
		if got.Lease != "" {
			// And it really is a lease: the message is still there to acknowledge.
			code, deleted, _ := t.ack(t.Estate, poll, "c2s", t.StationTok, got.Lease)
			ok("the lease from a long poll can be acknowledged", code == 200 && deleted == 1,
				fmt.Sprintf("got %d, deleted %d", code, deleted))
		}
	case <-time.After(40 * time.Second):
		ok("a long poll that asked for a lease wakes holding one", false, "it never returned")
	}

	// --- the lease parameter itself ------------------------------------------
	// One grammar, implemented by both. A form that works against one relay and
	// 400s against the other is the drift this suite exists to catch.
	bad := uniq + "-badlease"
	_, _ = t.put(t.Estate, bad, "c2s", t.Control, 1, []byte("x"))
	allRefused := true
	for _, v := range []string{"nonsense", "1h", "600", "1m30s", "-5s"} {
		code, _, _ := t.takeLeased(t.Estate, bad, "c2s", t.StationTok, v)
		if code != 400 {
			allRefused = false
			ok("a lease outside the grammar is refused: "+v, false, fmt.Sprintf("got %d", code))
		}
	}
	ok("a lease that is unparseable or too long is refused", allRefused, "")
	allAccepted := true
	for _, v := range []string{"30", "30s", "500ms", "2m"} {
		code, got, _ := t.takeLeased(t.Estate, bad, "c2s", t.StationTok, v)
		if code != 200 {
			allAccepted = false
			ok("a lease inside the grammar is accepted: "+v, false, fmt.Sprintf("got %d", code))
		}
		if got.Lease != "" {
			_, _, _ = t.ack(t.Estate, bad, "c2s", t.StationTok, got.Lease)
			_, _ = t.put(t.Estate, bad, "c2s", t.Control, 1, []byte("x"))
		}
	}
	ok("seconds, milliseconds and minutes are all accepted as a lease", allAccepted, "")

	return out
}

// durability asserts that an accepted message outlives the relay that accepted
// it, which is the one property a sender cannot verify for itself.
//
// A sender that receives a 202 and deletes its own copy has handed the relay the
// only copy. On this transport the sender is frequently a station nobody can log
// into, holding the only record of an hour-long capture, so "it costs a re-run"
// is not always a cost that can be paid.
//
// Both implementations must satisfy it. The Worker persists to Durable Object
// storage; the Go server persists to a spool directory when it has been given
// one. Whether a particular deployment IS durable is a deployment choice, which
// is why this needs a disruptor from the harness rather than asserting a storage
// model it cannot see.
func (t Target) durability(uniq string) []Result {
	var out []Result
	const (
		survives  = "a message accepted before the relay restarts is still there after it"
		notTwice  = "a message collected before the relay restarts does not come back after it"
		cameBack  = "the relay answers again after being restarted"
		accepted  = "a message is accepted before the relay is restarted"
		skipWhy   = "no disruptor was supplied, so nothing here was attempted. See cmd/conformance -restart"
		bodyMagic = "durable"
	)
	if t.Disrupt == nil {
		// Named and marked skip rather than left out. A reader of this output has
		// to be able to tell "this relay is durable" from "nobody asked".
		return []Result{
			{Name: survives, Skipped: true, Why: skipWhy},
			{Name: notTwice, Skipped: true, Why: skipWhy},
		}
	}
	ok := func(name string, cond bool, why string) {
		out = append(out, Result{Name: name, OK: cond, Why: why})
	}

	station := uniq + "-durable"
	want := []byte{0x00, 0xff, '\n', 'd', 'u', 'r', 'a', 'b', 'l', 'e', 0xfe}
	code, err := t.put(t.Estate, station, "c2s", t.Control, 11, want)
	ok(accepted, code == 202, fmt.Sprintf("got %d %v", code, err))
	if code != 202 {
		return out
	}

	if err := t.Disrupt(); err != nil {
		ok(cameBack, false, err.Error())
		return out
	}
	ok(cameBack, true, "")

	code, got, err := t.take(t.Estate, station, "c2s", t.StationTok)
	survived := code == 200 && len(got) == 1 && bytes.Equal(got[0].Body, want) && got[0].Seq == 11
	ok(survives, survived, fmt.Sprintf("got %d, %d messages, %+v (err %v)", code, len(got), got, err))

	// The other half, and the one that keeps durability from becoming a backup:
	// what has been collected must not reappear. A durable copy that outlives
	// collection is ciphertext the relay is still holding after it promised not
	// to, and the recipient would be handed it twice.
	second := uniq + "-collected"
	if code, err := t.put(t.Estate, second, "c2s", t.Control, 12, []byte(bodyMagic)); code != 202 {
		ok(notTwice, false, fmt.Sprintf("the second message was not accepted: %d %v", code, err))
		return out
	}
	if _, got, _ := t.take(t.Estate, second, "c2s", t.StationTok); len(got) != 1 {
		ok(notTwice, false, fmt.Sprintf("the second message did not come back at all: %d", len(got)))
		return out
	}
	if err := t.Disrupt(); err != nil {
		ok(notTwice, false, err.Error())
		return out
	}
	_, got, _ = t.take(t.Estate, second, "c2s", t.StationTok)
	ok(notTwice, len(got) == 0, fmt.Sprintf("it came back %d time(s) after collection", len(got)))
	return out
}

// Report renders results, and says whether everything passed.
func Report(w io.Writer, name string, rs []Result) bool {
	fmt.Fprintf(w, "\n--- relay conformance: %s ---\n", name)
	pass, fail, skip := 0, 0, 0
	for _, r := range rs {
		switch {
		case r.Skipped:
			// Printed, and printed with its reason. A skipped assertion that
			// leaves no trace is indistinguishable from one that was never
			// written.
			skip++
			fmt.Fprintf(w, "skip %s\n", r.Name)
			if r.Why != "" {
				fmt.Fprintf(w, "     %s\n", r.Why)
			}
		case r.OK:
			pass++
			fmt.Fprintf(w, "ok   %s\n", r.Name)
		default:
			fail++
			fmt.Fprintf(w, "FAIL %s\n", r.Name)
			if r.Why != "" {
				fmt.Fprintf(w, "     %s\n", r.Why)
			}
		}
	}
	fmt.Fprintf(w, "\n%s: %d passed, %d failed, %d skipped\n", name, pass, fail, skip)
	// Printed on every run, pass or fail. A green suite would otherwise read as
	// "the relay is correct" when what it means is "the relay behaves correctly
	// over HTTP", and the difference is where the two implementations diverged.
	fmt.Fprintf(w, "not asserted here: the storage model, which is not observable over HTTP.\n"+
		"  See storage_test.go and edge/test/storage-model.test.ts.\n")
	return fail == 0
}
