package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A control plane that mints authorisation leases, and can be taken away.
//
// It signs with a stub rather than with a cryptographic primitive, because
// there is none in this repository and the reason is written up on
// heliograph-io/heliograph-cloud#75. Everything this file asserts is about
// scope, expiry, revocation and the outage, and none of that changes with the
// signature scheme underneath.
type minter struct {
	secret string
	epoch  int64
}

func (m *minter) mint(sc Scope, notBefore, expires time.Time) string {
	return NewAuthority(Authority{
		Scope: sc, NotBefore: notBefore, Expires: expires, Epoch: m.epoch,
	}, stubSign(m.secret))
}

// stubSign and stubVerify are a MARKER, not a signature.
//
// They exist so the lease machinery can be tested end to end. They prove
// nothing, and a relay configured with them is not protected against a forged
// lease. Nothing else in this package pretends otherwise: the default verifier
// refuses every lease, so a deployment that forgot to supply a real one fails
// closed rather than accepting anything.
func stubSign(secret string) func(payload string) string {
	return func(payload string) string { return "stub-" + secret + "-" + payload }
}

func stubVerify(secret string) AuthorityVerifier {
	return VerifierFunc(func(payload, signature string) bool {
		return signature == "stub-"+secret+"-"+payload
	})
}

func alphaScope() Scope {
	return Scope{
		Estate: "e-9f3c1a", Stations: []string{"pump-01"},
		Read: []string{"c2s"}, Write: []string{"s2c"},
	}
}

// refusesEverything stands in for a control plane that cannot be reached.
type refusesEverything struct {
	NoAccounting
	NoSessions
	mu     sync.Mutex
	asked  int
	reason Reason
}

func (r *refusesEverything) Admit(context.Context, Request) Grant {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked++
	return Grant{Reason: r.reason}
}

func (r *refusesEverything) timesAsked() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.asked
}

// A lease carries its own scope and expiry, and the relay validates it without
// asking anybody.
//
// The inner authoriser here refuses everything and counts how often it was
// consulted. If the relay needed it, the request would fail; if the relay
// merely preferred not to use it, the count would rise. Neither happens.
//
// heliograph-io/heliograph-cloud#75.
func TestALeaseIsValidatedWithNoNetworkCall(t *testing.T) {
	m := &minter{secret: "s1"}
	down := &refusesEverything{reason: ReasonAuthoriserUnavailable}
	auth := &AuthorityAuth{Inner: down, Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)

	lease := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("status")); r.StatusCode != 202 {
		t.Fatalf("a valid lease was refused: %d", r.StatusCode)
	}
	if n := down.timesAsked(); n != 0 {
		t.Errorf("the relay consulted the authoriser %d times to validate a lease it was handed", n)
	}
}

// A lease is scoped exactly as a credential is, and the same test that tries.
func TestALeaseCannotReachOutsideItsOwnScope(t *testing.T) {
	m := &minter{secret: "s1"}
	auth := &AuthorityAuth{Inner: &refusesEverything{reason: ReasonBadCredential},
		Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)
	lease := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))

	// Another customer's estate, and another station in its own. Neither
	// direction, neither verb.
	for _, target := range []string{
		"/v1/e-2b7d44/till-07/c2s",
		"/v1/e-2b7d44/till-07/s2c",
		"/v1/e-9f3c1a/till-07/c2s",
		"/v1/e-9f3c1a/till-07/s2c",
		"/v1/e-2b7d44/pump-01/c2s",
	} {
		if r := put(t, srv, target, lease, 1, []byte("x")); r.StatusCode == 202 {
			t.Errorf("the lease wrote to %s", target)
		}
		if r := do(t, srv, "GET", target+"?wait=0", lease, nil); r.StatusCode == 200 {
			t.Errorf("the lease read %s", target)
		}
	}

	// Its own station, the direction it does not hold. The asymmetry survives
	// leasing: a station lease reads c2s and writes s2c, so it still cannot
	// queue a request for itself.
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/c2s", lease, 1, []byte("evil")); r.StatusCode == 202 {
		t.Error("a station lease queued a request for its own station")
	}
	if r := do(t, srv, "GET", "/v1/e-9f3c1a/pump-01/s2c?wait=0", lease, nil); r.StatusCode == 200 {
		t.Error("a station lease read the queue it publishes into")
	}
	// And it still does its own job, or the rest of this proves only that
	// everything is refused.
	if r := do(t, srv, "GET", "/v1/e-9f3c1a/pump-01/c2s?wait=0", lease, nil); r.StatusCode != 200 {
		t.Errorf("the lease could not collect its own requests: %d", r.StatusCode)
	}
}

// A control-plane outage leaves existing leases working until expiry, in a test
// that kills the control plane.
//
// This is the failure the whole design is arranged around. heliograph exists to
// reach machines when things are broken, and a transport that stops because OUR
// control plane stopped is the opposite of the proposition, met at exactly the
// moment somebody needed it.
func TestAControlPlaneOutageLeavesExistingLeasesWorking(t *testing.T) {
	cp := newControlPlane(t)
	m := &minter{secret: "s1"}
	remote := NewRemoteAuth(cp.srv.URL)
	auth := &AuthorityAuth{Inner: remote, Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)

	lease := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("before")); r.StatusCode != 202 {
		t.Fatalf("with the control plane up: %d", r.StatusCode)
	}

	cp.stop()

	// The station keeps working, on a route it has never used before, so this
	// cannot be a cached decision.
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 2, []byte("during")); r.StatusCode != 202 {
		t.Fatalf("an unexpired lease stopped working when the control plane did: %d", r.StatusCode)
	}
	if r := do(t, srv, "GET", "/v1/e-9f3c1a/pump-01/c2s?wait=0", lease, nil); r.StatusCode != 200 {
		t.Fatalf("an unexpired lease could not collect during the outage: %d", r.StatusCode)
	}
}

// Enrolment and any privilege increase refuse during that outage, and the
// refusal is distinguishable from a bad credential.
//
// A station arriving with no lease is enrolment. A station presenting a lease
// and asking for something outside it is a privilege increase. Both need the
// control plane, and both must answer 503 rather than 401, because a 401 sends
// somebody to check a credential on a machine they cannot reach while the fault
// is on our side.
func TestEnrolmentAndPrivilegeIncreaseRefuseDuringAnOutage(t *testing.T) {
	cp := newControlPlane(t)
	m := &minter{secret: "s1"}
	remote := NewRemoteAuth(cp.srv.URL)
	auth := &AuthorityAuth{Inner: remote, Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)
	lease := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))

	cp.stop()

	// Enrolment: a credential that is not a lease at all.
	r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", "a-newly-planted-station", 1, []byte("hello"))
	if r.StatusCode == http.StatusUnauthorized {
		t.Error("enrolment during an outage answered 401, which sends the reader to the wrong side of the gap")
	}
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("enrolment during an outage answered %d, want 503", r.StatusCode)
	}
	if got := reasonOf(t, r); got != string(ReasonAuthoriserUnavailable) {
		t.Errorf("enrolment refused as %q, want %q", got, ReasonAuthoriserUnavailable)
	}

	// A privilege increase: a good lease, used for something outside it.
	r = put(t, srv, "/v1/e-9f3c1a/pump-01/c2s", lease, 1, []byte("queue me a command"))
	if r.StatusCode == http.StatusUnauthorized {
		t.Error("a privilege increase during an outage answered 401")
	}
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("a privilege increase during an outage answered %d, want 503", r.StatusCode)
	}
	if got := reasonOf(t, r); got != string(ReasonAuthoriserUnavailable) {
		t.Errorf("a privilege increase refused as %q, want %q", got, ReasonAuthoriserUnavailable)
	}
}

// An expired lease is refused, and says it expired.
func TestAnExpiredLeaseIsRefusedAndSaysSo(t *testing.T) {
	m := &minter{secret: "s1"}
	auth := &AuthorityAuth{Inner: &refusesEverything{reason: ReasonBadCredential},
		Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)

	lease := m.mint(alphaScope(), time.Now().Add(-20*time.Minute), time.Now().Add(-10*time.Minute))
	r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("x"))
	if r.StatusCode == 202 {
		t.Fatal("an expired lease was accepted")
	}
	if got := reasonOf(t, r); got != string(ReasonAuthorityExpired) {
		t.Errorf("refused as %q, want %q", got, ReasonAuthorityExpired)
	}
}

// A lease not yet in force is refused too. Clocks disagree, and a lease minted
// for later must not work now just because this relay's clock runs fast.
func TestALeaseNotYetInForceIsRefused(t *testing.T) {
	m := &minter{secret: "s1"}
	auth := &AuthorityAuth{Inner: &refusesEverything{reason: ReasonBadCredential},
		Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)

	lease := m.mint(alphaScope(), time.Now().Add(10*time.Minute), time.Now().Add(20*time.Minute))
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("x")); r.StatusCode == 202 {
		t.Fatal("a lease that is not yet in force was accepted")
	}
}

// A lease nothing can verify is refused, and a relay with no verifier
// configured refuses every lease.
//
// Fail closed, and loudly. A relay that accepted an unverified lease would
// accept a forged one, and the forger chooses the scope.
func TestALeaseNothingCanVerifyIsRefused(t *testing.T) {
	m := &minter{secret: "s1"}
	good := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))

	for name, auth := range map[string]*AuthorityAuth{
		"no verifier configured": {Inner: &refusesEverything{reason: ReasonBadCredential}, Now: time.Now},
		"the wrong key":          {Inner: &refusesEverything{reason: ReasonBadCredential}, Verify: stubVerify("s2"), Now: time.Now},
	} {
		srv := scopedServer(t, auth)
		r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", good, 1, []byte("x"))
		if r.StatusCode == 202 {
			t.Errorf("%s: a lease was accepted", name)
		}
		if got := reasonOf(t, r); got != string(ReasonAuthorityUnverifiable) {
			t.Errorf("%s: refused as %q, want %q", name, got, ReasonAuthorityUnverifiable)
		}
	}
}

// Tampering with the scope invalidates the lease, because the signature covers
// the payload rather than sitting beside it.
func TestAWidenedLeaseNoLongerVerifies(t *testing.T) {
	m := &minter{secret: "s1"}
	auth := &AuthorityAuth{Inner: &refusesEverything{reason: ReasonBadCredential},
		Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)

	lease := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))
	wider := NewAuthority(Authority{
		Scope:     Scope{Estate: "e-9f3c1a", AllStations: true, Read: []string{"c2s", "s2c"}, Write: []string{"c2s", "s2c"}},
		NotBefore: time.Now().Add(-time.Minute), Expires: time.Now().Add(10 * time.Minute),
	}, func(string) string {
		// The original lease's signature, carried across to a payload it was
		// not made for.
		return strings.Split(lease, ".")[2]
	})
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/c2s", wider, 1, []byte("x")); r.StatusCode == 202 {
		t.Fatal("a lease widened after signing was accepted")
	}
}

// A lease longer than the published maximum is refused.
//
// The maximum revocation delay IS the maximum lease life, so a lease that
// outlived it would quietly extend the number this product publishes.
func TestALeaseLongerThanTheMaximumIsRefused(t *testing.T) {
	m := &minter{secret: "s1"}
	auth := &AuthorityAuth{Inner: &refusesEverything{reason: ReasonBadCredential},
		Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)

	now := time.Now()
	lease := m.mint(alphaScope(), now.Add(-time.Minute), now.Add(MaxAuthorityLife+2*time.Minute))
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("x")); r.StatusCode == 202 {
		t.Fatalf("a lease of %s was accepted, and the maximum is %s",
			MaxAuthorityLife+time.Minute, MaxAuthorityLife)
	}
}

// The maximum revocation delay, revoked and measured.
//
// Revocation raises the epoch. A lease minted under the old epoch is refused as
// soon as the relay learns the new one, and a relay that has NOT learned it
// keeps honouring the lease until the lease expires. So the worst case is a
// relay that never hears about the revocation, and the bound on that is the
// lease's own life.
//
// This measures it rather than asserting it: mint the longest lease the relay
// will accept, revoke at once, and step a fake clock forward until access stops.
func TestTheMaximumRevocationDelayIsTheNumberWePublish(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	m := &minter{secret: "s1"}
	auth := &AuthorityAuth{Inner: &refusesEverything{reason: ReasonBadCredential},
		Verify: stubVerify("s1"), Now: clock}
	srv := scopedServer(t, auth)

	// The longest lease this relay will accept.
	lease := m.mint(alphaScope(), now, now.Add(MaxAuthorityLife))
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("x")); r.StatusCode != 202 {
		t.Fatalf("the lease did not work to begin with: %d", r.StatusCode)
	}

	// Revoked, at a control plane this relay cannot reach. Nothing here learns
	// of it: this is the worst case rather than the usual one.
	revokedAt := now

	// Step forward a minute at a time and find the first moment it stops.
	var stopped time.Duration
	for step := time.Minute; step <= MaxAuthorityLife+10*time.Minute; step += time.Minute {
		now = revokedAt.Add(step)
		if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("x")); r.StatusCode != 202 {
			stopped = step
			break
		}
	}
	if stopped == 0 {
		t.Fatalf("access never stopped, so there is no maximum revocation delay to publish")
	}
	if stopped > MaxAuthorityLife {
		t.Errorf("access continued for %s after revocation, and the published maximum is %s",
			stopped, MaxAuthorityLife)
	}
	t.Logf("access stopped %s after revocation; the published maximum is %s", stopped, MaxAuthorityLife)
}

// And when the relay DOES learn of the revocation, it stops at once.
func TestRaisingTheEpochRefusesAnOlderLeaseImmediately(t *testing.T) {
	m := &minter{secret: "s1", epoch: 4}
	auth := &AuthorityAuth{Inner: &refusesEverything{reason: ReasonBadCredential},
		Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)

	lease := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("x")); r.StatusCode != 202 {
		t.Fatalf("the lease did not work to begin with: %d", r.StatusCode)
	}

	auth.Revoke("e-9f3c1a", 5)

	r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 2, []byte("x"))
	if r.StatusCode == 202 {
		t.Fatal("a lease from before the revocation still worked")
	}
	if got := reasonOf(t, r); got != string(ReasonRevoked) {
		t.Errorf("refused as %q, want %q", got, ReasonRevoked)
	}
	// A lease minted under the new epoch works, or revocation is a way of
	// locking a customer out permanently.
	m.epoch = 5
	fresh := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))
	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", fresh, 1, []byte("x")); r.StatusCode != 202 {
		t.Fatalf("a lease minted after the revocation was refused: %d", r.StatusCode)
	}
}

// An epoch is per estate, so revoking one customer's leases does not revoke
// another's.
func TestRevokingOneEstateDoesNotRevokeAnother(t *testing.T) {
	m := &minter{secret: "s1", epoch: 1}
	auth := &AuthorityAuth{Inner: &refusesEverything{reason: ReasonBadCredential},
		Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)

	other := Scope{Estate: "e-2b7d44", Stations: []string{"till-07"},
		Read: []string{"c2s"}, Write: []string{"s2c"}}
	bravo := m.mint(other, time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))

	auth.Revoke("e-9f3c1a", 99)

	if r := put(t, srv, "/v1/e-2b7d44/till-07/s2c", bravo, 1, []byte("x")); r.StatusCode != 202 {
		t.Fatalf("revoking one estate revoked another: %d", r.StatusCode)
	}
}

// A poll that is already open ends when its lease does.
//
// "Authorise every call" says nothing about a call still in progress, and a
// long poll is held for 25 seconds by design. Without this, a lease's stated
// expiry would be a lower bound rather than a bound.
func TestAPollAlreadyOpenEndsWhenItsLeaseExpires(t *testing.T) {
	m := &minter{secret: "s1"}
	auth := &AuthorityAuth{Inner: &refusesEverything{reason: ReasonBadCredential},
		Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)

	// In force now, gone in a moment.
	lease := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(300*time.Millisecond))

	type result struct {
		code   int
		reason string
	}
	done := make(chan result, 1)
	go func() {
		r := do(t, srv, "GET", "/v1/e-9f3c1a/pump-01/c2s", lease, nil)
		var why struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&why)
		done <- result{r.StatusCode, why.Reason}
	}()

	select {
	case got := <-done:
		if got.code == 200 {
			t.Fatal("a poll outlived the lease that authorised it")
		}
		if got.reason != string(ReasonAuthorityExpired) {
			t.Errorf("the poll ended as %q, want %q", got.reason, ReasonAuthorityExpired)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a poll held past its lease's expiry and was still going")
	}
}

// A poll that is already open ends when the epoch is raised under it.
func TestAPollAlreadyOpenEndsWhenItsAuthorityIsRevoked(t *testing.T) {
	m := &minter{secret: "s1", epoch: 1}
	auth := &AuthorityAuth{Inner: &refusesEverything{reason: ReasonBadCredential},
		Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)
	lease := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))

	done := make(chan string, 1)
	go func() {
		r := do(t, srv, "GET", "/v1/e-9f3c1a/pump-01/c2s", lease, nil)
		var why struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&why)
		done <- why.Reason
	}()
	time.Sleep(200 * time.Millisecond) // let the poll get in and wait
	auth.Revoke("e-9f3c1a", 2)

	select {
	case got := <-done:
		if got != string(ReasonRevoked) {
			t.Errorf("the poll ended as %q, want %q", got, ReasonRevoked)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoking authority did not end a poll that was already open")
	}
}

// The honest limit, asserted so it cannot be forgotten: a message already
// delivered is not recalled by revocation, because it is no longer here.
//
// Revocation stops the next collection and ends an open poll. It does not reach
// a command a station has already taken. That is the station's replay and
// request-id handling, and this test exists so nobody reads "revocation" as
// covering it.
func TestRevocationDoesNotRecallAMessageAlreadyDelivered(t *testing.T) {
	m := &minter{secret: "s1", epoch: 1}
	auth := &AuthorityAuth{Inner: &refusesEverything{reason: ReasonBadCredential},
		Verify: stubVerify("s1"), Now: time.Now}
	st := NewStore()
	srv := httptest.NewServer(NewAuthorisingServer(st, auth, quiet()).Routes())
	t.Cleanup(srv.Close)

	control := m.mint(Scope{Estate: "e-9f3c1a", Stations: []string{"pump-01"},
		Read: []string{"s2c"}, Write: []string{"c2s"}},
		time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))
	station := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))

	put(t, srv, "/v1/e-9f3c1a/pump-01/c2s", control, 1, []byte("run this"))
	r := do(t, srv, "GET", "/v1/e-9f3c1a/pump-01/c2s?wait=0", station, nil)
	var got []Message
	_ = json.NewDecoder(r.Body).Decode(&got)
	if len(got) != 1 {
		t.Fatalf("the station collected %d messages", len(got))
	}

	// Revoked after delivery. The relay stops the NEXT collection.
	auth.Revoke("e-9f3c1a", 2)
	if r := do(t, srv, "GET", "/v1/e-9f3c1a/pump-01/c2s?wait=0", station, nil); r.StatusCode != 401 {
		t.Errorf("a revoked lease could still collect: %d", r.StatusCode)
	}
	// And the message that was already handed over is gone from here, which is
	// what "not recalled" means in this server rather than a claim about what
	// the station does with it.
	if d := st.Depth("e-9f3c1a", "pump-01", "c2s"); d != 0 {
		t.Errorf("the delivered message was still queued: %d", d)
	}
}

// A malformed lease is not mistaken for a credential, and vice versa.
func TestSomethingThatIsNotALeaseFallsThroughToTheAuthoriser(t *testing.T) {
	inner := &refusesEverything{reason: ReasonBadCredential}
	auth := &AuthorityAuth{Inner: inner, Verify: stubVerify("s1"), Now: time.Now}
	srv := scopedServer(t, auth)

	for _, credential := range []string{"an-ordinary-token", "hl1.not-base64!.sig", "hl1.", "hl2.a.b"} {
		before := inner.timesAsked()
		put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", credential, 1, []byte("x"))
		if inner.timesAsked() == before {
			t.Errorf("%q was treated as a lease rather than passed to the authoriser", credential)
		}
	}
}

// A hosted tenant refuses an estate-wide lease, as it refuses an estate-wide
// credential.
//
// HELIOGRAPH_RELAY_HOSTED promises to refuse any credential not scoped to named
// stations, and a lease is a credential. The lease path used to answer before
// the tenant rule was applied, so a valid lease saying allStations was admitted
// by a relay that had been told one estate may hold several customers.
//
// Built with WithLeases, the composition main.go serves with, so this is the
// order the binary runs rather than an order a test chose.
func TestAHostedTenantRefusesAnEstateWideLease(t *testing.T) {
	m := &minter{secret: "s1"}
	srv := scopedServer(t, WithLeases(&refusesEverything{reason: ReasonBadCredential},
		stubVerify("s1"), true))

	wide := Scope{
		Estate: "e-9f3c1a", AllStations: true,
		Read: []string{"c2s"}, Write: []string{"s2c"},
	}
	lease := m.mint(wide, time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))

	r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("status"))
	if r.StatusCode == 202 {
		t.Fatal("a hosted tenant accepted a lease covering every station in the estate")
	}
	if got := reasonOf(t, r); got != string(ReasonEstateWide) {
		t.Errorf("refused as %q, want %q", got, ReasonEstateWide)
	}
	if r.StatusCode != 401 {
		t.Errorf("got %d, want 401", r.StatusCode)
	}
	if r := do(t, srv, "GET", "/v1/e-9f3c1a/pump-01/c2s?wait=0", lease, nil); r.StatusCode == 200 {
		t.Error("a hosted tenant let an estate-wide lease collect")
	}
}

// And a hosted tenant still honours a lease scoped to named stations, or the
// test above proves only that leasing is broken under hosting.
func TestAHostedTenantHonoursAStationScopedLease(t *testing.T) {
	m := &minter{secret: "s1"}
	srv := scopedServer(t, WithLeases(&refusesEverything{reason: ReasonBadCredential},
		stubVerify("s1"), true))
	lease := m.mint(alphaScope(), time.Now().Add(-time.Minute), time.Now().Add(10*time.Minute))

	if r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", lease, 1, []byte("status")); r.StatusCode != 202 {
		t.Fatalf("a hosted tenant refused a station-scoped lease: %d %q", r.StatusCode, reasonOf(t, r))
	}
	if r := do(t, srv, "GET", "/v1/e-9f3c1a/pump-01/c2s?wait=0", lease, nil); r.StatusCode != 200 {
		t.Errorf("a station-scoped lease could not collect under a hosted tenant: %d", r.StatusCode)
	}
}

// Hosting changes which grants are refused, never why a lease was refused.
//
// A lease refused for its signature or its window says so under a hosted
// tenant exactly as it does anywhere else, because an operator reading
// "estate-wide-credential" for an expired lease would go looking at scope.
func TestAHostedTenantKeepsALeaseRefusalReason(t *testing.T) {
	m := &minter{secret: "s1"}
	now := time.Now()
	for name, c := range map[string]struct {
		lease string
		want  Reason
	}{
		"expired": {m.mint(alphaScope(), now.Add(-20*time.Minute), now.Add(-10*time.Minute)),
			ReasonAuthorityExpired},
		"signed by somebody else": {(&minter{secret: "s2"}).mint(alphaScope(),
			now.Add(-time.Minute), now.Add(10*time.Minute)), ReasonAuthorityUnverifiable},
	} {
		srv := scopedServer(t, WithLeases(&refusesEverything{reason: ReasonBadCredential},
			stubVerify("s1"), true))
		r := put(t, srv, "/v1/e-9f3c1a/pump-01/s2c", c.lease, 1, []byte("x"))
		if got := reasonOf(t, r); got != string(c.want) {
			t.Errorf("%s: refused as %q, want %q", name, got, c.want)
		}
	}
}

func TestAnAuthorityRoundTripsThroughItsEncoding(t *testing.T) {
	want := Authority{
		Scope:     alphaScope(),
		NotBefore: time.Unix(1789255130, 0).UTC(),
		Expires:   time.Unix(1789255430, 0).UTC(),
		Epoch:     7,
	}
	got, _, err := ParseAuthority(NewAuthority(want, stubSign("s1")))
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotBefore.Equal(want.NotBefore) || !got.Expires.Equal(want.Expires) {
		t.Errorf("times changed: %v to %v, %v to %v",
			want.NotBefore, got.NotBefore, want.Expires, got.Expires)
	}
	if got.Epoch != want.Epoch || got.Scope.Estate != want.Scope.Estate {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if len(got.Scope.Stations) != 1 || got.Scope.Stations[0] != "pump-01" {
		t.Errorf("stations changed: %v", got.Scope.Stations)
	}
}
