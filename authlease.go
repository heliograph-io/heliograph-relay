package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// Authorisation leases, so that OUR control-plane outage is not the customer's
// transport outage.
//
// THE PROBLEM. RemoteAuth puts a call in front of every operation and fails
// closed. That is right, and on its own it converts a management-plane outage
// into a transport outage: cached decisions expire, a newly started relay has
// no cache at all, and the whole fleet loses access. On a product whose
// proposition is reaching machines when things are broken, that is the worst
// possible failure, and the customer meets it at exactly the moment they needed
// it.
//
// THE ANSWER. A lease carries its own scope and expiry, and the relay validates
// it locally. An existing grant runs for its stated lifetime whatever happens to
// the control plane; anything NEW needs the control plane and fails closed.
//
// THE TRADE, WHICH IS PUBLISHED RATHER THAN HIDDEN. A lease that runs to expiry
// after being revoked means revoked access persists for up to that lifetime.
// There is no lifetime that removes this: shorter means faster revocation and a
// harder availability dependency, longer means the reverse. So the decision is
// which number to publish, and MaxAuthorityLife is it.
//
// NOT LEASED COLLECTION, and the two share a word and nothing else. lease.go is
// a collector holding messages between reading them and confirming it has them,
// so a collector that dies loses nothing. This file is about who may collect at
// all. Neither implies the other: a station can hold an authorisation lease and
// never ask for a collection lease, and the reverse.
//
// heliograph-io/heliograph-cloud#75.

// MaxAuthorityLife is the longest lease this relay will honour, and therefore
// THE MAXIMUM REVOCATION DELAY. The two are the same number on purpose.
//
// Worst case: a lease is minted, the control plane is revoked and then becomes
// unreachable before it can tell this relay, and this relay never learns. The
// lease then runs to its own expiry, and the bound on that is this constant. A
// relay that DOES hear about the revocation stops at once, which is the usual
// case and not the one worth publishing.
//
// Fifteen minutes because a station reconnecting after a network partition
// should not need the control plane to be up, and because a compromised
// credential that stays live for a quarter of an hour is a smaller problem than
// a fleet that cannot be reached at all. Proved by
// TestTheMaximumRevocationDelayIsTheNumberWePublish rather than asserted.
const MaxAuthorityLife = 15 * time.Minute

// authorityPrefix versions the encoding. A relay that does not recognise the
// version treats the credential as not a lease at all, rather than guessing.
const authorityPrefix = "hl1"

var (
	// ErrNotAnAuthority means this credential is not a lease. It is not an
	// error about the credential's validity: an ordinary bearer token produces
	// it, and the right response is to ask the authoriser.
	ErrNotAnAuthority = errors.New("this credential is not an authorisation lease")
	// ErrBadAuthority means it is shaped like a lease and is not one.
	ErrBadAuthority = errors.New("this authorisation lease could not be read")
)

// Authority is a bounded, scoped grant.
//
// It is presented as the bearer credential, so nothing has to bind it to a
// separate token and there is no second thing to steal. A relay validates it
// with no network call and hands it back to nobody.
type Authority struct {
	// Scope is what it permits, per (estate, station, direction), and nothing
	// is permitted by omission. See scope.go.
	Scope Scope
	// NotBefore and Expires bound it. Both are required: a lease with no
	// NotBefore could be minted now and held until convenient, and a lease with
	// no Expires is not a lease.
	NotBefore time.Time
	Expires   time.Time
	// Epoch is the revocation counter for this scope's estate. A relay refuses
	// any lease whose epoch is below the highest it has been told about, so
	// revoking a whole estate's leases is one number rather than a list.
	Epoch int64
	// Audience, when set, names the relay this lease is for. A lease minted for
	// one relay must not be replayable at another, and an operator running
	// several sets this.
	Audience string
}

// authorityPayload is the wire shape. Short names because this travels in a
// header on every request from a link somebody is paying for.
type authorityPayload struct {
	Est   string   `json:"e"`
	Stns  []string `json:"s,omitempty"`
	All   bool     `json:"a,omitempty"`
	Read  []string `json:"r,omitempty"`
	Write []string `json:"w,omitempty"`
	NBF   int64    `json:"nbf"`
	Exp   int64    `json:"exp"`
	Epoch int64    `json:"ep,omitempty"`
	Aud   string   `json:"aud,omitempty"`
}

// NewAuthority encodes a lease and signs it.
//
// The relay does not call this in normal operation: a lease is minted by a
// control plane, and this exists so that a control plane, a self-hoster's own
// authoriser and this package's tests all produce the same bytes. Minting is
// the caller's business, and so is the signature: sign is handed the exact
// string the verifier will be handed.
func NewAuthority(a Authority, sign func(payload string) string) string {
	p := authorityPayload{
		Est: a.Scope.Estate, Stns: a.Scope.Stations, All: a.Scope.AllStations,
		Read: a.Scope.Read, Write: a.Scope.Write,
		NBF: a.NotBefore.Unix(), Exp: a.Expires.Unix(),
		Epoch: a.Epoch, Aud: a.Audience,
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return authorityPrefix + "." + payload + "." +
		base64.RawURLEncoding.EncodeToString([]byte(sign(payload)))
}

// ParseAuthority reads a lease, and returns the exact string a verifier must
// check along with the signature it must check against.
//
// THE SIGNATURE COVERS THE ENCODED PAYLOAD RATHER THAN THE DECODED FIELDS. That
// is not a detail: verifying a re-encoding would let two different payloads
// produce the same bytes to check, and a lease could then be widened after
// signing without the signature noticing.
func ParseAuthority(credential string) (Authority, signed, error) {
	parts := strings.Split(credential, ".")
	if len(parts) != 3 || parts[0] != authorityPrefix {
		return Authority{}, signed{}, ErrNotAnAuthority
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Authority{}, signed{}, ErrBadAuthority
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Authority{}, signed{}, ErrBadAuthority
	}
	var p authorityPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Authority{}, signed{}, ErrBadAuthority
	}
	if p.Exp == 0 || p.NBF == 0 {
		// A lease with no bounds is not a lease, and accepting one would make
		// the published revocation delay a fiction.
		return Authority{}, signed{}, ErrBadAuthority
	}
	return Authority{
		Scope: Scope{
			Estate: p.Est, Stations: p.Stns, AllStations: p.All,
			Read: p.Read, Write: p.Write,
		},
		NotBefore: time.Unix(p.NBF, 0).UTC(),
		Expires:   time.Unix(p.Exp, 0).UTC(),
		Epoch:     p.Epoch,
		Audience:  p.Aud,
	}, signed{payload: parts[1], signature: string(sig)}, nil
}

// signed is the pair a verifier is given: the bytes that were signed, and the
// signature over them.
type signed struct {
	payload   string
	signature string
}

// AuthorityVerifier checks that a lease was minted by somebody entitled to mint
// it.
//
// Ed25519Verifier in verify.go is the implementation, and it VERIFIES ONLY.
// There is no signing anywhere in the shipped relay, and that is established by
// the linker rather than by this comment: TestTheRelayBinaryCannotSignALease
// reads the built binary's symbol table and fails if any route to constructing
// an ed25519 private key is reachable from main.
//
// The seam stays an interface rather than becoming a concrete type, because an
// operator with their own control plane may sign leases some other way, and
// because it is what lets a test drive the lease machinery without a primitive.
// heliograph-io/heliograph-cloud#75 has the decision and the options it beat.
type AuthorityVerifier interface {
	// Verify reports whether signature is a valid signature over payload.
	//
	// payload is the encoded middle section of the lease, exactly as it
	// arrived. An implementation must not re-encode it.
	Verify(payload, signature string) bool
}

// VerifierFunc adapts a function to AuthorityVerifier.
type VerifierFunc func(payload, signature string) bool

func (f VerifierFunc) Verify(payload, signature string) bool { return f(payload, signature) }

// AuthorityAuth accepts leases locally and refers everything else onwards.
//
// The split is the whole design. A valid unexpired lease is answered here, with
// no network call, so an outage at the control plane does not stop a station
// that already has authority. Anything else - a credential that is not a lease,
// a lease that has expired, a lease used outside its own scope - is a question
// only the control plane can answer, and during an outage Inner refuses with
// authoriser-unavailable, which is a 503 rather than a 401.
//
// That is the distinguishable refusal heliograph-io/heliograph-cloud#75 asks
// for. Enrolment is a station with no lease. A privilege increase is a station
// with a lease asking for something outside it. Both are new authority, both
// need the control plane, and both fail closed.
type AuthorityAuth struct {
	NoAccounting

	// Inner answers anything a lease does not.
	Inner Authoriser
	// Verify checks the signature. Nil refuses every lease.
	Verify AuthorityVerifier
	// Audience, when set, is the name this relay answers to. A lease naming a
	// different one is refused, so a lease minted for one relay is not
	// replayable at another.
	Audience string
	// Now is the clock, for tests.
	Now func() time.Time

	mu sync.RWMutex
	// epoch is the revocation floor per estate, and the only mutable state
	// here. It is raised by Revoke and never lowered: a control plane that
	// could lower it could un-revoke, and the relay has no way to tell a
	// genuine rollback from a replayed message.
	epoch map[string]int64
	// watchers are polls currently held under a lease, so raising an epoch can
	// end them rather than letting them run to their own timeout.
	watchers map[string][]chan Reason
}

func (a *AuthorityAuth) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Revoke raises the revocation floor for an estate.
//
// Every lease below the new epoch stops working at once, here, and any poll
// already open under one ends. A relay that never hears this call keeps
// honouring those leases until they expire, and MaxAuthorityLife is the bound
// on that.
func (a *AuthorityAuth) Revoke(estate string, epoch int64) {
	a.mu.Lock()
	if a.epoch == nil {
		a.epoch = map[string]int64{}
	}
	if epoch > a.epoch[estate] {
		a.epoch[estate] = epoch
	}
	var ending []chan Reason
	for k, chans := range a.watchers {
		if strings.HasPrefix(k, estate+"\x00") {
			ending = append(ending, chans...)
			delete(a.watchers, k)
		}
	}
	a.mu.Unlock()

	for _, ch := range ending {
		select {
		case ch <- ReasonRevoked:
		default:
		}
	}
}

// Epoch is the current revocation floor for an estate, for an operator who has
// to say which one this relay is enforcing.
func (a *AuthorityAuth) Epoch(estate string) int64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epoch[estate]
}

// check validates a lease and says why not.
//
// Every check here is local. Nothing in this function can block, make a call,
// or depend on anything outside the lease and this relay's own clock and epoch
// floor, and that is the property the whole design rests on.
func (a *AuthorityAuth) check(auth Authority, s signed, req Request) Grant {
	if a.Verify == nil || !a.Verify.Verify(s.payload, s.signature) {
		// Fail closed, and loudly. A relay that accepted an unverified lease
		// would accept a forged one, and the forger chooses the scope.
		return Grant{Reason: ReasonAuthorityUnverifiable}
	}
	if a.Audience != "" && auth.Audience != a.Audience {
		return Grant{Reason: ReasonAuthorityUnverifiable,
			Detail: "this lease was minted for a different relay"}
	}
	now := a.now()
	if auth.Expires.Sub(auth.NotBefore) > MaxAuthorityLife {
		// A lease longer than the published maximum would quietly extend the
		// revocation delay this product publishes as a number.
		return Grant{Reason: ReasonAuthorityExpired,
			Detail: "this lease is longer than this relay will honour"}
	}
	if now.Before(auth.NotBefore) {
		return Grant{Reason: ReasonAuthorityExpired,
			Detail: "this lease is not in force yet"}
	}
	if !now.Before(auth.Expires) {
		return Grant{Reason: ReasonAuthorityExpired}
	}
	if auth.Epoch < a.Epoch(auth.Scope.Estate) {
		return Grant{Reason: ReasonRevoked}
	}
	if !auth.Scope.permits(req.Estate, req.Station, req.Dir, req.Op) {
		// Out of scope is a PRIVILEGE INCREASE rather than a refusal: the
		// station may genuinely be entitled to this and just not hold a lease
		// saying so. Only the control plane can answer that, so this falls
		// through to Inner rather than being refused here.
		return Grant{Reason: ReasonOutOfScope}
	}
	return Grant{Allow: true, Scope: auth.Scope}
}

func (a *AuthorityAuth) Admit(ctx context.Context, req Request) Grant {
	auth, s, err := ParseAuthority(req.Credential)
	if err != nil {
		// Not a lease, or not a readable one. Either way it is a question for
		// whoever can answer it.
		return a.Inner.Admit(ctx, req)
	}
	g := a.check(auth, s, req)
	if g.Allow || g.Reason != ReasonOutOfScope {
		return g
	}
	// A good lease, used outside itself. That is a request for MORE authority,
	// and more authority comes from the control plane or from nowhere.
	return a.Inner.Admit(ctx, req)
}

// WithLeases is the authoriser a relay serves with: lease recognition over
// inner, and, for a hosted tenant, the tenant rule.
//
// It is here rather than in main.go so that the order the binary composes them
// in is the order the tests exercise.
//
// Leases are recognised whether or not this relay can verify one. A nil verify
// refuses every lease, for the reason it was refused.
//
// THE TENANT RULE WRAPS THE LEASE CHECK, NOT THE OTHER WAY ROUND. A lease is a
// credential, and HELIOGRAPH_RELAY_HOSTED refuses any credential not scoped to
// named stations. With Hosted inside, AuthorityAuth answered an allowed lease
// without consulting Inner, so an estate-wide lease never met the rule. Hosted
// passes every refusal through unchanged, so wrapping it outside refuses more
// grants without changing why any lease is refused.
func WithLeases(inner Authoriser, verify AuthorityVerifier, hosted bool) Authoriser {
	var a Authoriser = &AuthorityAuth{Inner: inner, Verify: verify}
	if hosted {
		a = Hosted{Inner: a}
	}
	return a
}

// watchKey identifies the polls held under one estate. The NUL keeps an estate
// named "a" from matching one named "ab".
func watchKey(estate, station, dir string) string {
	return estate + "\x00" + station + "\x00" + dir
}

// Watch ends a held poll when the lease behind it expires or is revoked.
//
// Without this a lease's stated expiry is a lower bound rather than a bound: a
// poll that started a moment before expiry would run 25 seconds past it, and a
// revocation would take effect only when the station next reconnected.
func (a *AuthorityAuth) Watch(ctx context.Context, req Request, ref string) <-chan Reason {
	auth, s, err := ParseAuthority(req.Credential)
	if err != nil {
		return a.Inner.Watch(ctx, req, ref)
	}
	if g := a.check(auth, s, req); !g.Allow {
		return a.Inner.Watch(ctx, req, ref)
	}

	ch := make(chan Reason, 1)
	k := watchKey(auth.Scope.Estate, req.Station, req.Dir)
	a.mu.Lock()
	if a.watchers == nil {
		a.watchers = map[string][]chan Reason{}
	}
	a.watchers[k] = append(a.watchers[k], ch)
	a.mu.Unlock()

	// The expiry timer, and the cleanup. Both have to happen whichever way the
	// request ends, or a flapping link accumulates timers and channels.
	left := auth.Expires.Sub(a.now())
	timer := time.NewTimer(left)
	go func() {
		defer timer.Stop()
		select {
		case <-timer.C:
			select {
			case ch <- ReasonAuthorityExpired:
			default:
			}
		case <-ctx.Done():
		}
		a.mu.Lock()
		held := a.watchers[k]
		for i, c := range held {
			if c == ch {
				a.watchers[k] = append(held[:i], held[i+1:]...)
				break
			}
		}
		if len(a.watchers[k]) == 0 {
			delete(a.watchers, k)
		}
		a.mu.Unlock()
	}()
	return ch
}
