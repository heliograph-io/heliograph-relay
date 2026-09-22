<div align="center">

# heliograph-relay

**Stores and forwards ciphertext it cannot read**

[![License: FSL-1.1-ALv2](https://img.shields.io/badge/License-FSL--1.1--ALv2-blue.svg)](LICENSE)
[![Fair Source](https://img.shields.io/badge/fair-source-ff69b4.svg)](https://fair.io/)

Part of [heliograph](https://github.com/heliograph-io/heliograph), by [DBHQ](https://dbhq.uk)

</div>

---

## What this is

The relay for [heliograph](https://github.com/heliograph-io/heliograph): a queue that
lets a control and a station reach each other when neither can reach the other
directly. Both sides dial **out** over ordinary HTTPS, so an estate needs no git
host, no storage account, no VNet and no inbound firewall rule.

## What it can and cannot do

**There is no key here worth stealing and no plaintext to subpoena.** That is
the design, not an omission. Every message arrives already sealed by the client
and bound to its estate, station, direction and sequence number, and signed.
This server sees a byte slice, a routing key and a length.

> **This section used to say "There is no cryptography in this repository."**
> It is corrected here rather than quietly edited, because it was offered as a
> reason to trust this component and somebody may have approved the relay on the
> strength of it.
>
> That sentence was a **proxy** for the claim above, and the proxy has narrowed
> while the claim has not. The relay now verifies authorisation lease signatures
> with Ed25519, in both implementations, and **a public key is not a secret**:
> an attacker who takes everything this relay holds gets a key that checks
> signatures and makes none. Nothing else changed. It still holds no private
> key, still never sees plaintext, and still cannot forge a message.
>
> What it cost: a reader can no longer confirm the old sentence with one grep.
> So the narrower rule is enforced instead of asserted, and by the linker rather
> than by a grep - see [Verified, never signed](#verified-never-signed).

That is what makes the claim checkable: there is no private key here to leak, no
plaintext to subpoena, and no code path that could be persuaded to produce
either. You can establish it by reading `relay.go`, `server.go` and `verify.go`
rather than by trusting whoever is running it.

**It can:**

- see which estate is talking to which station, how often, and how big the messages are
- refuse to deliver, or delay delivery

**It cannot:**

- read a message
- alter one without the recipient noticing
- forge one, in either direction
- replay one, because sequence numbers are signed and enforced by the recipient

The last one matters most. A relay that could forge a request would have code
execution inside every estate at once, through a channel the customer installed
deliberately and trusts. That is a far worse position than reading logs, and it
is why authenticity comes before confidentiality in the design.

### What is NOT hidden

Message sizes and timing. The relay knows roughly how long a log was and roughly
how long a step took. Padding was considered and rejected for now: it costs
bandwidth on links that are often poor, and the leak is coarse. It is stated
here rather than implied away.

## Tokens are not the security boundary for content or execution

Content and execution are settled by signatures this server cannot make. Every
message arrives already sealed, and every request is signed by a key the relay
does not hold, so **a stolen token yields no plaintext and cannot cause a
station to run anything.** Saying so plainly matters, because "we use scoped
tokens" is exactly the kind of claim that gets mistaken for the real protection.

**They are the boundary for four other things, and all four matter to whoever
is paying for the transport:**

| a stolen token lets somebody | and the cost is |
|---|---|
| **collect** a queue | ciphertext they cannot read - and the legitimate collector never gets it, because a collection with no lease deletes. Silent loss, not silent disclosure. A thief who collects **under a lease** and never acknowledges causes a delay rather than a loss, but a thief chooses |
| **fill** a queue to `DefaultMaxQueue` | the real sender gets a 429 and delivery stops |
| **spend** whatever the operator is metering | denial of service, on somebody else's bill |
| **cross a tenant boundary**, wherever one authoriser serves several customers | one customer's routing keys reachable with another's credential |

The first row is the one that changed. This section used to say "a stolen token
yields denial of service and metadata", and that sentence was written when a
lost message cost a re-run. `Store.Take` (`relay.go:131`) deletes in the same
breath as it returns, and on this transport the sender is often a station nobody
can log into, holding the only copy of an hour-long capture. A re-run is not
always available, because the state that produced the log has moved on.

**Leased collection now exists** ([Collecting under a lease](#collecting-under-a-lease)),
and it changes that row for the honest collector rather than for the thief. A
collector that leases and dies loses nothing, because the messages come back. A
thief who has stolen a token still collects destructively if it chooses to, since
`?lease=` is the client's choice and the relay cannot tell the difference. What the
lease removes is the accidental loss, which is the common case; what it does not
remove is the deliberate one, which needs the token not to be stolen.

So treat a station token as a credential worth protecting, even though it cannot
read anything.

Tokens are asymmetric on purpose: a **station** token may read requests and
write status and logs, and may **not** queue a request, even for its own
station. A station credential sits on a machine nobody can reach and cannot be
rotated quickly.

## Run it

```bash
CTL=$(head -c 32 /dev/urandom | base64)
STN=$(head -c 32 /dev/urandom | base64)

docker run -p 8080:8080 \
  -e HELIOGRAPH_RELAY_ESTATES="payments:$CTL:$STN" \
  ghcr.io/heliograph-io/heliograph-relay:latest
```

Or from source:

```bash
go build ./cmd/heliograph-relay
HELIOGRAPH_RELAY_ESTATES="payments:$CTL:$STN" ./heliograph-relay
```

Put it behind a TLS terminator. The relay speaks plain HTTP on purpose: TLS
belongs to whatever is already terminating it, and a server that also managed
certificates would be a bigger thing to audit for no gain.

## Configuration

| | |
|---|---|
| `HELIOGRAPH_RELAY_ADDR` | listen address, default `:8080` |
| `HELIOGRAPH_RELAY_ESTATES` | `estate:controlToken:stationToken`, comma separated |
| `HELIOGRAPH_RELAY_STATIONS` | `estate:station:role:credential`, comma separated. `role` is `control` or `station`. Per-station scope |
| `HELIOGRAPH_RELAY_AUTHORISER` | a URL that answers authorisation decisions. When set, estates are that service's business and `HELIOGRAPH_RELAY_ESTATES` is not read |
| `HELIOGRAPH_RELAY_HOSTED` | refuse any credential not scoped to named stations, including one that declines to say |
| `HELIOGRAPH_RELAY_LEASE_KEY` | the Ed25519 **public** key authorisation leases are signed with, hex or base64. Unset means every lease is refused |
| `HELIOGRAPH_RELAY_SPOOL` | directory for durable messages. Unset means a restart drops what has not been collected: see [Storage](#storage) |

It **refuses to start** with none of the three configured. Starting and answering 401
to everything looks exactly like a credential problem at the far end, and sends
the reader to the wrong side of the gap.

It also refuses an estate whose two tokens are identical, since that collapses
the only scope separation there is.

## One relay, more than one customer

`HELIOGRAPH_RELAY_ESTATES` scopes a credential to an **estate**, and in both
directions: either side may read either queue of its own estate. That is right
when one estate is one customer, which is the self-hosted case.

**It is wrong the moment an account holds two.** Put two customers under one
estate identifier and a station credential lifted from a machine at one of them
reads the other's queues and writes fabricated replies into the other's reply
queue. Direction restrictions do not provide station isolation, and a station
name is not a secret: it travels in a URL and appears in logs.

So `HELIOGRAPH_RELAY_STATIONS` scopes one level narrower, per station:

```bash
HELIOGRAPH_RELAY_STATIONS="\
e-9f3c1a:pump-01:station:$ALPHA_STN,\
e-9f3c1a:pump-01:control:$ALPHA_CTL,\
e-2b7d44:till-07:station:$BRAVO_STN,\
e-2b7d44:till-07:control:$BRAVO_CTL"
```

A control credential covering a group is listed once per station. The direction
asymmetry is unchanged and survives scoping: a `station` role reads `c2s` and
writes `s2c`, so it still cannot queue a request even for its own station.

**Nothing is permitted by omission.** A scope that matched by leaving a field
blank is how an estate-wide credential ends up in a multi-customer tenant by
accident, and the accident is silent until somebody reads somebody else's logs.
A malformed entry is refused by name rather than skipped, because a skipped
entry fails closed and is far harder to diagnose than a refusal.

### The identifier in the first path segment

For a tenant carrying several customers it is **opaque, minted per station at
enrolment, and kept for that station's life**. It is derived from nothing and is
never treated as a secret.

One identifier per account has fewer moving parts and was rejected. The
identifier is written into a machine's configuration when the operator plants
it, and that machine is one nobody can reach, so a per-account identifier makes
every reorganisation a job of reaching machines. Per station, renaming a group,
nesting it differently or moving a whole group to another account is a record
change on the authoriser's side and **no station configuration changes at all**.

`TestMovingAGroupBetweenAccountsChangesNoStationConfiguration` is that claim
asserted rather than described.

### `HELIOGRAPH_RELAY_HOSTED`

Set it and the relay refuses any credential it cannot prove is scoped to named
stations, with `"reason":"estate-wide-credential"`.

**Silence is refused as firmly as an explicit estate-wide grant.** An authoriser
that answers "allow" without saying what for has not said the credential is
station-scoped, and reading silence as the safe answer is how this class of hole
gets created in the first place.

## Bring your own authoriser

Set `HELIOGRAPH_RELAY_AUTHORISER` and the relay asks that URL instead of reading
tokens from its environment. Accounts, estates, quota, policy and metering
become whatever answers it, and none of that is added to the code in the path.

```
POST https://authz.example/decide
{"credential":"...","estate":"e1","station":"st1","dir":"c2s","op":"write","bytes":812}

200 OK
{"allow":true,"scope":{"estate":"e1","stations":["st1"],"allStations":false,
                       "read":["s2c"],"write":["c2s"]}}

200 OK
{"allow":false,"reason":"wrong-direction","detail":"optional sentence for the caller"}
```

`scope` is what the authoriser says the credential covers. The relay has already
applied its own decision by then, so it is not a second gate: it is there so a
tenant configured with `HELIOGRAPH_RELAY_HOSTED` can refuse a grant for being too
**wide**, which is a different question from whether it covers this request.

The request is routing, an operation and a length. **No body, no stream, nothing
that could be followed to content.** `bytes` is a size, not a sample.

**Only a 200 is a decision.** Anything else - a refused connection, a timeout, a
500, a 403 about the relay's own credential to the authoriser - is treated as
the authoriser being unreachable, and the relay answers **503** with
`"reason":"authoriser-unavailable"`. It does not answer 401. A 401 sends
somebody to check a token on a machine they cannot reach while the fault is on
this side, which is the worst hour this transport can cost anybody.

Decisions are cached: 30 seconds for a yes, 5 for a no. A no expires sooner
because reusing a stale yes keeps a revoked credential alive and reusing a stale
no keeps a repaired one dead, and neither number removes the trade.
Unavailability is **not** cached at all, so the relay recovers as soon as the
authoriser does.

The Worker takes the same variable and speaks the same wire, and CI runs the
same conformance suite against both, including an outage the suite causes
itself.

### The authoriser never touches a message

Not as a rule it is asked to follow, but as something the types make impossible.
The seam is three interfaces in `auth.go`, and none of them can carry bytes:

| | |
|---|---|
| `Admission` | may this proceed, and what does it reserve. Can cap one operation below the server's own limit |
| `Accounting` | what it actually cost: bytes moved, messages, outcome, duration. Settled after the fact, because a declared size is a number the payer chose |
| `Sessions` | whether the authority behind something already open has been withdrawn. A long poll is held for 25 seconds, and "authorise every call" says nothing about a call still in progress |

`TestAnAuthoriserCannotObtainAMessageBody` walks every parameter and every
return value on that surface by reflection and fails on anything that could
carry, reference or yield bytes. It is an allowlist rather than a denylist,
because the thing nobody thought of is how this sort of claim usually breaks.

The conformance suite checks the same thing against a **running** relay: it puts
a recognisable pattern of bytes through, then reads back every byte the
authoriser was sent and fails if the pattern is in there. Both implementations
run it.

This is what lets the claim sharpen rather than weaken when an operator's
authoriser is proprietary: **the thing that touches your ciphertext is readable,
and the thing that is not readable never touches it.**

## Authorisation leases

**Two different things in this repository share the word "lease" and nothing
else.** A *collection* lease is a collector holding messages between reading
them and confirming it has them, so a collector that dies loses nothing
(`lease.go`, `?lease=` and `/ack`). An **authorisation** lease, which this
section is about, is who may collect at all (`authlease.go`). Neither implies
the other: a station can hold an authorisation lease and never ask for a
collection lease, and the reverse.

An authoriser in front of every operation, failing closed, turns **our** outage
into the customer's transport outage. Cached decisions expire, a newly started
relay has no cache at all, and the fleet loses access. On a transport whose
proposition is reaching machines when things are broken, that is the worst
failure available, and it arrives exactly when somebody needed it.

A **lease** is a bounded, scoped grant presented as the bearer credential:

```
hl1.<base64url(payload)>.<base64url(signature)>

payload = {"e":"e-9f3c1a","s":["pump-01"],"r":["c2s"],"w":["s2c"],
           "nbf":1789255130,"exp":1789255730,"ep":7,"aud":"relay.example"}
```

The relay reads it, checks scope, window, lifetime, revocation epoch and
audience, and **makes no network call to do any of it**. So:

- an existing grant runs for its stated lifetime whatever happens to the authoriser
- **enrolment** (a station with no lease) and any **privilege increase** (a lease used outside itself) need the authoriser, and during an outage answer **503** `authoriser-unavailable`, never 401
- a poll already held ends when its lease expires or its epoch is raised, rather than running on to its own timeout

### The maximum revocation delay is 15 minutes, and that is the trade

Revocation raises an estate's **epoch**. A relay that hears it refuses every
older lease at once. A relay that never hears it keeps honouring a lease until
that lease expires, and `MaxAuthorityLife` bounds that at **15 minutes**.

**There is no lifetime that removes this.** Shorter means faster revocation and
a harder availability dependency; longer means the reverse. The decision is
which number to publish, and `TestTheMaximumRevocationDelayIsTheNumberWePublish`
revokes and measures it rather than asserting it:

```
access stopped 15m0s after revocation; the published maximum is 15m0s
```

### What revocation does not do

A message already handed to a station is not recalled, because it is no longer
here. Revocation stops the next collection and ends an open poll. A command the
station has already taken is the station's replay and request-id handling, not
this server's. `TestRevocationDoesNotRecallAMessageAlreadyDelivered` says so.

### Verified, never signed

A lease is signed with **Ed25519** and both implementations verify it. **Neither
can produce one**, and that is enforced rather than promised.

```bash
HELIOGRAPH_RELAY_LEASE_KEY=<32-byte Ed25519 public key, hex or base64>
```

The relay holds the **public** half and nothing else. Unset means every lease is
refused, which is the only safe default: a relay that accepted an unverified
lease would accept a forged one, and the forger chooses the scope. A 64-byte
value is refused by name rather than truncated to its public half, because that
is an Ed25519 private key and accepting it would leave signing material in the
configuration of a component whose whole claim is that it holds none.

**How "cannot sign" is established.** Not by reading the source, and not by a
grep: both can be satisfied by code that imports a package and calls it
somewhere else.

| | |
|---|---|
| **Go binary** | CI builds `cmd/heliograph-relay` and reads its **symbol table**. Go links only reachable code, so a binary with no route to constructing an `ed25519` private key has no code path that could sign anything. `TestTheRelayBinaryCannotSignALease` |
| **Worker** | a bundle has no symbol table, so CI allowlists the two calls that verify - `crypto.subtle.importKey` and `crypto.subtle.verify` - and fails on `sign`, `generateKey`, `deriveKey`, `exportKey` and the rest. The key is imported with `extractable: false` and `["verify"]` as its only usage, so the runtime itself refuses to sign with it or hand it back |

The check is known to discriminate rather than merely pass:
`TestTheSigningCheckCanTellASignerFromAVerifier` builds the conformance harness,
which **does** sign, and fails if the check cannot see the difference.

**HMAC was rejected**, though it would have needed no new primitive at all. It
is symmetric, so a relay able to verify is a relay able to **mint** any lease it
likes. That ends the claim rather than narrowing a sentence about it.

### Why this rather than a fork

The relay a hosted operator deploys is built from this source with nothing
added, so a customer can compare a hash instead of trusting an operator. That is
only true while everything a hosted service needs fits behind this seam, which
is why the seam is here and published rather than kept private. See
[CONTRIBUTING.md](CONTRIBUTING.md).

### Every refusal says why

Beside the sentence, in a field a program can read.

| `reason` | status | |
|---|---|---|
| `no-credential` | 401 | no bearer token |
| `bad-credential` | 401 | the token is not one this relay knows |
| `wrong-direction` | 401 | a good token used for the other side's half |
| `authoriser-unavailable` | 503 | **our** fault, not yours |
| `bad-route` | 400 | not an estate, a station and `c2s` or `s2c` |
| `unreadable-request` | 400 | the envelope would not parse |
| `too-large` | 413 | over `MaxBodyBytes` |
| `queue-full` | 429 | the recipient has stopped collecting |
| `out-of-scope` | 401 | a credential this relay knows, used somewhere it does not reach |
| `authority-expired` | 401 | an authorisation lease outside the window it was minted for |
| `authority-unverifiable` | 401 | an authorisation lease whose signature does not check against the configured key |
| `estate-wide-credential` | 401 | a credential too wide for a tenant that may hold several customers |

The sentence is for a person and the reason is for a program, because a client
that has to match on English prose breaks when the prose improves.

## Where to run it

Two implementations, one contract. `conformance/` holds it, asserted over HTTP,
and CI runs it against **both**. An implementation that has not passed it does
not get deployed.

| | |
|---|---|
| **Cloudflare Worker + Durable Object** (`edge/`) | cheapest, global, and the one to reach for |
| **Go binary or container** (this repository) | anywhere else: a VM, Fly, Cloud Run, or inside a customer's own estate |

### Why a Worker rather than the Go binary in a Container

Cloudflare Containers would run the Go binary unmodified, and it was rejected on
cost rather than capability. Every long poll holds a request open, which is
exactly the "idle in memory but unable to hibernate" case that bills Durable
Object wall-clock time **anyway** - so you would pay the DO cost *and* the
container cost, plus egress, for the same behaviour.

A Durable Object is also simply the right shape: single-threaded and consistent,
which is what a queue wants, with one object per estate, station and direction so
that one busy estate cannot make another wait.

### Why a second implementation is acceptable here

Because this server is trivial. It is a queue with a TTL and a token check, and
it holds no keys, so the whole of it can still be audited in an afternoon in
either language. The end-to-end guarantee is untouched: it cannot read a message
in TypeScript any more than it can in Go.

The real cost is drift, and that is answered the same way heliograph answers it
everywhere else - one specification, several implementations, and none of them
trusted until it has passed.

The hosted relay deploys **on a tag**, through
[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml):

```bash
git tag v0.3.0 && git push --tags
```

The workflow runs the contract first, deploys, then **polls the live relay until
`/version` reports the commit it just built**. A green deploy step with the old
code still answering is exactly the drift this is meant to catch, so deploying
and having deployed are checked separately.

Pushing to `main` deploys nothing. The relay other people's stations are talking
to should change on a deliberate act.

Secrets required: `CLOUDFLARE_API_TOKEN` scoped to Workers deploy on this account,
and `CLOUDFLARE_ACCOUNT_ID`. `HELIOGRAPH_RELAY_ESTATES` stays a wrangler secret,
set once and never in CI.

### Deploying by hand, if you must

```bash
cd edge
npx wrangler secret put HELIOGRAPH_RELAY_ESTATES   # estate:controlToken:stationToken
npx wrangler deploy \
  --var VERSION:"$(git rev-parse HEAD)" \
  --var BUNDLE_SHA256:"$(cd .. && edge/reproduce.sh | sed -n 's/^sha256:[[:space:]]*//p')"
```

**Do not drop either `--var`.** Without them the deployment answers
`{"version":"unknown"}` and `{"hash":"unknown"}`, and nobody - including whoever
deployed it - can tell which commit is running or check the bundle against a
build of their own. A relay whose proposition is that you can read it before you
run it ought to be able to say which "it" you are reading.

This is also why the workflow exists: a human can pass the wrong commit to
`--var` and the endpoint will repeat it confidently. CI stamps the commit it
actually built.

## Identity

Two endpoints, neither of which needs a token, because "the relay you are talking
to is the relay you read" is not checkable if you need a credential to ask which
relay it is.

```bash
curl https://relay.heliograph.io/version
{"service":"heliograph-relay","implementation":"worker","version":"<commit>",...}
```

`GET /version` gives the service, which implementation is answering, the commit
it was built from, and where the source is.

**Two hostnames answer, and neither redirects to the other.**
`relay.heliograph.io` is the endpoint this documentation names.
`heliograph-relay.dbhq.uk` is the older name and is kept **permanently** rather
than deprecated: a station's `RELAY_URL` lives on a machine nobody can reach to
change, which is the premise of this whole product, so a station already
pointing at it keeps working for as long as the relay does.

**There is deliberately no redirect between them.** The bash station's `curl`
has no `-L`, and Go's HTTP client strips the `Authorization` header across a
host change, so a 301 added as a tidy-up would present as an authentication
failure on somebody else's machine. `GET /` gives the same plus a
sentence on what this server is and a link to the documentation, because
somebody who found the hostname in a config file and pasted it into a browser
deserves better than a bare 404.

**`version` is never an empty string.** An unstamped build reports `unknown`,
which is a true answer somebody can act on, where a blank field reads as a fault
in whatever asked.

**A version string is still only a claim the deployment makes about itself.** It
is not provenance: whoever deploys can pass any commit they like to `--var`, and
before the deploy workflow existed somebody did. The hash below is the half that
is checkable, and `## Provenance` sets out exactly how far it goes and where it
stops.

## Provenance

**`GET /health` reports the version serving and the SHA-256 of the artefact
serving it.**

```bash
curl https://relay.heliograph.io/health
{"ok":true,"version":"<commit>","hash":"<sha256 of the worker bundle>"}
```

That second number is one you can arrive at yourself, without asking us:

```bash
git clone --branch <the tag> https://github.com/heliograph-io/heliograph-relay
cd heliograph-relay && edge/reproduce.sh
```

Same hash, and the bundle answering your requests is the source you just read.
A different hash means the deployment is not that tag, which is worth knowing
loudly. The Go binary answers the same way and needs no help doing it: it hashes
its own executable at startup, so `hash` there is what is actually running.

**Both builds are reproducible, and CI proves it on every pull request** rather
than asserting it - each is built twice, from two directories, the second from a
copy with no `.git`, and a difference fails the build. Measured 2026-09-13, the
Worker bundle at 25,968 bytes:
`55cb53fa36888666e93b1128af2cefabdb55113b09c0a76c8bbc81284e907871` twice.
`npm ci` rather than `npm install` is load-bearing: the lockfile is what pins the
bundler, and a different bundler emits different bytes.

**Where this stops, stated rather than glossed.** A Worker cannot read its own
code, so `hash` is the number the deploy workflow computed from the source it
then deployed - a public log of a public workflow, which is weaker than a binary
that hashes itself. Nothing here is signed yet. So the honest sentence today is
"the bundle this tag produces is a number you can check, and the deployment says
it is serving that number", not "the relay is provably the source you read".

The whole account, including the CLI's side of it, is at
[docs.heliograph.io/provenance](https://docs.heliograph.io/provenance).

## Storage

**Held only until collected, or seven days, whichever comes first.** Then
deleted. Nothing is kept after either.

**Both implementations can keep an accepted message across a restart. For the Go
binary it is a deployment choice, and the difference is stated rather than
averaged over:**

| | how | what a restart does |
|---|---|---|
| **Worker + Durable Object** (`edge/`) | Durable Object storage, which is persistent | nothing. A message you were told was accepted is still there |
| **Go binary** with `HELIOGRAPH_RELAY_SPOOL` | one file per message in that directory, written and flushed before the 202 | nothing, as long as the directory outlives the process |
| **Go binary** without it | in memory | drops undelivered messages, which costs a re-run |

The Worker is the one deployed at `relay.heliograph.io`, so the hosted relay
**does write to disk** inside that window.

This documentation previously said "in memory ... never written to disk" of both,
which was true of the Go binary and false of the Worker. That is corrected here
rather than quietly edited, because the sentence was offered as a reason to trust
the design and somebody may have relied on it.

### Why persisting in that window is the better answer anyway

The original argument was that a relay which persisted would be a relay with a
backup, and a backup of ciphertext is a liability that has to be explained to
every customer who asks what happens to their data. That argument is right about
**long** retention and it was wrong to express as "never to disk".

A Durable Object can lose in-memory state on a lifecycle transition. So an
in-memory queue means a sender can receive a 200, delete its own copy believing
the message delivered, and lose it - and on this transport the sender is often a
station nobody can log into, holding the only copy of an hour-long capture. A
re-run is not always available, because the state that produced the log has moved
on.

So the honest promise is not "we never write it down". It is **"we write it down
only for as long as it takes you to collect it, and then we delete it"** - which
is a shorter window than most systems and, unlike the previous sentence, is
actually kept.

### Durable before acknowledged, which is the whole of it

The order is the guarantee. The message is written and flushed, and only then does
the sender get its 202. A message that could not be written is a message that was
**not accepted**: the relay answers `503` and says so, rather than a 202 it knows
it cannot honour. The refusal reaches the one side that still has a copy, which is
the only side that can do anything.

### Running the Go relay durably

```bash
docker run -p 8080:8080 \
  -v heliograph-spool:/var/lib/heliograph-relay \
  -e HELIOGRAPH_RELAY_SPOOL=/var/lib/heliograph-relay \
  -e HELIOGRAPH_RELAY_ESTATES="payments:$CTL:$STN" \
  ghcr.io/heliograph-io/heliograph-relay:latest
```

**The volume is the durability.** Without `-v` the spool lives in the container's
own filesystem, which a replacement discards: a spool that looks durable and is
not, which is the exact class of claim this page has already been wrong about
once. That is why the spool is opt-in rather than a default path.

At startup it says which guarantee you have, and what it recovered:

```json
{"level":"INFO","msg":"durable","spool":"/var/lib/heliograph-relay","recovered":1,"bytes":7}
{"level":"INFO","msg":"not durable","reason":"HELIOGRAPH_RELAY_SPOOL is unset, so a restart drops what has not been collected"}
```

A file in the spool that does not parse as a message is **moved aside** to
`.corrupt` and named in the log at error level. Not deleted, because those bytes
may be the only remaining copy of something; not fatal, because one unreadable
file should not be an outage for every station on the relay.

### What durability costs, measured rather than assumed

| | |
|---|---|
| Go spool, per retained message | the body, plus **77 bytes** of header, plus filesystem block granularity. At 1 KiB, 64 KiB and 1 MiB of body: 1101, 65613 and 1048653 bytes on disk |
| Go spool, per accepted message | one file created, one flush of it, one flush of the directory, inside the store's lock. A promise about power cuts that skips the flush is not one |
| Durable Object, per retained message | about **1.34x the raw body**, with a floor of about 8 KiB. 1 KiB of body costs 8192 B, 64 KiB costs 94208 B, 512 KiB costs 704512 B |
| Durable Object, per accepted message | one write of the **whole queue**. Put number n writes a value holding all n messages, so filling one queue to `DefaultMaxQueue` writes on the order of n squared bytes |

Both rows are produced by tests rather than by arithmetic:
[`TestASpooledMessageCostsTheBodyPlusASmallHeader`](spool_test.go) and
[`edge/test/storage-cost.test.ts`](edge/test/storage-cost.test.ts), which print
their figures on every run.

The Durable Object numbers are measured against the local implementation
(`wrangler dev --local`, which is miniflare's SQLite) and not against the
platform's meter. The 1.33x is ours and transfers exactly - a body is stored in
the base64 form it arrives in, and is never decoded - while the 8 KiB floor is
SQLite page granularity and may differ on the platform.

### What is still outstanding

- the Worker stores one queue as one value, so a put rewrites every message
  already queued. Correct, and more expensive than it needs to be
- the CLI and the station still collect without a lease, so the loss window is
  closed in the relay and not yet in the collector. Leasing is opt-in and the
  client side of it is work in `heliograph-io/heliograph` rather than here
- `conformance/` asserts **durability** for both implementations, because an
  accepted message outliving a restart is observable as soon as the harness can
  restart the relay (`conformance -restart`, and the scripts in
  [`scripts/`](scripts)). It cannot assert the **storage model**: it is asserted
  over HTTP, and memory and disk answer every request in it identically. So
  storage claims are asserted per implementation instead, in
  [`storage_test.go`](storage_test.go) and
  [`edge/test/storage-model.test.ts`](edge/test/storage-model.test.ts), and a
  conformance run says so in its own output

## API

```
POST /v1/{estate}/{station}/{dir}        queue a message   (dir: c2s | s2c)
GET  /v1/{estate}/{station}/{dir}        collect, long-polling by default
POST /v1/{estate}/{station}/{dir}/ack    confirm a leased collection
GET  /health                             liveness, the version and hash serving,
                                         and whether this deployment is durable
GET  /version                            which commit is answering, no token
GET  /                                   the same, plus what this server is
```

`/health`, `/version` and `/` need no token.

`GET` on a queue holds the connection for up to 25 seconds waiting for a
message. Add `?wait=0` to return immediately.

| parameter on `GET` | |
|---|---|
| `wait=0` | answer immediately rather than holding the line |
| `limit=N` | at most N messages |
| `lease=30s` | hold the messages instead of deleting them, and answer with a lease to acknowledge. Absent or `0` means the old behaviour, unchanged |

## Collecting under a lease

Collection without a lease deletes as it returns, which leaves a window: between
the relay deleting and the collector durably storing, the message exists nowhere.
On this transport what is in that window is frequently the only copy of a capture
from a machine nobody can log into.

```
   collector                        relay
      │   GET ?lease=30s              │
      │ ────────────────────────────► │  marked, NOT deleted
      │ ◄──────────────────────────── │  {"lease":"L7","until":"...","messages":[...]}
      │                               │
      │   write it down locally       │
      │                               │
      │   POST .../ack {"lease":"L7"} │
      │ ────────────────────────────► │  now deleted
      │                               │
      │   (crashed instead?)          │  the lease expires and the messages return
```

```bash
# collect, holding a lease for thirty seconds
r=$(curl -s "$RELAY/v1/$ESTATE/$STATION/c2s?wait=0&lease=30s" -H "Authorization: Bearer $TOK")
echo "$r" | jq -c '.messages[]' | while read -r m; do ...; done   # write it down first

# then, and only then
curl -s -X POST "$RELAY/v1/$ESTATE/$STATION/c2s/ack" \
  -H "Authorization: Bearer $TOK" \
  -d "{\"lease\":$(echo "$r" | jq '.lease')}"
```

| | |
|---|---|
| the lease duration | `30s`, `500ms`, `2m`, or a bare number of seconds like `30`. At most **5 minutes**, and a longer one is refused rather than clamped, because a collector that thinks it has an hour behaves differently from one that knows it has five minutes |
| while a lease is live | those messages go to nobody else, whether or not the other collector asks for a lease |
| when it expires unacknowledged | the messages return, **in their original position**, and are collectable again |
| acknowledging twice | the second is `410 Gone`. So is acknowledging a lease that expired, and the collector's safe response to both is the same: expect the messages again |
| acknowledging | takes the same credential as collecting. A station may confirm the requests it collects and still may not queue one |

**Every message now carries an `id`**, leased or not, and it does not change when a
message is redelivered. That is what a collector deduplicates on, and the relay
guarantees three things about it: it is stable for the life of the message, it
survives a relay restart, and it is never reused - not even after a queue empties.
An id is unique within its route and is not comparable between routes.

**What the relay cannot do for you, stated plainly.** A lease that expires before
the collector acknowledges means the messages are delivered twice, and no broker
can prevent that: the collector is the only party that knows whether it finished
writing. So a collector must be idempotent on the message id, and a request
redelivered to a station must not cause a second run. The station keys runs by
request id and triggers only on a change to that id, which makes this hold - and it
now holds load-bearingly rather than incidentally, so it belongs in a test on the
station side rather than in a sentence here.

**The long poll is available; the bash station does not use it.** It fetches
`?wait=0` on an interval that defaults to five seconds. This README used to say
"an idle station costs one held connection rather than a request every few
seconds", which is the opposite of what the shipped station does, and the
sentence was being quoted as the basis for cost reasoning. Corrected here rather
than edited away, because a wrong reason is worse than no reason once somebody
has built on it.

What an idle station actually costs has not been measured, and the two shapes
are not close enough to guess between: a held connection bills wall-clock
duration on a Durable Object, where a short poll bills a request. Neither number
belongs in this file until somebody has run it.

Long-poll rather than WebSocket, deliberately. A station runs behind a corporate
proxy that may strip an upgrade header, and a transport that fails on those
estates fails on exactly the estates this exists for.

## Licence

[FSL-1.1-ALv2](LICENSE) (c) 2026 DBHQ Consulting Ltd. **Fair source, not open
source**: read it, build it, modify it, run it, and each release converts to
Apache 2.0 two years after it ships. What it does not permit is competing use -
selling relay hosting, which is a tier we sell.

Deploying the relay to reach estates you or your clients operate, as part of
professional services you provide, is expressly permitted. [`NOTICE`](NOTICE)
carries that grant in full, along with why FSL rather than AGPL and the honest
limit of a two-year clock on a component this stable.

Relicensed from MIT on 2026-09-17. Every commit up to and including `f664ea0`,
including the `v0.1.0` and `v0.1.1` tags, stays available under MIT for ever.

The CLI, station payloads, wire format and site are
[heliograph](https://github.com/heliograph-io/heliograph), Apache 2.0. No shape
is ever gated: beacon, flare and beam all work on a relay you host yourself.

Full statement, including why fair source rather than AGPL and the honest limit
of a two-year clock on a component this stable:
**<https://docs.heliograph.io/licence>**
