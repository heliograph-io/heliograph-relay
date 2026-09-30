/**
 * The heliograph relay, on Cloudflare's edge.
 *
 * A second implementation of the same contract as the Go server in this
 * repository. It exists because the shapes genuinely differ: a Durable Object
 * is how you hold a queue at the edge, and a Go binary is how you run one
 * anywhere else. Neither is a port of the other.
 *
 * The cost of a second implementation is drift, and drift is only dangerous
 * when it is untested. `conformance/` holds the contract, asserted over HTTP,
 * and CI runs it against BOTH. An implementation that has not passed it is not
 * permitted to be deployed.
 *
 * THERE IS NO CRYPTOGRAPHY HERE EITHER, and for the same reason. Every message
 * arrives already sealed and signed by the client. This code sees a base64
 * string, a routing key and a length. There is no key to leak and no plaintext
 * to subpoena, in this language or the other one.
 */

export interface Env {
  QUEUE: DurableObjectNamespace;
  /** estate:controlToken:stationToken, comma separated. A secret, not a var. */
  HELIOGRAPH_RELAY_ESTATES: string;
  /**
   * When set, decisions are fetched from here rather than read out of
   * HELIOGRAPH_RELAY_ESTATES. This is the seam the hosted service lives behind:
   * tenants, estates, quota and billing belong to whatever answers this URL,
   * and none of it is added to the code in the data path.
   *
   * The Go server's RemoteAuth speaks the same wire shape, and the conformance
   * suite runs the same assertions against both. heliograph-io/heliograph-cloud#7.
   */
  HELIOGRAPH_RELAY_AUTHORISER?: string;
  /**
   * estate:station:role:credential, comma separated. role is "control" or
   * "station".
   *
   * Per-station scope, one level narrower than HELIOGRAPH_RELAY_ESTATES, for an
   * operator whose one relay carries more than one customer. A credential
   * covering several stations is listed once per station.
   * heliograph-io/heliograph-cloud#71.
   */
  HELIOGRAPH_RELAY_STATIONS?: string;
  /**
   * Refuse any credential not scoped to named stations, including one that
   * merely declines to say.
   *
   * An estate identifier is a name and never a secret: it travels in a URL and
   * appears in logs. So a tenant whose estates may each hold more than one
   * customer cannot treat "knows the identifier" as "may read the queue".
   */
  HELIOGRAPH_RELAY_HOSTED?: string;
  /**
   * The Ed25519 PUBLIC key authorisation leases are signed with, hex or base64.
   *
   * Unset means every lease is refused. This relay never needs the private half
   * and refuses one if given it: a 64-byte key is an Ed25519 private key whose
   * last 32 bytes are the public half, and accepting it would leave signing
   * material in the configuration of a component whose whole claim is that it
   * holds no key worth stealing. heliograph-io/heliograph-cloud#75.
   */
  HELIOGRAPH_RELAY_LEASE_KEY?: string;
  /**
   * The commit this was deployed from. A var rather than a secret, because the
   * entire point is that anybody can read it and compare it against `main`.
   * Set at deploy: `wrangler deploy --var VERSION:$(git rev-parse HEAD)`.
   */
  VERSION?: string;
  /**
   * SHA-256 of the bundle that was uploaded, computed by the deploy workflow
   * from `wrangler deploy --dry-run` over the same source it then deploys.
   *
   * A version is a NAME a deployment gives itself. This is a NUMBER anybody
   * can arrive at independently: `edge/reproduce.sh` rebuilds the bundle from
   * the tag and prints the same hash, so "the relay in the path is the relay
   * you read" stops being a sentence and becomes a comparison. A Worker cannot
   * read its own bundle, so this arrives the same way VERSION does.
   * See https://heliograph.dbhq.uk/provenance.
   */
  BUNDLE_SHA256?: string;
}

const WHAT_IT_IS =
  "Stores and forwards opaque ciphertext between a control and a station. " +
  "It holds no keys, does no crypto, and never sees plaintext.";
const SOURCE_URL = "https://github.com/heliograph-io/heliograph-relay";
const DOCS_URL = "https://heliograph.dbhq.uk/relay";

// A browser asking for / must get a page, not a download prompt. Returning
// application/json makes mobile Safari offer the response as a file, which is
// what somebody who pasted this hostname into a phone actually saw. Machines
// still get JSON, because the endpoint is also how a check reads the version.
function wantsHTML(req: Request): boolean {
  const accept = req.headers.get("accept") ?? "";
  return accept.includes("text/html");
}

function landingHTML(version: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>heliograph relay</title>
<style>
 body{background:#111;color:#eee;font:15px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;padding:2.5rem 1.25rem;max-width:34rem}
 h1{font-size:1rem;margin:0;font-weight:600}
 p{color:#8b8b8b;margin:.25rem 0 1.75rem}
 a{color:#6cf;display:block}
 code{color:#8b8b8b;word-break:break-all}
</style></head><body>
<h1>heliograph relay</h1>
<p>Stores and forwards ciphertext it cannot read.</p>
<code>${version}</code>
<a href="${SOURCE_URL}">source</a>
<a href="${DOCS_URL}">docs</a>
</body></html>`;
}

function html(body: string): Response {
  return new Response(body, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

// Never an empty string. A deploy with no version stamped says "unknown",
// which is a true answer an operator can act on, where a blank field reads as
// a bug in whatever asked.
function reportedVersion(env: Env): string {
  return env.VERSION && env.VERSION !== "" ? env.VERSION : "unknown";
}

// Same rule, same reason: never blank.
function reportedHash(env: Env): string {
  return env.BUNDLE_SHA256 && env.BUNDLE_SHA256 !== ""
    ? env.BUNDLE_SHA256
    : "unknown";
}

const MAX_BODY_BYTES = 8 << 20; // 8 MiB, as the Go server
const MAX_QUEUE = 256;
const TTL_MS = 7 * 24 * 60 * 60 * 1000;
const HOLD_MS = 25_000;

/** The longest lease the relay will grant. The Go server's MaxLease. */
const MAX_LEASE_MS = 5 * 60 * 1000;

interface Msg {
  /**
   * Stable for the life of the message, including across a redelivery. It is what
   * a collector deduplicates on: an expired lease followed by a successful one
   * delivers the same message twice, and the collector has to be able to tell.
   * Unique within this route, opaque, and not comparable between routes.
   */
  id: string;
  seq: number;
  body: string; // base64, exactly as it arrives and leaves
  at: number;
  /** The collector holding this message, if any, and until when. */
  lease?: string;
  until?: number;
}

/**
 * The stored value for one route: the messages, and the counters that name them.
 *
 * ONE KEY RATHER THAN THREE, so that a put is one write and the queue and its
 * counters cannot disagree after a partial write.
 *
 * THE COUNTERS OUTLIVE THE MESSAGES, which is why this record is not deleted when
 * the last message is collected. An id must never be reused: a collector
 * deduplicates on it, so a new message wearing a retired id would be dropped as a
 * duplicate of something it has nothing to do with. What stays behind is about
 * thirty bytes of counters, and no ciphertext.
 *
 * v is the shape. The shape before leasing was a bare Msg[] with no ids, and the
 * hosted relay may be holding messages in it when this deploys, so load() upgrades
 * rather than discarding.
 */
interface Queue {
  v: number;
  n: number; // next message number
  l: number; // next lease number
  msgs: Msg[];
}

const QUEUE_SHAPE = 2;

/**
 * Reads the ?lease= parameter. Empty and "0" mean no lease.
 *
 * THE SAME SMALL GRAMMAR THE GO SERVER PARSES, and it is small so that both can
 * implement all of it:
 *
 *     lease  = "" | "0" | number unit?
 *     number = digits [ "." digits ]
 *     unit   = "ms" | "s" | "m" | "h"      default "s"
 *
 * Go's own time.ParseDuration would accept compound durations like "1m30s", and
 * using it there while hand-parsing here is how ?lease=1m30s ends up working
 * against one implementation and 400ing against the other.
 *
 * Returns the lease in milliseconds, 0 for no lease, or null for a request that
 * cannot be honoured, which is a 400 rather than a silent fall back to
 * destructive collection: a collector that asked for a lease and did not get one
 * would delete its only copy on the strength of a 200.
 */
function parseLease(raw: string | null): number | 0 | null {
  const v = (raw ?? "").trim();
  if (v === "" || v === "0") return 0;
  const units: [string, number][] = [
    ["ms", 1],
    ["s", 1000],
    ["m", 60_000],
    ["h", 3_600_000],
  ];
  let unit = 1000;
  let digits = v;
  for (const [suffix, ms] of units) {
    if (v.endsWith(suffix)) {
      unit = ms;
      digits = v.slice(0, -suffix.length);
      break;
    }
  }
  if (digits === "" || !/^[0-9]+(\.[0-9]+)?$/.test(digits)) return null;
  const ms = Math.floor(Number(digits) * unit);
  if (!Number.isFinite(ms) || ms <= 0 || ms > MAX_LEASE_MS) return null;
  return ms;
}

/** Constant-time comparison, so a token is not discoverable by timing. */
function sameToken(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

interface Tokens {
  control: string;
  station: string;
}

function parseEstates(spec: string): Map<string, Tokens> {
  const out = new Map<string, Tokens>();
  for (const entry of (spec ?? "").split(",")) {
    const parts = entry.trim().split(":");
    if (parts.length !== 3) continue;
    const [estate, control, station] = parts;
    if (!estate || !control || !station) continue;
    // One token for both sides collapses the only scope separation there is,
    // and a station credential could then queue requests. Refused here as the
    // Go server refuses it at startup.
    if (control === station) continue;
    out.set(estate, { control, station });
  }
  return out;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Why a request was refused.
 *
 * The same set of strings the Go server uses, because a client that has to
 * learn two vocabularies to talk to two relays is a client that learns one and
 * breaks on the other.
 *
 * The distinction that carries weight is the last group against the first. A
 * 401 sends somebody to check a token on a machine they cannot reach; if the
 * real fault is that the authoriser is down, that is hours on the wrong side of
 * the gap, on a transport whose entire proposition is reaching machines when
 * things are broken.
 */
type Reason =
  | "no-credential"
  | "bad-credential"
  | "wrong-direction"
  | "authoriser-unavailable"
  | "bad-route"
  | "unreadable-request"
  | "too-large"
  | "queue-full"
  | "out-of-scope"
  | "estate-wide-credential"
  | "authority-expired"
  | "authority-unverifiable"
  // The collection lease, which is a duration in a query string and has nothing
  // to do with the authorisation lease above. The word is overloaded; the two
  // are unrelated. heliograph-io/heliograph-cloud#9.
  | "bad-lease"
  | "no-such-lease"
  | "internal";

const STATUS: Record<Reason, number> = {
  "no-credential": 401,
  "bad-credential": 401,
  "wrong-direction": 401,
  "authoriser-unavailable": 503,
  "bad-route": 400,
  "unreadable-request": 400,
  "too-large": 413,
  "queue-full": 429,
  "out-of-scope": 401,
  "estate-wide-credential": 401,
  "authority-expired": 401,
  "authority-unverifiable": 401,
  "bad-lease": 400,
  "no-such-lease": 410,
  internal: 500,
};

const DETAIL: Record<Reason, string> = {
  "no-credential": "not authorised for this estate",
  "bad-credential": "not authorised for this estate",
  "wrong-direction": "not authorised to write that direction for this estate",
  "authoriser-unavailable":
    "the authoriser could not be reached, so this request was neither allowed nor refused",
  "bad-route": "a message must name an estate, a station and a direction of c2s or s2c",
  "unreadable-request": "could not read the message",
  "too-large": "message is larger than the relay will carry",
  "queue-full": "this queue is full: the recipient is not collecting",
  "out-of-scope": "this credential is not scoped to that station and direction",
  "estate-wide-credential": "this tenant refuses estate-wide credentials",
  "authority-expired": "this authorisation lease is outside the window it was minted for",
  "authority-unverifiable": "this authorisation lease could not be verified",
  "bad-lease": "a lease must be a duration, like 30s",
  "no-such-lease":
    "the relay is not holding that lease, so the messages may already have been returned to the queue",
  internal: "could not accept the message",
};

/**
 * Every refusal carries a sentence for a person and a reason for a program.
 *
 * Two fields rather than one, because a caller that has to match on English
 * prose is a caller that breaks when the prose improves.
 */
function fail(reason: Reason, detail?: string): Response {
  return json({ error: detail ?? DETAIL[reason], reason }, STATUS[reason]);
}

function bearer(req: Request): string {
  const h = req.headers.get("authorization") ?? "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

/**
 * What an authoriser is told about an attempt.
 *
 * Note what is absent, and permanently absent: the message body, any stream
 * that could yield one, and the Request it arrived on. Routing, an operation
 * and a length, and there is no field here anybody could follow to content.
 * `bytes` is a size, not a sample.
 */
interface DecisionRequest {
  credential: string;
  estate: string;
  station: string;
  dir: string;
  op: "read" | "write";
  bytes: number;
}

interface Grant {
  allow: boolean;
  /** Absent when allowed. A refusal always names one. */
  reason?: Reason;
  /**
   * What this credential covers, as the authoriser understands it. Carried so
   * a hosted tenant can refuse a grant for being too WIDE, which is a different
   * question from whether it covers this request.
   */
  scope?: Scope;
}

/**
 * What a credential may do, and nothing is permitted by omission.
 *
 * Every field is a positive grant. An empty scope allows nothing at all, which
 * is the only safe zero value: a scope that matched by leaving a field blank is
 * how an estate-wide credential gets into a hosted tenant by accident, and the
 * accident is silent until somebody reads somebody else's logs.
 */
interface Scope {
  estate: string;
  stations: string[];
  /** Estate-wide. It exists so such a scope can SAY so and be refused for it. */
  allStations: boolean;
  read: string[];
  write: string[];
}

function scopePermits(s: Scope, d: DecisionRequest): boolean {
  if (!d.estate || !d.station || (d.dir !== "c2s" && d.dir !== "s2c")) return false;
  if (!s.estate || s.estate !== d.estate) return false;
  if (!s.allStations && !s.stations.includes(d.station)) return false;
  return (d.op === "read" ? s.read : s.write).includes(d.dir);
}

/** A scope narrowed to named stations, which is what a hosted tenant requires. */
function stationScoped(s: Scope | undefined): boolean {
  return !!s && !s.allStations && s.stations.length > 0;
}

/**
 * Per-station scopes, parsed from one configuration string.
 *
 * Every fault is refused rather than skipped, and the refusal names the entry.
 * parseEstates skips a malformed estate, which fails closed and is far harder
 * to diagnose: the relay starts, answers 401 to everything for that estate, and
 * sends the reader to the far side of a gap they cannot cross.
 */
function parseStationScopes(spec: string): Map<string, Scope> {
  const out = new Map<string, Scope>();
  const roles = new Map<string, string>();
  let n = 0;
  for (const raw of (spec ?? "").split(",")) {
    const entry = raw.trim();
    if (entry === "") continue;
    const parts = entry.split(":");
    if (parts.length !== 4) {
      throw new Error(`${entry} is not estate:station:role:credential`);
    }
    const [estate, station, role, credential] = parts;
    if (!estate || !station || !credential) {
      throw new Error(
        `${entry} leaves estate, station or credential empty, and nothing is permitted by omission`,
      );
    }
    if (role !== "control" && role !== "station") {
      throw new Error(`${entry}: role must be "control" or "station", not ${role}`);
    }
    const had = roles.get(credential);
    if (had && had !== role) {
      throw new Error(
        `${entry}: this credential is already the ${had} side, and one credential for both sides removes the scope separation entirely`,
      );
    }
    roles.set(credential, role);

    const read = role === "station" ? ["c2s"] : ["s2c"];
    const write = role === "station" ? ["s2c"] : ["c2s"];
    const s = out.get(credential) ?? {
      estate,
      stations: [],
      allStations: false,
      read,
      write,
    };
    s.estate = estate;
    s.read = read;
    s.write = write;
    if (!s.stations.includes(station)) s.stations.push(station);
    out.set(credential, s);
    n++;
  }
  if (n === 0) {
    throw new Error("no scopes configured, so no client could ever authenticate");
  }
  return out;
}

/** Decisions held between requests, so an idle poll is not an authz call. */
interface CachedGrant {
  grant: Grant;
  until: number;
}

const POSITIVE_MS = 30_000;
const NEGATIVE_MS = 5_000;
/**
 * A cap, because this Map outlives a request and an isolate that never forgets
 * a decision is an isolate that eventually forgets everything at once. Clearing
 * wholesale rather than evicting cleverly: the cost of a cold cache is one
 * round trip, and the cost of an eviction policy is code in the data path.
 */
const MAX_CACHED = 4096;
const decisions = new Map<string, CachedGrant>();

function decisionKey(d: DecisionRequest): string {
  return [d.credential, d.estate, d.station, d.dir, d.op].join("|");
}

/** The static answer, read out of HELIOGRAPH_RELAY_ESTATES. */
function admitStatic(env: Env, d: DecisionRequest): Grant {
  if (!d.credential) return { allow: false, reason: "no-credential" };
  const tokens = parseEstates(env.HELIOGRAPH_RELAY_ESTATES).get(d.estate);
  // An estate with no configured tokens must refuse, rather than treating an
  // absent entry as a match. That would authorise everybody.
  if (!tokens) return { allow: false, reason: "bad-credential" };

  const isControl = sameToken(d.credential, tokens.control);
  const isStation = sameToken(d.credential, tokens.station);
  if (!isControl && !isStation) return { allow: false, reason: "bad-credential" };
  // Reading is symmetric; writing is not. A station credential sits on a
  // machine nobody can reach and cannot be rotated quickly, so it must not be
  // able to queue a request, even for its own station.
  // A static estate has no notion of a station, so anything it allows is
  // allowed estate-wide. Saying that in the grant rather than leaving it blank
  // is what lets a hosted tenant refuse it for the right reason.
  const wide: Scope = {
    estate: d.estate,
    stations: [],
    allStations: true,
    read: ["c2s", "s2c"],
    write: [d.dir],
  };
  if (d.op === "read") return { allow: true, scope: wide };
  const mayWrite = d.dir === "c2s" ? isControl : isStation;
  // A good credential used in the wrong direction is not a bad credential, and
  // reporting it as one is what gets a station rotated on a machine nobody can
  // reach, for nothing.
  return mayWrite ? { allow: true, scope: wide } : { allow: false, reason: "wrong-direction" };
}

/**
 * The fetched answer.
 *
 * Only 200 is a decision. A 401 or a 403 from the authoriser is about the
 * relay's own credential to it, and a 500 is about the authoriser, and neither
 * is a statement about the caller. Treating them as refusals is exactly how a
 * deployment fault gets reported as a token fault.
 *
 * Unavailability is never cached. Caching it would extend our outage past its
 * own end, which is the opposite of what the cache is for.
 */
async function admitRemote(url: string, d: DecisionRequest): Promise<Grant> {
  const key = decisionKey(d);
  const held = decisions.get(key);
  if (held && held.until > Date.now()) return held.grant;

  let grant: Grant;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(d),
      // Short, because this sits in front of every request including a long
      // poll. A slow authoriser must become an outage quickly rather than
      // holding the caller's connection open alongside our own.
      signal: AbortSignal.timeout(3_000),
    });
    if (resp.status !== 200) return { allow: false, reason: "authoriser-unavailable" };
    const out = (await resp.json()) as {
      allow?: boolean;
      reason?: string;
      scope?: Partial<Scope>;
    };
    grant = {
      allow: out.allow === true,
      // A refusal with no reason still refuses, and names itself, because a
      // blank reason would leave the caller guessing which side is broken.
      reason: (out.reason as Reason) || "bad-credential",
    };
    if (out.scope) {
      grant.scope = {
        estate: out.scope.estate ?? "",
        stations: out.scope.stations ?? [],
        allStations: out.scope.allStations === true,
        read: out.scope.read ?? [],
        write: out.scope.write ?? [],
      };
    }
  } catch {
    return { allow: false, reason: "authoriser-unavailable" };
  }

  if (decisions.size >= MAX_CACHED) decisions.clear();
  // A no expires sooner than a yes, because reusing a stale yes keeps a revoked
  // credential alive and reusing a stale no keeps a repaired one dead. Neither
  // number removes the trade.
  decisions.set(key, {
    grant,
    until: Date.now() + (grant.allow ? POSITIVE_MS : NEGATIVE_MS),
  });
  return grant;
}

/**
 * Per-station scope, read out of HELIOGRAPH_RELAY_STATIONS.
 *
 * Parsed once per isolate and kept, because the string does not change while
 * the isolate lives and parsing it per request would be work in the data path
 * for no reason.
 */
let scopes: Map<string, Scope> | null = null;
let scopesFrom = "";
let scopesError = "";

function stationScopes(spec: string): Map<string, Scope> {
  if (scopes && scopesFrom === spec) {
    if (scopesError) throw new Error(scopesError);
    return scopes;
  }
  scopesFrom = spec;
  scopesError = "";
  try {
    scopes = parseStationScopes(spec);
  } catch (e) {
    scopes = new Map();
    scopesError = e instanceof Error ? e.message : String(e);
    throw e;
  }
  return scopes;
}

function admitScoped(spec: string, d: DecisionRequest): Grant {
  if (!d.credential) return { allow: false, reason: "no-credential" };
  let known: Map<string, Scope>;
  try {
    known = stationScopes(spec);
  } catch {
    // A configuration this relay could not read is not a statement about the
    // caller's credential, so it is not reported as one.
    return { allow: false, reason: "internal" };
  }
  const s = known.get(d.credential);
  if (!s) return { allow: false, reason: "bad-credential" };
  if (scopePermits(s, d)) return { allow: true, scope: s };
  // A credential this relay knows, used somewhere it does not reach. Saying
  // "out-of-scope" rather than "bad-credential" is what stops an operator
  // rotating a credential on a machine they cannot reach for a fault that was
  // a console misconfiguration.
  return { allow: false, reason: "out-of-scope" };
}

/**
 * Refuse anything that cannot be proved scoped to named stations.
 *
 * Silence is refused as firmly as an explicit estate-wide grant. An authoriser
 * that says "allow" without saying what for has not said the credential is
 * station-scoped, and reading silence as the safe answer is how this class of
 * hole is created.
 */
function hosted(g: Grant): Grant {
  if (!g.allow || stationScoped(g.scope)) return g;
  return { allow: false, reason: "estate-wide-credential" };
}

function truthy(v: string | undefined): boolean {
  switch ((v ?? "").trim().toLowerCase()) {
    case "1":
    case "true":
    case "yes":
    case "on":
      return true;
  }
  return false;
}

/**
 * Authorisation leases, VERIFIED HERE AND NEVER SIGNED HERE.
 *
 * heliograph-io/heliograph-cloud#75 is a bounded, scoped, signed grant the relay
 * validates with no network call, so that a control-plane outage is not a
 * transport outage. This implementation is the hosted relay almost every
 * customer touches, so a lease that could not be honoured here would make the
 * whole feature theatre - which is why the rule against cryptography at the
 * edge narrowed to permit verification, rather than the feature being dropped.
 *
 * WHAT NARROWED AND WHAT DID NOT. The claim is that there is no key here worth
 * stealing. A public key is not a secret, so the claim is untouched. The
 * SENTENCE that used to stand in for it, "no cryptography at the edge", is what
 * changed, and `.github/workflows/validate.yml` now says the narrower thing it
 * always meant: importKey and verify, never sign, never generateKey.
 *
 * The key is imported with `extractable: false` and `["verify"]` as its only
 * usage, so the runtime itself refuses to sign with it or hand it back.
 */
function looksLikeAuthority(credential: string): boolean {
  const parts = credential.split(".");
  return parts.length === 3 && parts[0] === "hl1" && parts[1] !== "";
}

function fromBase64Url(s: string): Uint8Array | null {
  // atob wants standard base64 with padding; a lease carries the unpadded URL
  // alphabet because it travels in a header.
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  try {
    const raw = atob(padded);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** The only algorithm this relay touches, and only to verify with it. */
const ED25519 = { name: "Ed25519" } as const;

const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_PRIVATE_KEY_BYTES = 64;

/**
 * Read the configured public key.
 *
 * Hex, standard base64 or unpadded base64url, because an operator will have it
 * in whichever spelling produced it. A 64-byte key is refused by name: that is
 * an Ed25519 PRIVATE key whose last 32 bytes are the public half, and a
 * truncating parser would leave signing material in this relay's configuration.
 */
function parsePublicKey(spec: string): Uint8Array | null {
  const s = spec.trim();
  if (!s) return null;
  let raw: Uint8Array | null = null;
  if (s.length === ED25519_PUBLIC_KEY_BYTES * 2 && /^[0-9a-fA-F]+$/.test(s)) {
    raw = Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16)));
  } else {
    raw = fromBase64Url(s);
  }
  if (raw && raw.length === ED25519_PRIVATE_KEY_BYTES) {
    // Named rather than silently truncated. An Ed25519 private key's last 32
    // bytes ARE the public half, so a lenient parser would accept one and leave
    // signing material in the configuration of a relay whose whole claim is
    // that it holds no key worth stealing.
    console.error(
      "HELIOGRAPH_RELAY_LEASE_KEY is a 64-byte Ed25519 PRIVATE key. This relay wants the 32-byte public half, never needs a private key, and refuses one. Every lease will be refused until it is corrected.",
    );
    return null;
  }
  if (!raw || raw.length !== ED25519_PUBLIC_KEY_BYTES) return null;
  return raw;
}

/**
 * The imported key, cached per isolate.
 *
 * importKey is asynchronous and the key does not change while the isolate
 * lives, so importing it per request would be work in the data path for no
 * reason. Cached by the configured string, so a changed binding re-imports.
 */
let leaseKey: Promise<CryptoKey | null> | null = null;
let leaseKeyFrom = "";

function verificationKey(spec: string): Promise<CryptoKey | null> {
  if (leaseKey && leaseKeyFrom === spec) return leaseKey;
  leaseKeyFrom = spec;
  const raw = parsePublicKey(spec);
  if (!raw) {
    leaseKey = Promise.resolve(null);
    return leaseKey;
  }
  // extractable: false, and "verify" as the only usage. The runtime will not
  // sign with this key or give it back, whatever this code later asks for.
  const imported = crypto.subtle.importKey("raw", raw as BufferSource, ED25519, false, ["verify"]);
  leaseKey = imported.catch(() => null);
  return leaseKey;
}

/** Verify a lease's signature. Fails closed on anything unexpected. */
async function verifyAuthority(spec: string, credential: string): Promise<boolean> {
  const parts = credential.split(".");
  if (parts.length !== 3) return false;
  const key = await verificationKey(spec);
  if (!key) return false;
  const sig = fromBase64Url(parts[2]);
  if (!sig || sig.length !== 64) return false;
  try {
    const payload = new TextEncoder().encode(parts[1]) as BufferSource;
    return await crypto.subtle.verify(ED25519, key, sig as BufferSource, payload);
  } catch {
    return false;
  }
}

/**
 * The local half: scope, window, lifetime and epoch, none of which needs a
 * network call or a key.
 */
interface AuthorityPayload {
  e?: string;
  s?: string[];
  a?: boolean;
  r?: string[];
  w?: string[];
  nbf?: number;
  exp?: number;
  ep?: number;
  aud?: string;
}

/** The longest lease this relay honours, and so the maximum revocation delay. */
const MAX_AUTHORITY_LIFE_MS = 15 * 60 * 1000;

function readAuthority(credential: string): AuthorityPayload | null {
  const parts = credential.split(".");
  if (parts.length !== 3) return null;
  const raw = fromBase64Url(parts[1]);
  if (!raw) return null;
  try {
    const p = JSON.parse(new TextDecoder().decode(raw)) as AuthorityPayload;
    // A lease with no bounds is not a lease, and accepting one would make the
    // published revocation delay a fiction.
    if (!p.exp || !p.nbf) return null;
    return p;
  } catch {
    return null;
  }
}

async function admitAuthority(env: Env, d: DecisionRequest): Promise<Grant> {
  const spec = (env.HELIOGRAPH_RELAY_LEASE_KEY ?? "").trim();
  if (!spec) return { allow: false, reason: "authority-unverifiable" };
  if (!(await verifyAuthority(spec, d.credential))) {
    return { allow: false, reason: "authority-unverifiable" };
  }
  const p = readAuthority(d.credential);
  if (!p) return { allow: false, reason: "authority-unverifiable" };

  const now = Date.now();
  const nbf = p.nbf! * 1000;
  const exp = p.exp! * 1000;
  // Longer than this relay will honour would quietly extend the revocation
  // delay this product publishes as a number.
  if (exp - nbf > MAX_AUTHORITY_LIFE_MS) return { allow: false, reason: "authority-expired" };
  if (now < nbf || now >= exp) return { allow: false, reason: "authority-expired" };

  const scope: Scope = {
    estate: p.e ?? "",
    stations: p.s ?? [],
    allStations: p.a === true,
    read: p.r ?? [],
    write: p.w ?? [],
  };
  if (!scopePermits(scope, d)) return { allow: false, reason: "out-of-scope" };
  return { allow: true, scope };
}

async function admit(env: Env, d: DecisionRequest): Promise<Grant> {
  // The tenant rule applies to every grant, a lease's included. A lease is a
  // credential, and a hosted tenant refuses any credential not scoped to named
  // stations. hosted() passes a refusal through unchanged, so this refuses more
  // grants without changing why any lease is refused.
  const apply = truthy(env.HELIOGRAPH_RELAY_HOSTED) ? hosted : (g: Grant) => g;
  if (looksLikeAuthority(d.credential)) {
    const g = await admitAuthority(env, d);
    // A lease used outside itself is a request for MORE authority, and more
    // authority comes from the control plane or from nowhere. Everything else
    // about a lease is answered here, with no network call.
    if (g.allow || g.reason !== "out-of-scope") return apply(g);
  }
  const stations = (env.HELIOGRAPH_RELAY_STATIONS ?? "").trim();
  if (stations) return apply(admitScoped(stations, d));
  const url = env.HELIOGRAPH_RELAY_AUTHORISER;
  if (!url) return apply(admitStatic(env, d));
  if (!d.credential) return { allow: false, reason: "no-credential" };
  return apply(await admitRemote(url, d));
}

/**
 * One queue, for one estate, station and direction.
 *
 * A Durable Object is single-threaded and consistent, which is exactly what a
 * queue wants and exactly what a Worker on its own cannot give you. Splitting
 * by route rather than by estate means one busy estate cannot make another
 * wait.
 */
export class RelayQueue implements DurableObject {
  private state: DurableObjectState;
  /** Requests waiting for a message, so a put can wake them immediately. */
  private waiters: Array<() => void> = [];

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    // The outer Worker has already authorised this. Acknowledging is the second
    // half of collecting, so it arrives as a POST to the queue's own path with
    // /ack on the end.
    if (url.pathname.endsWith("/ack")) {
      // Checked before the method fallthrough below, or a GET on this path would
      // be read as a collection of the queue it acknowledges.
      if (req.method !== "POST") {
        return json({ error: "acknowledge a lease with POST", reason: "bad-route" }, 405);
      }
      return this.ack(req);
    }
    if (req.method === "POST") return this.put(req);
    if (req.method === "GET") return this.take(url);
    return json({ error: "method not allowed", reason: "bad-route" }, 405);
  }

  /**
   * Reads the queue, expiring what the seven days have taken and releasing leases
   * whose deadline has passed.
   *
   * `changed` is true when this read alone altered the queue, so a caller that is
   * not going to write anyway still persists the expiry rather than doing it again
   * on every request.
   */
  private async load(): Promise<{ q: Queue; changed: boolean }> {
    const raw = await this.state.storage.get<Queue | Msg[]>("q");
    let q: Queue;
    let changed = false;

    if (raw === undefined) {
      q = { v: QUEUE_SHAPE, n: 1, l: 1, msgs: [] };
    } else if (Array.isArray(raw)) {
      // The shape before leasing: a bare array, no ids, no counters. The hosted
      // relay may be holding messages in it when this deploys, and they must
      // survive that, so they are given ids in the order they were queued.
      let n = 1;
      q = {
        v: QUEUE_SHAPE,
        n: 1,
        l: 1,
        msgs: raw.map((m) => ({ ...m, id: `m${n++}` })),
      };
      q.n = n;
      changed = true;
    } else {
      q = raw;
    }

    const now = Date.now();
    const cut = now - TTL_MS;
    const live = q.msgs.filter((m) => m.at >= cut);
    if (live.length !== q.msgs.length) {
      q.msgs = live;
      changed = true;
    }
    for (const m of q.msgs) {
      if (m.lease !== undefined && (m.until ?? 0) <= now) {
        // The collector holding it never acknowledged. The message stays where it
        // is in the queue rather than moving to the back, so an abandoned lease
        // does not reorder the queue for whoever collects next.
        delete m.lease;
        delete m.until;
        changed = true;
      }
    }
    return { q, changed };
  }

  /**
   * Writes the queue back.
   *
   * The record stays even when the last message has gone, because the counters in
   * it must not restart: an id is what a collector deduplicates on, and a new
   * message wearing a retired id would be dropped as a duplicate of something
   * else. What is retained is about thirty bytes of counters, and no ciphertext.
   */
  private async save(q: Queue): Promise<void> {
    await this.state.storage.put("q", q);
  }

  private async put(req: Request): Promise<Response> {
    let parsed: { seq?: number; body?: string };
    try {
      parsed = (await req.json()) as { seq?: number; body?: string };
    } catch {
      return fail("unreadable-request");
    }
    const body = parsed.body ?? "";
    // base64 is 4 characters per 3 bytes, so this bounds the decoded size
    // without decoding it. The body is never decoded here at all: decoding it
    // would be the first step towards reading it.
    if ((body.length * 3) / 4 > MAX_BODY_BYTES) {
      return fail("too-large");
    }

    const { q } = await this.load();
    // A full queue means the recipient has stopped collecting. Refuse the
    // NEWEST rather than dropping the oldest: silently discarding an earlier
    // message leaves the recipient a gap it reads as a delivered sequence and
    // never learns about, while a refusal reaches the sender, which is the
    // side that can act on it.
    if (q.msgs.length >= MAX_QUEUE) {
      return fail("queue-full");
    }
    q.msgs.push({
      id: `m${q.n++}`,
      seq: parsed.seq ?? 0,
      body,
      at: Date.now(),
    });
    await this.save(q);

    const woken = this.waiters;
    this.waiters = [];
    for (const wake of woken) wake();
    return new Response(null, { status: 202 });
  }

  /** Waits for a put, the hold timeout, or nothing. */
  private async hold(): Promise<void> {
    // Long-poll rather than WebSocket. A station runs behind a corporate proxy
    // that may strip an upgrade header, and a transport that fails on those
    // estates fails on exactly the estates this exists for.
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== wake);
        resolve();
      }, HOLD_MS);
      const wake = () => {
        clearTimeout(timer);
        resolve();
      };
      this.waiters.push(wake);
    });
  }

  /** The messages a collector may have: not held under somebody else's lease. */
  private static available(q: Queue, limit: number): Msg[] {
    const out: Msg[] = [];
    for (const m of q.msgs) {
      if (m.lease !== undefined) continue;
      if (limit > 0 && out.length >= limit) break;
      out.push(m);
    }
    return out;
  }

  private static wire(msgs: Msg[]): { id: string; seq: number; body: string }[] {
    return msgs.map((m) => ({ id: m.id, seq: m.seq, body: m.body }));
  }

  private async take(url: URL): Promise<Response> {
    const held = parseLease(url.searchParams.get("lease"));
    if (held === null) {
      return fail(
        "bad-lease",
        `a lease must be a duration of at most ${MAX_LEASE_MS / 1000}s, like 30s`,
      );
    }
    const limit = Number(url.searchParams.get("limit") ?? "0");
    const wait = url.searchParams.get("wait") !== "0";

    let { q, changed } = await this.load();
    if (RelayQueue.available(q, limit).length === 0 && wait) {
      if (changed) await this.save(q);
      await this.hold();
      ({ q, changed } = await this.load());
    }
    const out = RelayQueue.available(q, limit);

    if (held > 0) {
      // Leased: marked, not deleted. The messages stay in the queue until the
      // collector says it has them, so the window between the relay deleting and
      // the collector durably storing - which is somebody's only copy of a
      // capture - stops existing.
      if (out.length === 0) {
        if (changed) await this.save(q);
        return json({ lease: "", until: "", messages: [] });
      }
      const lease = `L${q.l++}`;
      const until = Date.now() + held;
      for (const m of out) {
        m.lease = lease;
        m.until = until;
      }
      await this.save(q);
      return json({
        lease,
        until: new Date(until).toISOString(),
        messages: RelayQueue.wire(out),
      });
    }

    // No lease asked for, so delete on collection: exactly what this has always
    // done, and what every station already deployed expects, down to the bare
    // array rather than an object. A message under somebody's lease is skipped
    // rather than taken, because a lease any other collector could override would
    // guarantee nothing.
    if (out.length > 0) {
      const taken = new Set(out.map((m) => m.id));
      q.msgs = q.msgs.filter((m) => !taken.has(m.id));
      await this.save(q);
    } else if (changed) {
      await this.save(q);
    }
    return json(RelayQueue.wire(out));
  }

  /** Deletes what a collector has confirmed it holds. */
  private async ack(req: Request): Promise<Response> {
    let parsed: { lease?: string };
    try {
      parsed = (await req.json()) as { lease?: string };
    } catch {
      return fail("unreadable-request", "could not read the acknowledgement");
    }
    const lease = (parsed.lease ?? "").trim();
    const { q, changed } = await this.load();
    const acked = lease === "" ? [] : q.msgs.filter((m) => m.lease === lease);
    if (acked.length === 0) {
      if (changed) await this.save(q);
      // 410 rather than 404: the route exists and the lease is what is gone. It
      // expired, or this is a repeat of an acknowledgement that already worked,
      // and a collector's safe response is the same either way - expect the
      // messages again and recognise them by their ids.
      return fail("no-such-lease");
    }
    q.msgs = q.msgs.filter((m) => m.lease !== lease);
    await this.save(q);
    return json({ deleted: acked.length });
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    // /health carries what a monitoring check has no other way to learn: the
    // version answering, the hash of the bundle answering, and which storage
    // guarantee this deployment gives. `ok` stays first and stays a boolean,
    // because something out there is already looking for it.
    //
    // `durable` is always true here: the queue lives in Durable Object storage,
    // so an accepted message survives the instance that accepted it. The Go
    // server answers the same question with false when it has no spool. The field
    // exists for the same reason the hash does - a published claim about storage
    // was false for the implementation actually deployed, and nobody could tell
    // by asking.
    if (url.pathname === "/health") {
      return json({
        ok: true,
        version: reportedVersion(env),
        hash: reportedHash(env),
        durable: true,
      });
    }

    // /version exists so that "the relay you are talking to is the relay you
    // read" is checkable rather than asserted. Without it nobody, including
    // whoever deployed it, can tell which commit is answering.
    if (url.pathname === "/version") {
      return json({
        service: "heliograph-relay",
        implementation: "worker",
        version: reportedVersion(env),
        source: SOURCE_URL,
      });
    }

    // The one request a human makes. Somebody who found this hostname in a
    // config file and pasted it into a browser used to get a bare 404, which
    // tells them nothing about what they have found or whether it is theirs.
    if (url.pathname === "/") {
      if (wantsHTML(req)) return html(landingHTML(reportedVersion(env)));
      return json({
        service: "heliograph-relay",
        implementation: "worker",
        version: reportedVersion(env),
        what: WHAT_IT_IS,
        source: SOURCE_URL,
        docs: DOCS_URL,
      });
    }

    // /v1/{estate}/{station}/{dir}, and /v1/{estate}/{station}/{dir}/ack
    const parts = url.pathname.split("/").filter(Boolean);
    const isAck = parts.length === 5 && parts[4] === "ack";
    if ((parts.length !== 4 && !isAck) || parts[0] !== "v1") {
      return json({ error: "no such route", reason: "bad-route" }, 404);
    }
    const [, estate, station, dir] = parts;
    // The direction is route shape, not credential scope, so it is refused
    // before the authoriser is asked and refused as a 400. Asking about a
    // direction that does not exist would bill a decision for a typo.
    if (dir !== "c2s" && dir !== "s2c") return fail("bad-route");

    const grant = await admit(env, {
      credential: bearer(req),
      estate,
      station,
      dir,
      // ACKNOWLEDGING IS A READ, even though it arrives as a POST.
      //
      // It is the second half of collecting: the side that may collect a queue
      // is the side that may say it has the messages. Calling it a write would
      // refuse a station credential acknowledging the requests it just
      // collected, because a station may not queue a request - and it would ask
      // the authoriser the wrong question about scope. The Go server routes it
      // to the same OpRead for the same reason.
      op: req.method === "POST" && !isAck ? "write" : "read",
      // A length, never a sample. Absent means the client did not say, which
      // the Go server reports the same way.
      bytes: Number(req.headers.get("content-length") ?? -1),
    });
    if (!grant.allow) return fail(grant.reason ?? "bad-credential");

    const id = env.QUEUE.idFromName(`${estate}/${station}/${dir}`);
    return env.QUEUE.get(id).fetch(req);
  },
} satisfies ExportedHandler<Env>;
