import { env as testEnv } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/worker";
import type { Env } from "../src/worker";

/**
 * Authorisation lease verification at the edge.
 *
 * heliograph-io/heliograph-cloud#75. This implementation is the relay almost
 * every customer touches, so a lease it could not honour would leave the
 * control-plane outage protection absent from the only relay most people use.
 * That is why the rule against cryptography here narrowed to permit
 * verification rather than the feature being dropped.
 *
 * WHAT THE RELAY HOLDS IS A PUBLIC KEY. This file signs, because a test has to
 * mint a lease to check that verifying one works, and it does so with
 * WebCrypto's own key generation rather than anything in `src/`. The Worker's
 * own source is held to importKey and verify by a CI step, and `src/` is what
 * ships.
 *
 * verify_test.go is the Go half of the same pair.
 */

// The contract's published keypair, so this file and conformance/ agree about
// which key a relay under test trusts. Not a secret: it is a test fixture.
const SEED_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const PUBLIC_HEX = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";

const ESTATE = "e-9f3c1a";
const STATION = "pump-01";
const CIPHERTEXT = "Y2lwaGVydGV4dA==";

function hexBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * A signing key, built from the contract's seed.
 *
 * An Ed25519 private key in PKCS#8 is a fixed 16-byte prefix followed by the
 * 32-byte seed, which is the shortest way to turn a published seed into a
 * CryptoKey without carrying a base64 blob nobody can check by eye.
 */
async function signingKey(): Promise<CryptoKey> {
  const prefix = hexBytes("302e020100300506032b657004220420");
  const pkcs8 = new Uint8Array(prefix.length + 32);
  pkcs8.set(prefix, 0);
  pkcs8.set(hexBytes(SEED_HEX), prefix.length);
  return crypto.subtle.importKey("pkcs8", pkcs8 as BufferSource, { name: "Ed25519" }, false, [
    "sign",
  ]);
}

interface LeaseFields {
  estate?: string;
  stations?: string[];
  allStations?: boolean;
  read?: string[];
  write?: string[];
  nbfMs?: number;
  expMs?: number;
  sign?: boolean;
}

async function lease(f: LeaseFields = {}): Promise<string> {
  const now = Date.now();
  const payload: Record<string, unknown> = {
    e: f.estate ?? ESTATE,
    s: f.stations ?? [STATION],
    r: f.read ?? ["c2s"],
    w: f.write ?? ["s2c"],
    nbf: Math.floor((f.nbfMs ?? now - 60_000) / 1000),
    exp: Math.floor((f.expMs ?? now + 10 * 60_000) / 1000),
  };
  if (f.allStations) payload.a = true;
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  if (f.sign === false) {
    return `hl1.${body}.${b64url(new Uint8Array(64))}`;
  }
  const sig = await crypto.subtle.sign(
    { name: "Ed25519" },
    await signingKey(),
    new TextEncoder().encode(body) as BufferSource,
  );
  return `hl1.${body}.${b64url(new Uint8Array(sig))}`;
}

async function call(
  method: "GET" | "POST",
  route: string,
  credential: string,
  bindings: Partial<Env>,
): Promise<{ status: number; reason: string }> {
  const url = `https://relay.test/v1/${route}${method === "GET" ? "?wait=0" : ""}`;
  const req = new Request(url, {
    method,
    headers: { authorization: `Bearer ${credential}` },
    body: method === "POST" ? JSON.stringify({ seq: 1, body: CIPHERTEXT }) : undefined,
  });
  const resp = await worker.fetch(
    req,
    { QUEUE: testEnv.QUEUE, HELIOGRAPH_RELAY_ESTATES: "", ...bindings } as Env,
  );
  let reason = "";
  if (resp.status !== 202 && resp.status !== 200) {
    reason = ((await resp.json()) as { reason?: string }).reason ?? "";
  }
  return { status: resp.status, reason };
}

const verifying = { HELIOGRAPH_RELAY_LEASE_KEY: PUBLIC_HEX };

describe("a lease the worker can verify", () => {
  it("is honoured", async () => {
    const r = await call("POST", `${ESTATE}/${STATION}/s2c`, await lease(), verifying);
    expect(r.status).toBe(202);
  });

  it("collects its own requests", async () => {
    const r = await call("GET", `${ESTATE}/${STATION}/c2s`, await lease(), verifying);
    expect(r.status).toBe(200);
  });

  // The asymmetry survives leasing, exactly as it survives scoping.
  it("still may not queue a request for its own station", async () => {
    const r = await call("POST", `${ESTATE}/${STATION}/c2s`, await lease(), verifying);
    expect(r.status).not.toBe(202);
  });

  // A lease used outside itself is a request for MORE authority, so it falls
  // through to whatever authoriser sits underneath rather than being refused
  // here. That is deliberate: the station may genuinely be entitled to this and
  // simply not hold a lease saying so, and only the control plane knows.
  //
  // So the reason on this one comes from the authoriser underneath, which here
  // has no estates configured and says "bad-credential". The refusal is what
  // this asserts; which component refused is the next assertion down.
  it("does not reach a station it does not name", async () => {
    const r = await call("POST", `${ESTATE}/till-07/s2c`, await lease(), verifying);
    expect(r.status).not.toBe(202);
  });

  it("falls through to the authoriser when used outside its own scope", async () => {
    // With per-station scopes configured underneath, the fallthrough reaches a
    // real answer rather than an empty one, and that answer is out-of-scope.
    const r = await call("POST", `${ESTATE}/till-07/s2c`, await lease(), {
      ...verifying,
      HELIOGRAPH_RELAY_STATIONS: `${ESTATE}:till-07:station:somebody-elses-credential`,
    });
    expect(r.status).not.toBe(202);
    expect(r.reason).toBe("bad-credential");
  });
});

describe("a lease the worker cannot verify", () => {
  it("is refused when the signature is not ours", async () => {
    const r = await call("POST", `${ESTATE}/${STATION}/s2c`, await lease({ sign: false }), verifying);
    expect(r.status).not.toBe(202);
    expect(r.reason).toBe("authority-unverifiable");
  });

  // Fail closed. A relay that accepted an unverified lease would accept a
  // forged one, and the forger chooses the scope.
  it("is refused when no key is configured at all", async () => {
    const r = await call("POST", `${ESTATE}/${STATION}/s2c`, await lease(), {});
    expect(r.status).not.toBe(202);
    expect(r.reason).toBe("authority-unverifiable");
  });

  it("is refused when the configured key is not a key", async () => {
    const r = await call("POST", `${ESTATE}/${STATION}/s2c`, await lease(), {
      HELIOGRAPH_RELAY_LEASE_KEY: "not-a-key",
    });
    expect(r.reason).toBe("authority-unverifiable");
  });

  // A private key pasted where the public half belongs would leave signing
  // material in the configuration of a relay whose claim is that it holds no
  // key worth stealing. Refused rather than truncated to its public half.
  it("is refused when a private key is configured instead of a public one", async () => {
    const priv = SEED_HEX + PUBLIC_HEX; // the 64-byte form
    const r = await call("POST", `${ESTATE}/${STATION}/s2c`, await lease(), {
      HELIOGRAPH_RELAY_LEASE_KEY: priv,
    });
    expect(r.reason).toBe("authority-unverifiable");
  });
});

describe("a signed lease still has to be in date", () => {
  it("is refused once expired", async () => {
    const now = Date.now();
    const r = await call(
      "POST",
      `${ESTATE}/${STATION}/s2c`,
      await lease({ nbfMs: now - 20 * 60_000, expMs: now - 10 * 60_000 }),
      verifying,
    );
    expect(r.status).not.toBe(202);
    expect(r.reason).toBe("authority-expired");
  });

  it("is refused before it is in force", async () => {
    const now = Date.now();
    const r = await call(
      "POST",
      `${ESTATE}/${STATION}/s2c`,
      await lease({ nbfMs: now + 10 * 60_000, expMs: now + 20 * 60_000 }),
      verifying,
    );
    expect(r.reason).toBe("authority-expired");
  });

  // Longer than the relay honours would quietly extend the maximum revocation
  // delay this product publishes as a number.
  it("is refused when longer than the published maximum", async () => {
    const now = Date.now();
    const r = await call(
      "POST",
      `${ESTATE}/${STATION}/s2c`,
      await lease({ nbfMs: now - 60_000, expMs: now + 30 * 60_000 }),
      verifying,
    );
    expect(r.reason).toBe("authority-expired");
  });
});

/**
 * A hosted tenant refuses an estate-wide lease, as it refuses an estate-wide
 * credential.
 *
 * HELIOGRAPH_RELAY_HOSTED promises to refuse any credential not scoped to named
 * stations, and a lease is a credential. The lease path used to answer before
 * the tenant rule was applied, so a valid lease saying allStations was admitted
 * by a relay that had been told one estate may hold several customers.
 *
 * authlease_test.go is the Go half of the same pair.
 */
describe("a hosted tenant and a lease", () => {
  const hostedVerifying = { ...verifying, HELIOGRAPH_RELAY_HOSTED: "1" };

  it("refuses a lease covering every station in the estate, and says why", async () => {
    const wide = await lease({ stations: [], allStations: true });
    const r = await call("POST", `${ESTATE}/${STATION}/s2c`, wide, hostedVerifying);
    expect(r.status).toBe(401);
    expect(r.reason).toBe("estate-wide-credential");
  });

  it("does not let an estate-wide lease collect either", async () => {
    const wide = await lease({ stations: [], allStations: true });
    const r = await call("GET", `${ESTATE}/${STATION}/c2s`, wide, hostedVerifying);
    expect(r.status).not.toBe(200);
    expect(r.reason).toBe("estate-wide-credential");
  });

  // Or the refusal above proves only that leasing is broken under hosting.
  it("still honours a lease scoped to named stations", async () => {
    const r = await call("POST", `${ESTATE}/${STATION}/s2c`, await lease(), hostedVerifying);
    expect(r.status).toBe(202);
  });

  // Hosting changes which grants are refused, never why a lease was refused.
  it("keeps the reason a lease was refused for", async () => {
    const now = Date.now();
    const expired = await lease({ nbfMs: now - 20 * 60_000, expMs: now - 10 * 60_000 });
    let r = await call("POST", `${ESTATE}/${STATION}/s2c`, expired, hostedVerifying);
    expect(r.reason).toBe("authority-expired");
    r = await call("POST", `${ESTATE}/${STATION}/s2c`, await lease({ sign: false }), hostedVerifying);
    expect(r.reason).toBe("authority-unverifiable");
  });
});
