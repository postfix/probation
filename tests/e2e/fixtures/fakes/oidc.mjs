// The fake OIDC IdP. It answers under every IdP name the stack routes to it
// (idp.e2e.test for company SSO, accounts.google.com for the Google provider); the
// issuer is `https://<host>`. Authorization redirects straight back (no login page)
// as the person set with `next`, and `next.mode` makes the ID token bad in one way, for
// the negative cases: wrong_iss, wrong_aud, expired, alg_none, unknown_kid,
// bad_signature, no_nonce, wrong_nonce, or cancel (the person declines).

import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const DEFAULT_PERSON = { sub: "e2e-sso-1", email: "sso-user@acme.e2e.test", mode: "ok" };

export class Oidc {
  constructor() {
    this.reset();
  }

  reset() {
    this.codes = new Map();
    this.person = { ...DEFAULT_PERSON };
    this.rotate();
  }

  /// Who the next sign-ins are (sticky until changed): {sub, email, hd, tid, mode}.
  next(person) {
    this.person = { ...DEFAULT_PERSON, ...person };
  }

  /// A new signing key; the old one leaves the JWKS.
  rotate() {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    this.key = { kid: randomBytes(6).toString("hex"), privateKey, publicKey };
  }

  idToken(issuer, grant) {
    const { person, clientId, nonce } = grant;
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: person.mode === "wrong_iss" ? "https://evil.e2e.test" : issuer,
      aud: person.mode === "wrong_aud" ? "someone-else" : clientId,
      sub: person.sub,
      email: person.email,
      email_verified: true,
      iat: now,
      exp: person.mode === "expired" ? now - 3600 : now + 600,
    };
    if (person.hd) claims.hd = person.hd;
    if (person.tid) claims.tid = person.tid;
    if (person.mode !== "no_nonce") claims.nonce = person.mode === "wrong_nonce" ? "not-the-nonce" : nonce;
    if (person.mode === "alg_none") return `${b64({ alg: "none", typ: "JWT" })}.${b64(claims)}.`;
    const kid = person.mode === "unknown_kid" ? "rotated-away" : this.key.kid;
    const signing = `${b64({ alg: "RS256", typ: "JWT", kid })}.${b64(claims)}`;
    const signature = sign("sha256", Buffer.from(signing), this.key.privateKey);
    if (person.mode === "bad_signature") signature[0] ^= 1;
    return `${signing}.${signature.toString("base64url")}`;
  }

  handle(req, path, host, body) {
    const issuer = `https://${host}`;
    const url = new URL(path, issuer);
    switch (url.pathname) {
      case "/.well-known/openid-configuration":
        return json({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          code_challenge_methods_supported: ["S256"],
        });
      case "/jwks":
        return json({ keys: [{ ...this.key.publicKey.export({ format: "jwk" }), kid: this.key.kid, alg: "RS256", use: "sig" }] });
      case "/authorize": {
        const q = url.searchParams;
        const back = new URL(q.get("redirect_uri"));
        back.searchParams.set("state", q.get("state") ?? "");
        if (this.person.mode === "cancel") {
          back.searchParams.set("error", "access_denied");
        } else {
          const code = randomBytes(16).toString("hex");
          this.codes.set(code, {
            person: this.person,
            clientId: q.get("client_id"),
            redirectUri: q.get("redirect_uri"),
            challenge: q.get("code_challenge"),
            nonce: q.get("nonce"),
          });
          back.searchParams.set("code", code);
        }
        return { status: 302, headers: { location: back.toString() }, body: "" };
      }
      case "/token": {
        if (req.method !== "POST") return { status: 405, body: "" };
        const form = new URLSearchParams(body.toString());
        const grant = this.codes.get(form.get("code"));
        this.codes.delete(form.get("code"));
        const verifier = form.get("code_verifier") ?? "";
        const challenge = createHash("sha256").update(verifier).digest("base64url");
        if (!grant || grant.redirectUri !== form.get("redirect_uri") || grant.clientId !== form.get("client_id") || grant.challenge !== challenge) {
          return { status: 400, headers: { "content-type": "application/json" }, body: '{"error":"invalid_grant"}' };
        }
        return json({ access_token: randomBytes(16).toString("hex"), token_type: "Bearer", expires_in: 600, id_token: this.idToken(issuer, grant) });
      }
      default:
        return { status: 404, body: "Not Found" };
    }
  }
}

function json(value) {
  return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify(value) };
}
