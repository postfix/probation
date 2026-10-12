# Backlog

Requested work not yet planned. An entry here is a candidate, not a commitment: it becomes real
when it gets a `docs/plans/<slug>/` and a Gate 1.

---

## B1 — Block on vulnerability intelligence (OSV), not only on hashes — **SHIPPED**

**Requested:** 2026-09-25, by the user. Accepted the same day, in Rust with no provider
abstraction (a scriptable-provider proposal was declined). **Shipped** in f5ec49a via
`docs/plans/osv-intel/` (all four gates approved 2026-09-29, slices 1–4 done, ending with
operator-configurable `osv_mode`). The product questions were settled in
`docs/plans/osv-intel/01-product.md`; the operator view is `docs/operations.md` §4.

---

## B4 — Authenticate inbound clients with a generated per-user password

**Requested:** 2026-09-25, by the user, as planned work.

**What.** Require a single shared secret on package and artifact requests, instead of serving every
anonymous peer.

**Scope, set by the user 2026-09-25, revised the same day: a generated unique password per user.**
Not an identity provider, not OAuth, not per-team policy — a high-entropy secret issued per user,
whose identity is recorded on the decision line for troubleshooting. The first scoping was one
shared password; the user revised it on the point below, that a shared secret buys no attribution.

**Where the codebase stands today: there is no inbound authentication of any kind.** Checked
2026-09-25. The `auth`-shaped code in `src/` is entirely outbound — `src/upstream/reqwest_transport.rs`
for the upstream registries and `src/delivery/mod.rs` for the SIEM sink credential. The SPEC is
deliberate about this rather than silent:

- `SPEC.md:361` mentions client authorization only to forbid forwarding it: "Never forward a
  client's authorization, cookies, or proxy credentials upstream."
- `SPEC.md:234` and `:236` state twice that `reference_id` "is a lookup key, **not** a content hash
  or authorization token", and explain that the ecosystem segment is checked precisely *because*
  the id is derived from public metadata and authorizes nothing.
- `SPEC.md:280`'s "a request is authorized by its final successful policy check" means **policy**
  authorization — blocklist and age — not identity.

So this is new surface, not a gap in an existing mechanism.

**What a shared password does and does not buy.** Several risks in the `rated-load-guard` plan are
accepted in their current form *because* every caller is anonymous — it is why that plan keeps
saying "unauthenticated peer". A shared secret removes the **anonymous internet** from all of them:
**G3-T6** (flood, poll until shedding, then fetch what you want absent), **G3-T13** (attacker-set
log volume against a collector the operator cannot throttle) and **G3-T7** (the `/health/` route as
a load-balancer lever) all stop being reachable by someone who simply knows the URL.

**Per-user passwords additionally buy what a shared one cannot:** attribution on the decision line,
revocation of one user without disturbing the rest, and rotation without global downtime. That is
the reason for the revision — a single shared secret leaves an insider and a leaked password
indistinguishable from a legitimate client. None of the existing acceptances becomes wrong either
way: they were taken under the more hostile anonymous assumption.

**Open questions for Gate 1**, none settled here:
- **How does the secret travel, and can the real clients send it?** A fact to measure:
  `npm` supports `_auth` / `_authToken` in `.npmrc` and `pip` takes credentials in the index URL, so
  HTTP Basic and Bearer are the candidates — but which one each client actually sends, per version,
  is a fact to check before choosing, not after.
- **Is it required, or configurable?** An always-on requirement is a breaking change for every
  existing client. If it is a config key, absent-means-open repeats the `log_file_path` shape this
  project already has, and the default decides whether a fresh deployment is exposed.
- **What does a wrong or missing password get?** `401` with a challenge, or `404` to avoid
  confirming the instance exists at all.
- **Log the identity, never the secret.** `SPEC.md:379` fixes the logged field set and says "Never
  log credentials"; this is the first inbound credential that sentence must hold for, and the whole
  point of the feature is to put *something* about the caller on that line. The two are one edit
  apart.
- **Storage and lookup.** Where do the credentials live — config, or the embedded Turso store the
  `store` module already owns? Because the secrets are *generated* rather than chosen, they are
  high-entropy, so storing a SHA-256 of each and looking up **by that hash** gives an O(1) match
  with no per-record scan and no password at rest. A slow KDF (argon2, bcrypt) buys nothing against
  a 256-bit random token and costs latency on every request.
- **Issuing and revoking.** Generating a password is easy; the operator workflow around it is the
  actual feature. Who issues, how is it delivered once, and what does revocation do to a client
  mid-install?
- **Transport.** A shared password over plain HTTP is worth nothing. Since f5ec49a `serve`
  terminates TLS itself when `tls_cert_path`/`tls_key_path` are set (`docs/operations.md` §6),
  so the question is whether to refuse the feature on a plain-HTTP listener.

**Cross-plan consequence, recorded now so it is not a surprise later.** Putting a caller identity on
the decision line adds a field to `Decision` (`src/delivery/mod.rs`). The shipped
`rated-load-guard` plan fixed `BYTES_PER_RECORD` as a *ceiling* over that struct, derived field by
field — today six `String`s, three `&'static str`, four integers and one `Option<IpAddr>`, with a
compile-time assertion on the struct size. A seventh `String` changes that derivation, the
published budget, and the `rl22` property that falsifies it. Cheapest handling: bound the identity
field the way `method`, `package` and `version` are bounded, and restate the derivation in the
same change.

### B4 addendum — signed tokens instead of stored credentials

**Proposed:** 2026-09-25, by the user: *"We don't need to store passwords, we can just sign it and
verify signature."*

**The idea.** The credential is a token carrying the user's identity plus a MAC over it, computed
with one server-side signing key. Verification recomputes the MAC and compares. Nothing per-user is
stored anywhere.

**What it buys, and it is real:**
- **No credential store at all.** One key in config, no table, no migration, nothing per-user to
  back up or leak.
- **O(1) stateless verification** on every request, no database round trip on the hot path.
- **Attribution comes free** — the identity is *inside* the token, so the decision line can name it
  without a lookup, which is the whole point of the per-user revision.
- **Nothing secret at rest** beyond the single signing key.

**The one question it has to answer: revocation.** A stateless token cannot be withdrawn. A
developer leaves the team, or a token leaks — with stored credentials that is a row delete; with
signatures the only lever is rotating the signing key, which invalidates *everyone's* token at once
and means reissuing to the whole team. Three ways out, and the choice shapes the feature:
1. **Short expiry plus reissue.** The token carries an expiry the MAC covers. Revocation becomes
   "wait for it to lapse", so the window is the expiry. Costs a reissue workflow and puts a clock in
   the credential — a client whose token expires mid-CI-run fails in a way a password never does.
2. **A denylist of revoked identities.** Storage comes back, but only for revoked users rather than
   all of them — typically a handful, and the embedded Turso store the `store` module already owns
   can hold it. This keeps stateless verification for the common case.
3. **Accept that revocation means rotating the key** and reissuing to everyone. Defensible for a
   small team, and it should be *stated* rather than discovered the first time someone leaves.

**Second question: expiry.** A token that never expires is valid forever once leaked, and there is
no store to notice. Related, and the same shape as the problem the shared-password scoping had: key
rotation is still all-or-nothing.

**Implementation notes, grounded 2026-09-25:**
- The primitive is **HMAC-SHA256**, not a bare hash of key-plus-message, and the comparison must be
  constant-time. `sha2 = "0.11.0"` is already a direct dependency (`Cargo.toml:21`); **`hmac` is
  not** and would be a new one — it is the RustCrypto crate that pairs with `sha2`, and `subtle`
  for the constant-time compare. Small, but new, so it is a decision rather than a detail.
- Token length matters only because of where it has to travel: a `.npmrc` `_authToken` or a `pip`
  index URL. Identity plus a 256-bit MAC, base64'd, lands around 60-100 characters — fine for both,
  but worth confirming against the real clients alongside B4's other client measurement.

**How it compares with storing hashes.** The alternative already in this entry — generate a
high-entropy token, store its SHA-256, look up by that hash — is also O(1), also keeps no password
at rest, and makes revocation a row delete, at the cost of one table in a store that already exists.
So the honest framing is not "storage versus no storage" but **"where does revocation live"**.
Signing moves the cost from a table to a workflow; whether that is cheaper depends entirely on how
often a credential has to be withdrawn.

**Decide revocation first.** Expiry, rotation, storage and the operator workflow all fall out of
that one answer, and it is a product question, not an implementation one.

