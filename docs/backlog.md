# Backlog

Requested work not yet planned. An entry here is a candidate, not a commitment: it becomes real
when it gets a `docs/plans/<slug>/` and a Gate 1.

---

## B1 — Block on vulnerability intelligence (OSV), not only on hashes — **ACCEPTED, unplanned**

**Requested:** 2026-09-25, by the user. **Accepted the same day, to be implemented in Rust with no provider abstraction (see B2).** Not yet planned: it needs a `docs/plans/` slug and a Gate 1, and the open questions below are what Gate 1 has to settle.

**What.** Fetch advisory data from the [OSV](https://osv.dev) API and use it to decide blocks,
instead of relying on the operator's hand-fed artifact digests.

**Why it matters.** Today the blocklist carries `blocked_hashes` (SPEC §, the `blocked_hashes`
array with `algorithm`/`value`) plus package and version blocks, supplied by an external producer
that writes the snapshot this service polls. The firewall can therefore only block what somebody
has already identified and hashed. A package compromised an hour ago is invisible to it until that
producer catches up. OSV would give the service its own source of truth.

**What already exists and must not be reinvented:** the blocklist snapshot loader, its
`expires_at` validity window, the fail-closed behaviour when no valid snapshot is loaded (the
service starts, answers `/health/live` but not `/health/ready`, and refuses every package
request), and `blocklist_poll_seconds`. An intelligence provider is a new *source* for that
existing decision path, not a new decision path.

**Open questions for Gate 1**, none of them settled here:
- Does OSV data *replace* the producer's snapshot, or merge with it? What wins on disagreement?
- OSV keys advisories by package and version range. The current model blocks exact artifact
  digests. Which is authoritative when a version matches an advisory but its digest is unlisted?
- What happens when OSV is unreachable? The blocklist's answer is fail-closed; is that right for
  a second source, or does an outage in one source stop the firewall serving?
- Severity threshold, or block everything with an advisory?

---

## B2 — Swappable intelligence providers via an embedded script engine — **DECLINED 2026-09-25**

**Requested:** 2026-09-25, by the user, alongside B1. The proposal was an embedded Lua engine so
that changing provider means editing a script and declaring a data schema, with no rebuild.

**Decision, 2026-09-25: declined by the user. OSV is hardcoded in Rust.** No script engine, no
configuration DSL, no provider abstraction. The deciding reason is the one that survived the
argument below: a provider system for one provider generalises over an interface that has never
been exercised twice. Revisit only when a second provider is actually wanted — and note that at
that point an embedded language beats a homegrown mapping language, which is the opposite of what
this entry first recommended.

**Possible SPEC conflict, recorded unresolved — the author decides.** `SPEC.md:59` ends:

> Do not implement a dependency solver or **generic plugin framework**.

The term appears exactly once in the SPEC, is not defined there or anywhere in `docs/`, and sits in
a paragraph otherwise about which libraries to use — beside "dependency solver", which suggests the
intent was "do not build large generic machinery yourself" rather than a ruling on this case.

Whether B2 is caught by it is genuinely arguable. An embedded Lua engine has three of the four
things that usually make a plugin framework — a loader (the VM), operator-authored code running
in-process, and a declared contract (the data schema) — but **one** extension point rather than
arbitrary ones. That is closer to a configurable client than to a framework. The SPEC's author is
the one who settles it; this entry does not.

**Two further costs, recorded so the decision is made with them in view:**
- It moves parsing of untrusted upstream JSON into operator-authored script, inside a service
  whose entire job is to be a trust boundary. A provider script becomes a new place to get
  memory-safety and injection questions wrong, in a language without the type system that
  currently carries those guarantees.
- It is a plugin system for one plugin. There is no second provider today, so the interface it
  would generalise over has never been exercised twice. **This is the load-bearing objection** — it
  is about timing, not about scripting, and it applies equally to any configuration language
  invented for the same purpose.

**The cheaper thing that delivers most of the value:** ship OSV as one provider, in Rust. No
script, no mapping language. If and when a second provider exists, the seam's shape will be known
rather than guessed.

**Correction, same day.** An earlier draft of this entry proposed a config-declared endpoint plus a
field mapping as the "cheaper" alternative to Lua. The user pointed out that this is a DSL
invention, and they are right: a bespoke mapping language means designing a grammar, an evaluation
model and error messages from nothing, which is *more* build than embedding a mature language, not
less. If operator-editable provider logic is ever actually wanted, an embedded language (Lua via
`mlua`, or Rhai, or Starlark) is the smaller and better-tested choice, and this entry no longer
recommends a homegrown config DSL over it. The objection that survives is narrower and applies to
both: **one provider does not need a provider system.**

**Status: B1 is the work. B2 is closed unless a second provider appears.**

---

## B3 — Tell the developer *why* their package was blocked, where they will actually see it

**Requested:** 2026-09-25, by the user.

**What.** A developer whose `npm install` or `pip install` fails should learn that the firewall
blocked the package, which package and version, and what to do next.

**What already exists and must not be reinvented.** The server side is largely built:

- `ApiError::Blocked { reason: &'static str }` (`src/http/error.rs`) is the denial arm, and its
  doc comment already states the design intent — "There is no deadline: a block is not something
  to wait out."
- `ApiError::Held { eligible_at_micros, retry_after_seconds }` is the cooldown arm and already
  carries a numeric `Retry-After` and the eligibility deadline, per SPEC §11.
- Errors are rendered as a JSON `ErrorBody` through `Json(body).into_response()`.

So the firewall already *has* a per-denial reason and already puts it on the wire. This entry is
not about producing a reason; it is about the reason reaching a human.

**The actual gap, and the thing Gate 1 must verify first.** A carefully written JSON error body is
of no use if the package manager never shows it. `npm` and `pip` surface registry failures in their
own words, and how much of a response body they reveal differs by client and version. **Nobody has
checked what a developer sees today** — that measurement is the first task, not a design decision.
Run a real block through both clients and record the exact terminal output before proposing
anything. Every option below is worthless if it lands somewhere the client discards.

**Open questions for Gate 1**, none settled here:
- What do `npm` and `pip` actually print for each denial arm today? Which parts of the response —
  status, reason phrase, headers, body — reach the terminal, per client?
- If the body is discarded by the client, what channel is left? A chosen status code, a header the
  client echoes, or a stable short URL in whatever text does survive?
- ~~How much should the message say?~~ **Settled 2026-09-25 by the user: say it.** Naming the
  advisory or blocklist entry also tells an unauthenticated caller what the firewall knows, which is
  the confirmation-oracle shape accepted as G3-T6 in the `rated-load-guard` plan. The user accepts
  that disclosure, so it is **not** a constraint on the message: write the useful one. B4 would
  narrow the exposure further.
- Is the audience the developer alone, or also the operator who must unblock? Those want different
  messages, and only one of them is reading a terminal.

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
- **How does the secret travel, and can the real clients send it?** The same measurement B3 needs:
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
- **Transport.** A shared password over plain HTTP is worth nothing. Does this instance terminate
  TLS, or is it always behind a proxy that does? The SPEC does not say.

**Cross-plan consequence, recorded now so it is not a surprise later.** Putting a caller identity on
the decision line adds a field to `Decision` (`src/delivery/mod.rs`). The in-flight
`rated-load-guard` plan is at this moment fixing `BYTES_PER_RECORD` as a *ceiling* over that struct,
derived field by field — today six `String`s, three `&'static str`, four integers and one
`Option<IpAddr>`. A seventh `String` changes that derivation, the published budget, and the
`rl22` property that falsifies it. Cheapest handling: bound the identity field the way `method`,
`package` and `version` are bounded, and restate the derivation in the same change. This is a reason
to land `rated-load-guard` first, not a reason to alter it now.

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
  but worth confirming against the real clients alongside B3's and B4's other client measurement.

**How it compares with storing hashes.** The alternative already in this entry — generate a
high-entropy token, store its SHA-256, look up by that hash — is also O(1), also keeps no password
at rest, and makes revocation a row delete, at the cost of one table in a store that already exists.
So the honest framing is not "storage versus no storage" but **"where does revocation live"**.
Signing moves the cost from a table to a workflow; whether that is cheaper depends entirely on how
often a credential has to be withdrawn.

**Decide revocation first.** Expiry, rotation, storage and the operator workflow all fall out of
that one answer, and it is a product question, not an implementation one.

