// The model of the property-based portal test (harness/pbt.mjs): what the portal and
// the firewalls should do, from the model's state alone, with no I/O.
//
// The policy rules are a port of crates/probation-policy (resolve, rules_for and
// check_edit, C8 C11 C16 C45 C46 C47) for the values the test generates: canonical npm
// names, PyPI `e2e-left`, versions in plain x.y.z. Roles and visibility follow
// tenancy.rs (`role_for`, `authorized_place`, `may_edit`; C1 C24 C27 C78).
//
// `node tests/e2e/harness/pbt-model.mjs` runs its self-check (cases from lib.rs's tests).

export const HOUR = 3600;
export const DAY = 86_400;
const KINDS = ["platform", "org", "group", "user", "personal"];
const SWITCHES = ["exceptions", "osv_off", "shorter_freeze"];

/// An empty layer: inherits everything, allows nothing.
export const emptyLayer = (kind) => ({ kind, freeze: null, allow: { exceptions: false, osv_off: false, shorter_freeze: false }, blocks: [], exceptions: [] });

export const cloneLayer = (layer) => structuredClone(layer);

/// resolve(): the chain (top to bottom) merged; `allow` is what the layer below it may loosen.
export function resolve(chain) {
  const blocks = [];
  const exceptions = [];
  let above = { exceptions: true, osv_off: true, shorter_freeze: true };
  for (const layer of chain) {
    for (const block of layer.blocks) blocks.push({ owner: layer.kind, ...block });
    for (const e of layer.exceptions) {
      const lifts = { block: e.lifts.block && above.exceptions, freeze: e.lifts.freeze && above.shorter_freeze, osv: e.lifts.osv && above.osv_off };
      if (lifts.block || lifts.freeze || lifts.osv) exceptions.push({ owner: layer.kind, ...e, lifts });
    }
    above = Object.fromEntries(SWITCHES.map((s) => [s, above[s] && layer.allow[s]]));
  }
  return { chain, blocks, exceptions, allow: above };
}

const rank = (kind) => KINDS.indexOf(kind);

/// merge(): a stricter freeze replaces the one above, a looser one only while every layer
/// above allows a shorter freeze; lifted layers are skipped. [seconds, kind] or null.
function mergeFreeze(chain, lifted = () => false) {
  let merged = null;
  let allowed = true;
  for (const layer of chain) {
    if (layer.freeze !== null && !lifted(layer.kind)) {
      if (merged === null || layer.freeze > merged[0] || (layer.freeze < merged[0] && allowed)) merged = [layer.freeze, layer.kind];
    }
    allowed &&= layer.allow.shorter_freeze;
  }
  return merged;
}

/// The firewall's decision for one npm or PyPI version under `chain`: "blocked", "held"
/// or "allowed". `age` is the version's age in seconds.
export function decide(chain, { ecosystem, name, version, age }) {
  const policy = resolve(chain);
  const matching = policy.exceptions.filter((e) => e.ecosystem === ecosystem && e.name === name && (e.version === null || e.version === version));
  const liftedAt = (owner, lift) => matching.some((e) => rank(e.owner) >= rank(owner) && e.lifts[lift]);
  const blocked = policy.blocks.some(
    (b) => b.what !== "file" && b.ecosystem === ecosystem && b.name === name && (b.what === "package" || b.version === version) && !liftedAt(b.owner, "block"),
  );
  if (blocked) return "blocked";
  const freeze = mergeFreeze(chain, (kind) => liftedAt(kind, "freeze"));
  return freeze && freeze[0] > age ? "held" : "allowed";
}

const sameTarget = (a, b) => a.ecosystem === b.ecosystem && a.name === b.name && a.version === b.version;

/// check_edit(): null when `proposed` may replace `current` under the layers `above`,
/// else the switch whose refusal the form shows ("shorter_freeze", ...).
export function checkEdit(above, current, proposed) {
  const parent = resolve(above);
  const freezeAbove = mergeFreeze(above);
  if (
    proposed.freeze !== null &&
    (current.freeze === null || proposed.freeze < current.freeze) &&
    freezeAbove &&
    proposed.freeze < freezeAbove[0] &&
    !parent.allow.shorter_freeze
  )
    return "shorter_freeze";
  for (const e of proposed.exceptions) {
    const had = { block: false, freeze: false, osv: false };
    for (const stored of current.exceptions) {
      const samePackage = stored.ecosystem === e.ecosystem && stored.name === e.name;
      if (sameTarget(stored, e)) for (const lift of Object.keys(had)) had[lift] ||= stored.lifts[lift];
      else if (samePackage && stored.version === null && e.version !== null) {
        had.freeze ||= stored.lifts.freeze;
        had.osv ||= stored.lifts.osv;
      }
    }
    for (const [lift, sw] of [["block", "exceptions"], ["freeze", "shorter_freeze"], ["osv", "osv_off"]]) {
      if (e.lifts[lift] && !had[lift] && !parent.allow[sw]) return sw;
    }
  }
  return SWITCHES.find((sw) => proposed.allow[sw] && !current.allow[sw] && !parent.allow[sw]) ?? null;
}

// ---- Roles (tenancy.rs) ----------------------------------------------------------------

/// The person's membership in `org` (a model org), or undefined.
export const membership = (org, slot) => org?.members.find((m) => m.slot === slot);

/// Whether the person's session counts a second factor (`signed_in_as`): it passed a
/// code at sign-in, or the login has an authenticator.
export const secondFactor = (person) => person.totp || person.sessionTotpOk;

/// `role_for` for one of the test's people (none is a global admin) on `place`
/// ({kind, org, group, mid, personal, owner}); `admin`: may hold the org admin role.
export function roleFor(model, person, place, admin = secondFactor(person)) {
  if (place.kind === "platform") return null;
  const org = place.org === undefined ? undefined : model.orgs.find((o) => o.id === place.org);
  if (place.kind === "personal") {
    const owned = person.personal && person.personal.id === place.id && !person.personal.deleted;
    return owned ? "owner" : null;
  }
  if (!org || org.status === "suspended") return null;
  const m = membership(org, person.slot);
  if (!m) return null;
  if (admin && m.role === "org_admin") return "org_admin";
  if (place.kind === "group" && m.role === "group_admin" && m.group === place.group) return "group_admin";
  if (place.kind === "user" && place.mid === m.mid) return "owner";
  return "member";
}

/// Whether an admin role is held back for want of a second factor (`Actor.withheld`).
export const withheld = (model, person, place) => !secondFactor(person) && roleFor(model, person, place, true) !== roleFor(model, person, place, false);

/// `authorized_place` for one of the test's people: visible, or the same 404 as unknown.
export function visible(model, person, place) {
  if (place.kind === "platform") return false;
  if (place.kind === "personal") return Boolean(person.personal && person.personal.id === place.id && !person.personal.deleted);
  const org = model.orgs.find((o) => o.id === place.org);
  return Boolean(org && membership(org, person.slot));
}

/// `may_edit`.
export function mayEdit(role, kind) {
  switch (role) {
    case "org_admin":
      return ["org", "group", "user"].includes(kind);
    case "group_admin":
      return kind === "group";
    case "owner":
      return kind === "user" || kind === "personal";
    default:
      return false;
  }
}

/// The places of the person's switcher, in its order (`top_bar`): "personal", "org:<id>".
export function places(model, person) {
  const list = [];
  if (person.personal && !person.personal.deleted) list.push("personal");
  for (const org of [...model.orgs].sort((a, b) => a.id - b.id)) if (membership(org, person.slot)) list.push(`org:${org.id}`);
  return list;
}

/// The place the person's session works in: the chosen one while it is listed, else the first.
export function currentPlace(model, person) {
  const list = places(model, person);
  return list.includes(person.chosen) ? person.chosen : (list[0] ?? null);
}

/// A layer key's place: {kind, id, org, group, mid}.
export function placeOf(model, key) {
  const [kind, raw] = key.split("-");
  const id = Number(raw);
  if (kind === "platform") return { kind, id };
  if (kind === "personal") return { kind, id };
  if (kind === "org") return { kind, id, org: id };
  if (kind === "group") {
    const org = model.orgs.find((o) => o.groups.some((g) => g.id === id));
    return { kind, id, org: org?.id ?? -1, group: id };
  }
  for (const org of model.orgs) {
    const m = org.members.find((x) => x.mid === id);
    if (m) return { kind, id, org: org.id, group: m.group, mid: id };
  }
  return { kind, id, org: -1, mid: id };
}

/// The chain of layer keys from the platform down to `key`, as the place sits now.
export function chainOf(model, key) {
  const place = placeOf(model, key);
  if (place.kind === "platform") return ["platform-1"];
  if (place.kind === "personal") return ["platform-1", key];
  const chain = ["platform-1", `org-${place.org}`];
  if (place.kind === "group") chain.push(key);
  if (place.kind === "user") {
    if (place.group) chain.push(`group-${place.group}`);
    chain.push(key);
  }
  return chain;
}

/// What a firewall should answer one key for a version: 401 when the key no longer
/// works, else the decision under its place's chain.
export function keyDecision(model, key, target) {
  if (key.revoked) return "refused";
  const place = placeOf(model, key.place);
  if (place.kind === "personal") {
    const owner = model.people.find((p) => p.personal?.id === place.id);
    if (!owner || owner.personal.deleted || owner.loginDeleted) return "refused";
  } else {
    const org = model.orgs.find((o) => o.id === place.org);
    if (!org || org.status === "suspended") return "refused";
  }
  return decide(chainOf(model, key.place).map((k) => model.layers[k]), target);
}

// ---- Self-check ------------------------------------------------------------------------

function selfCheck() {
  const assert = (ok, what) => {
    if (!ok) throw new Error(`pbt-model self-check: ${what}`);
  };
  const L = (kind, fields = {}) => ({ ...emptyLayer(kind), ...fields, allow: { ...emptyLayer(kind).allow, ...fields.allow } });
  const left = { ecosystem: "npm", name: "e2e-left", version: "2.0.0", age: 300 * DAY };
  const fresh = { ecosystem: "npm", name: "e2e-fresh", version: "1.0.0", age: HOUR };
  // C125: an empty chain freezes nothing.
  assert(decide([L("platform"), L("org"), L("user")], fresh) === "allowed", "empty chain allows");
  // A stricter freeze below always applies; a shorter one only with the switch.
  assert(decide([L("platform", { freeze: 0 }), L("org", { freeze: 2 * HOUR })], fresh) === "held", "stricter freeze holds");
  assert(decide([L("platform", { freeze: 2 * HOUR }), L("org", { freeze: 0 })], fresh) === "held", "shorter freeze without the switch");
  assert(decide([L("platform", { freeze: 2 * HOUR, allow: { shorter_freeze: true } }), L("org", { freeze: 0 })], fresh) === "allowed", "shorter freeze with the switch");
  // An exception lifts a block only where every layer above allows exceptions, and only
  // blocks owned at or above its own layer.
  const block = { ecosystem: "npm", name: "e2e-left", what: "version", version: "2.0.0" };
  const exception = { ecosystem: "npm", name: "e2e-left", version: null, lifts: { block: true, freeze: false, osv: false } };
  assert(decide([L("platform", { blocks: [block] }), L("org", { exceptions: [exception] })], left) === "blocked", "exception needs the switch");
  assert(decide([L("platform", { blocks: [block], allow: { exceptions: true } }), L("org", { exceptions: [exception] })], left) === "allowed", "exception lifts");
  assert(decide([L("platform", { allow: { exceptions: true } }), L("org", { exceptions: [exception] }), L("user", { blocks: [block] })], left) === "blocked", "a lower block stays");
  assert(decide([L("platform", { blocks: [{ ...block, what: "package" }] })], { ...left, version: "1.0.0" }) === "blocked", "a package block");
  // check_edit: a shorter freeze, an exception and a grant each need the switch above.
  assert(checkEdit([L("platform", { freeze: DAY })], L("org"), L("org", { freeze: 0 })) === "shorter_freeze", "shorter freeze refused");
  assert(checkEdit([L("platform", { freeze: DAY })], L("org"), L("org", { freeze: 2 * DAY })) === null, "longer freeze accepted");
  assert(checkEdit([L("platform")], L("org"), L("org", { exceptions: [exception] })) === "exceptions", "exception refused");
  assert(checkEdit([L("platform")], L("org"), L("org", { allow: { exceptions: true } })) === "exceptions", "grant not held");
  assert(checkEdit([], L("platform"), L("platform", { freeze: 0, allow: { exceptions: true } })) === null, "the platform may do anything");
  // C47: a stored looser value stays saveable after the switch above went off.
  const kept = L("org", { exceptions: [exception] });
  assert(checkEdit([L("platform")], kept, structuredClone(kept)) === null, "unchanged kept settings pass");
  console.log("pbt-model self-check: ok");
}

if (import.meta.url === `file://${process.argv[1]}`) selfCheck();
