// E2E-020 OAuth and company SSO with an OIDC provider
// (docs/plans/e2e-coverage/00-inventory.md §3).
//
// The fake IdP plays Google (the server's [portal.google] provider, at
// accounts.google.com) and an organisation's own OIDC issuer (idp.e2e.test).
//
// - The org admin connects company SSO; the page refuses an http issuer, a shared
//   issuer without a tenant, and another organisation's issuer and client ID.
// - In Chromium: `/o/<organisation>`, the IdP and back (the session cookie survives
//   the cross-site return), a member through SSO, a key, npm install. That session
//   cannot change the login.
// - In Chromium: "Continue with Google" makes a login with no place; it adds a personal
//   account and installs. A password login links Google, signs in with it, removes it;
//   then Google opens a separate login. A method of another login cannot be linked.
// - Refused sign-ins, each with no session: wrong iss, wrong aud, expired, alg none, a
//   key not in the JWKS, a bad signature, no or wrong nonce, the user cancels, a
//   replayed callback, another tenant. A rotated IdP key still signs in.
// - Removal (C128): SSO does not add the removed member back; a new invitation does.
//   An approved leave (C130) does not block SSO, which adds them back.
// - SSO turned off: the SSO member sets a password from a reset mail and signs in.
//
// Not covered here: the nightly happy path against a real IdP (dex), which needs an
// IdP container in the stack.

import { act, accept, freshMailWindow, invite, keyAnswers, memberId, orgId } from "../harness/people.mjs";

export const meta = {
  id: "E2E-020",
  title: "OAuth and company SSO with an OIDC provider, removal and SSO re-join rules",
  suites: ["nightly", "release"],
};

const ISSUER = "https://idp.e2e.test";
const REFUSED = "We could not sign you in that way";

export default async function oauthSso(h) {
  const { expect } = h;
  freshMailWindow(h);
  const [admin, other, linker] = await Promise.all([h.signUp({ kind: "org" }), h.signUp({ kind: "org" }), h.signUp({ kind: "personal" })]);
  await Promise.all([h.enableTotp(admin), h.enableTotp(other)]);
  const org = await orgId(admin.portal);
  const clientId = h.unique("acme-client");
  const sso = (who, id, fields) => who.portal.submit(`/org/${id}`, `/org/${id}/sso`, fields);
  const on = { enabled: "on", issuer: ISSUER, client_id: clientId, allowed_tenant: "", client_secret: "acme-secret" };

  // Company SSO settings, with what the page refuses.
  let answer = await sso(admin, org, { ...on, issuer: "http://idp.e2e.test" });
  expect(answer.status === 409 && answer.body.includes("Enter the issuer as an https URL."), `http issuer: ${answer.status}`);
  answer = await sso(admin, org, { ...on, issuer: "https://accounts.google.com" });
  expect(answer.status === 409 && answer.body.includes("A shared issuer needs the tenant"), `shared issuer without a tenant: ${answer.status}`);
  answer = await sso(admin, org, on);
  expect(answer.status === 303, `SSO on: ${answer.status}\n${answer.body}`);
  answer = await sso(other, await orgId(other.portal), on);
  expect(answer.status === 409 && answer.body.includes("Another organisation already uses this issuer and client ID."), `the same issuer and client in another organisation: ${answer.status}`);
  const page = (await admin.portal.get(`/org/${org}`)).body;
  expect(page.includes(`<code>https://portal.e2e.test/sso/${org}/callback</code>`), "the page shows the redirect address");

  // In Chromium: the organisation's link, the IdP, and back as a member.
  const person = { sub: h.unique("sso-sub"), email: `${h.unique("sso")}@acme.e2e.test` };
  await h.fakes.oidcNext(person);
  const browser = await (await h.browser()).newPage();
  const path = (p) => new URL(p.url()).pathname;
  const text = (p) => p.locator("main").innerText();
  await browser.goto(`/o/${admin.org}`);
  expect(path(browser) === "/account", `signed in through SSO: ${browser.url()}`);
  const places = await browser.locator("#place-switcher option").allTextContents();
  expect(places.length === 1 && places[0] === `${admin.org} (organisation)`, `an SSO session sees only its organisation: ${places}`);
  const ssoKey = await h.browserCreateKey(browser, "sso-laptop");
  let run = h.npm("install e2e-left@1.0.0 --no-audit --no-fund", { npmrc: ssoKey.npmrc });
  expect(run.status === 0, `npm with the SSO member's key: ${run.status}\n${run.stderr}`);
  const listed = (await admin.portal.get(`/org/${org}`)).body;
  expect(listed.includes(`<td>${person.email} <span class="mut">joined through company SSO</span>`), "the member list marks the SSO member");
  await browser.goto("/account");
  await browser.click("form[action='/account/link/google'] button");
  expect((await text(browser)).includes("You signed in through your organisation's SSO."), "an SSO session cannot change the login");

  // "Continue with Google": a login with no place, which adds a personal account.
  const googler = { sub: h.unique("google-sub"), email: `${h.unique("g")}@gmail.e2e.test` };
  await h.fakes.oidcNext(googler);
  const g = await (await h.browser()).newPage();
  await g.goto("/signin");
  await g.click("a[href='/oauth/google/start']");
  expect(path(g) === "/account", `signed in with Google: ${g.url()}`);
  await g.goto("/keys");
  expect((await text(g)).includes("You have no place yet"), "a Google login starts with no place");
  await g.goto("/account");
  await g.click("form[action='/account/personal'] button[type=submit]");
  const googleKey = await h.browserCreateKey(g, "g-laptop");
  run = h.npm("install e2e-left@1.1.0 --no-audit --no-fund", { npmrc: googleKey.npmrc });
  expect(run.status === 0, `npm with the Google login's personal key: ${run.status}\n${run.stderr}`);

  // A password login links Google, signs in with it, and removes it.
  const l = await (await h.browser()).newPage();
  await h.browserSignIn(l, linker);
  const linked = { sub: h.unique("google-sub"), email: linker.email };
  const linkGoogle = async () => {
    await l.goto("/account");
    await l.click("form[action='/account/link/google'] button");
  };
  await h.fakes.oidcNext(googler);
  await linkGoogle();
  expect((await text(l)).includes("That sign-in method belongs to another login."), "another login's method cannot be linked");
  await h.fakes.oidcNext(linked);
  await linkGoogle();
  expect(path(l) === "/account" && (await l.locator("main table").first().innerText()).includes("Google"), "Google is linked");
  const viaGoogle = await (await h.browser()).newPage();
  await viaGoogle.goto("/oauth/google/start");
  expect(path(viaGoogle) === "/account" && (await viaGoogle.locator("header").innerText()).includes(linker.email), "Google opens the linked login");
  await l.goto("/account");
  await l.click("button[aria-label^='Remove Google']");
  expect(!(await l.locator("main table").first().innerText()).includes("Google"), "Google is removed");
  await viaGoogle.goto("/account");
  expect(path(viaGoogle) === "/signin", "removing a method signs out the login's other sessions");
  await viaGoogle.goto("/oauth/google/start");
  await viaGoogle.goto("/keys");
  expect((await text(viaGoogle)).includes("You have no place yet"), "after the removal Google opens a separate, new login");

  // Refused sign-ins through the API, each leaving no session.
  /// One sign-in through the IdP: the callback's answer, and the callback's path.
  const flow = async (portal, start) => {
    const begun = await portal.get(start);
    expect(begun.status === 303, `${start}: ${begun.status}\n${begun.body}`);
    const idp = await h.request(begun.location);
    expect(idp.status === 302, `the IdP: ${idp.status}`);
    const back = new URL(idp.headers.location);
    const done = await portal.get(back.pathname + back.search);
    done.callback = back.pathname + back.search;
    return done;
  };
  const refused = async (what, start, person) => {
    await h.fakes.oidcNext(person);
    const portal = new h.Portal();
    const done = await flow(portal, start);
    expect(done.status === 400 && done.body.includes(REFUSED), `${what}: ${done.status}\n${done.body}`);
    const after = await portal.get("/account");
    expect(after.status === 303 && after.location === "/signin", `${what} leaves no session: ${after.status} ${after.location}`);
  };
  for (const mode of ["wrong_iss", "wrong_aud", "expired", "alg_none", "unknown_kid", "bad_signature", "no_nonce", "wrong_nonce", "cancel"]) {
    await refused(`Google, ${mode}`, "/oauth/google/start", { ...googler, mode });
    await refused(`SSO, ${mode}`, `/sso/${org}/start`, { ...person, mode });
  }
  await h.fakes.oidcNext(person);
  const replayed = new h.Portal();
  answer = await replayed.get((await flow(replayed, `/sso/${org}/start`)).callback);
  expect(answer.status === 400 && answer.body.includes(REFUSED), `a replayed callback: ${answer.status}`);
  // The IdP rotates its signing key: the next sign-in fetches the new JWKS.
  await h.fakes.oidcRotate();
  await h.fakes.oidcNext(person);
  const rotated = new h.Portal();
  answer = await flow(rotated, `/sso/${org}/start`);
  expect(answer.status === 303 && answer.location === "/account", `sign-in after the IdP rotated its key: ${answer.status}`);
  // A required tenant: another tenant is refused, the right one signs in.
  answer = await sso(admin, org, { ...on, allowed_tenant: "acme.e2e.test", client_secret: "" });
  expect(answer.status === 303, `required tenant: ${answer.status}\n${answer.body}`);
  await refused("another tenant", `/sso/${org}/start`, { ...person, hd: "other.e2e.test" });
  await h.fakes.oidcNext({ ...person, hd: "acme.e2e.test" });
  answer = await flow(new h.Portal(), `/sso/${org}/start`);
  expect(answer.status === 303 && answer.location === "/account", `the right tenant: ${answer.status}`);
  answer = await sso(admin, org, { ...on, client_secret: "" });
  expect(answer.status === 303, `tenant cleared: ${answer.status}`);

  // Removal (C128): SSO does not add the member back; the key stops.
  const ssoSignIn = async () => {
    await h.fakes.oidcNext(person);
    const portal = new h.Portal();
    const done = await flow(portal, `/sso/${org}/start`);
    expect(done.status === 303 && done.location === "/account", `SSO sign-in: ${done.status} ${done.location}`);
    return { email: person.email, portal };
  };
  const member = await memberId(admin.portal, org, person.email);
  await act(admin.portal, `/org/${org}`, `/org/members/${member}/remove`);
  await keyAnswers(h, ssoKey.key, 401, { what: "the removed SSO member's key" });
  let again = await ssoSignIn();
  expect((await again.portal.get("/keys")).body.includes("You have no place yet"), "SSO does not add a removed member back");
  expect((await memberId(admin.portal, org, person.email)) === null, "the removed member stays off the list");
  // A new invitation does.
  await accept(again, await invite(h, admin, org, person.email));
  expect((await memberId(admin.portal, org, person.email)) !== null, "a new invitation brings the removed member back");

  // An approved leave (C130) does not block SSO.
  await act(again.portal, `/org/${org}`, `/org/${org}/leave`);
  const leave = (await admin.portal.get(`/org/${org}`)).body.match(new RegExp(`<td>${person.email}</td><td>[^<]*</td><td class="row">\\s*<form method="post" action="/org/leave/(\\d+)/approve"`))?.[1];
  expect(leave, "the leave request is listed");
  await act(admin.portal, `/org/${org}`, `/org/leave/${leave}/approve`);
  expect((await memberId(admin.portal, org, person.email)) === null, "the member left");
  again = await ssoSignIn();
  expect((await memberId(admin.portal, org, person.email)) !== null, "after an approved leave, SSO adds the member back");
  const rejoined = await h.createKey(again.portal, "sso-again");
  await keyAnswers(h, rejoined.key, 200, { what: "the key after re-joining through SSO" });

  // SSO off: the member sets a password from a reset mail and signs in with it.
  answer = await sso(admin, org, { issuer: "", client_id: "", allowed_tenant: "", client_secret: "" });
  expect(answer.status === 303, `SSO off: ${answer.status}`);
  answer = await new h.Portal().get(`/o/${admin.org}`);
  expect(answer.status === 200 && answer.body.includes("<h1>Sign in</h1>"), `/o/<org> without SSO is the sign-in page: ${answer.status}`);
  const reset = new h.Portal();
  answer = await reset.submit("/reset", "/reset", { email: person.email });
  expect(answer.status === 200, `reset asked: ${answer.status}`);
  const link = await h.mail.link(person.email, /^\/reset\/confirm$/, { subject: "Choose a new password" });
  const form = await reset.get(link.pathname + link.search);
  const password = `sso ${h.unique("pw")} member`;
  answer = await reset.post("/reset/confirm", { csrf: h.hidden(form.body, "csrf"), token: link.searchParams.get("token"), new: password, again: password });
  expect(answer.body.includes("Your password is changed"), `password set: ${answer.status}\n${answer.body}`);
  const byPassword = new h.Portal();
  answer = await byPassword.submit("/signin", "/signin", { email: person.email, password });
  expect(answer.status === 303 && answer.location === "/account", `password sign-in: ${answer.status} ${answer.location}`);
  expect((await byPassword.get("/keys")).body.includes(`Your keys in ${admin.org}`), "still a member, by password now");
  expect((await new h.Portal().get("/o/no-such-org-e2e")).body.includes("<h1>Sign in</h1>"), "an unknown organisation link shows the sign-in page");
}
