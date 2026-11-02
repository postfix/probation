// E2E-019 Password reset and account-takeover defences
// (docs/plans/e2e-coverage/00-inventory.md §3).
//
// A user with an authenticator and a key is signed in in browser A. In browser B they
// ask for a reset twice: the older link is dead, the newer one refuses a leaked
// password and two different passwords, then takes a good one. Browser A and every
// other session are signed out, the old password fails, the new one still asks for the
// authenticator code, and the key still installs. The used link is refused (410).
//
// Takeover: an attacker signs up with the victim's address and their own password and
// keeps that session open; opening the mail changes nothing, then the victim chooses a
// password and the attacker's session ends (F7). A victim whose address was squatted that way
// (unconfirmed) takes it back with a reset: the attacker's session ends, the attacker's
// password stops working, and the victim gets in.

import { forgetMail, freshMailWindow } from "../harness/people.mjs";

export const meta = {
  id: "E2E-019",
  title: "Password reset and account-takeover defences",
  suites: ["nightly", "release"],
};

const RESET_SUBJECT = "Choose a new password";

export default async function passwordReset(h) {
  const { expect } = h;
  freshMailWindow(h);
  const user = await h.signUp({ kind: "org" });
  await h.enableTotp(user);
  const { npmrc } = await h.createKey(user.portal, "laptop");
  const path = (page) => new URL(page.url()).pathname;
  const text = (page) => page.locator("main").innerText();
  const signIn = async (page, who, password) => {
    await h.browserSignIn(page, { email: who, password });
    return path(page);
  };

  // Browser A: signed in with the code.
  const a = await (await h.browser()).newPage();
  expect((await signIn(a, user.email, user.password)) === "/totp", "browser A is asked for the code");
  await a.fill("#code", await user.auth.code());
  await a.click("form[action='/totp'] button[type=submit]");
  expect(path(a) === "/account", `browser A is signed in: ${a.url()}`);

  // Browser B: "Forgot your password?", twice; the newer link cancels the older.
  const b = await (await h.browser()).newPage();
  const askReset = async (page, email) => {
    await forgetMail(h, email);
    await page.goto("/signin");
    await page.click("a[href='/reset']");
    await page.fill("#email", email);
    await page.click("form[action='/reset'] button[type=submit]");
    expect((await text(page)).includes("If an account uses this address, we sent it a link"), `reset asked:\n${await text(page)}`);
    return h.mail.link(email, /^\/reset\/confirm$/, { subject: RESET_SUBJECT });
  };
  const older = await askReset(b, user.email);
  const newer = await askReset(b, user.email);
  let answer = await b.goto(older.toString());
  expect(answer.status() === 410 && (await text(b)).includes("Link expired"), `the older link is dead: ${answer.status()}`);
  answer = await b.goto(newer.toString());
  expect(answer.status() === 200 && (await text(b)).includes("Choose a new password"), `the newer link works: ${answer.status()}`);
  const choose = async (page, first, second = first) => {
    await page.fill("#new", first);
    await page.fill("#again", second);
    await page.click("form[action='/reset/confirm'] button[type=submit]");
    return text(page);
  };
  const leaked = `leaked ${h.unique("pw")}`;
  await h.fakes.leakPassword(leaked);
  expect((await choose(b, leaked)).includes("This password has appeared in a known data leak"), "a leaked password is refused");
  expect((await choose(b, `one ${h.unique("pw")}`, `two ${h.unique("pw")}`)).includes("The two passwords do not match."), "two different passwords are refused");
  const fresh = `new ${h.unique("pw")} battery`;
  expect((await choose(b, fresh)).includes("Your password is changed. Sign in with your new password."), "a good password is taken");

  // Every session ended: browser A, and the API session from the sign-up.
  await a.goto("/account");
  expect(path(a) === "/signin", `browser A is signed out: ${a.url()}`);
  answer = await user.portal.get("/account");
  expect(answer.status === 303 && answer.location === "/signin", `the other session is signed out: ${answer.status} ${answer.location}`);
  // The old password fails; the new one still asks for the authenticator code.
  expect((await signIn(b, user.email, user.password)) === "/signin" && (await text(b)).includes("That email and password do not match"), "the old password fails");
  expect((await signIn(b, user.email, fresh)) === "/totp", "the new password still asks for the authenticator code");
  await b.fill("#code", await user.auth.code());
  await b.click("form[action='/totp'] button[type=submit]");
  expect(path(b) === "/account", `signed in with the new password and a code: ${b.url()}`);
  // The key does not care.
  const run = h.npm("install e2e-left@1.0.0 --no-audit --no-fund", { npmrc });
  expect(run.status === 0, `the key still installs: ${run.status}\n${run.stderr}`);
  // The used link: 410, opened or posted.
  answer = await b.goto(newer.toString());
  expect(answer.status() === 410, `the used link: ${answer.status()}`);
  const anyone = new h.Portal();
  const form = await anyone.get("/reset");
  const posted = await anyone.post("/reset/confirm", { csrf: h.hidden(form.body, "csrf"), token: newer.searchParams.get("token"), new: `x ${fresh}`, again: `x ${fresh}` });
  expect(posted.status === 410, `posting the used link: ${posted.status}`);

  // Takeover: the attacker signs up with the victim's address and keeps the session.
  const victim = `${h.unique("victim")}@example.com`;
  const attacker = { portal: new h.Portal(), password: `attacker ${h.unique("pw")} pass` };
  const squat = async (email) => {
    answer = await attacker.portal.submit("/signup", "/signup", { email, password: attacker.password, kind: "personal" });
    expect(answer.status === 200 && answer.body.includes("Check your email"), `the attacker's sign-up: ${answer.status}`);
    answer = await attacker.portal.submit("/signin", "/signin", { email, password: attacker.password });
    expect(answer.status === 303, `the attacker signs in: ${answer.status}`);
    answer = await attacker.portal.get("/account");
    expect(answer.status === 303 && answer.location === "/verify-email", `unconfirmed, the attacker reaches nothing: ${answer.status} ${answer.location}`);
  };
  await squat(victim);
  // Opening the link alone does not confirm the address or end the attacker's session.
  const c = await (await h.browser()).newPage();
  await c.goto((await h.mail.link(victim, /^\/verify-email$/, { subject: "Confirm your email" })).toString());
  expect((await text(c)).includes("Choose your password to confirm your email address"), "the link asks the victim to choose a password");
  answer = await attacker.portal.get("/account");
  expect(answer.status === 303 && answer.location === "/verify-email", "opening the link did not confirm the attacker's login");
  const victimPassword = `victim ${h.unique("pw")} staple`;
  await c.fill("#new", victimPassword);
  await c.fill("#again", victimPassword);
  await c.click("form[action='/verify-email'] button[type=submit]");
  expect((await text(c)).includes("Your email address is confirmed"), "the victim confirmed the address with their own password");
  answer = await attacker.portal.get("/account");
  expect(answer.status === 303 && answer.location === "/signin", `the attacker's session ended: ${answer.status} ${answer.location ?? "page"}`);
  answer = await new h.Portal().submit("/signin", "/signin", { email: victim, password: attacker.password });
  expect(answer.status === 422, "the attacker's original password no longer signs in");
  expect((await signIn(c, victim, victimPassword)) === "/account", "the victim signs in with the password chosen from the mail");

  // A squatted, unconfirmed address taken back with a reset.
  const victim2 = `${h.unique("victim")}@example.com`;
  attacker.portal = new h.Portal();
  await squat(victim2);
  const d = await (await h.browser()).newPage();
  await d.goto("/reset");
  await d.fill("#email", victim2);
  await d.click("form[action='/reset'] button[type=submit]");
  await d.goto((await h.mail.link(victim2, /^\/reset\/confirm$/, { subject: RESET_SUBJECT })).toString());
  const mine = `mine ${h.unique("pw")} again`;
  expect((await choose(d, mine)).includes("Your password is changed"), "the victim sets a password from the reset mail");
  answer = await attacker.portal.get("/verify-email");
  expect(answer.status === 303 && answer.location === "/signin", `the attacker's session ended: ${answer.status} ${answer.location}`);
  answer = await new h.Portal().submit("/signin", "/signin", { email: victim2, password: attacker.password });
  expect(answer.status === 422, `the attacker's password fails: ${answer.status}`);
  // The victim signs in, confirming the address from the mail if asked to.
  let where = await signIn(d, victim2, mine);
  if (where === "/verify-email") {
    await d.goto((await h.mail.link(victim2, /^\/verify-email$/, { subject: "Confirm your email" })).toString());
    expect((await text(d)).includes("Choose your password to confirm your email address"), "the victim chooses a password from the confirmation mail");
    await d.fill("#new", mine);
    await d.fill("#again", mine);
    await d.click("form[action='/verify-email'] button[type=submit]");
    expect((await text(d)).includes("Your email address is confirmed"), "the victim confirms the address");
    where = await signIn(d, victim2, mine);
  }
  expect(where === "/account", `the victim is in: ${d.url()}`);
}
