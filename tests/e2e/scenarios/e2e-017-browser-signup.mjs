// E2E-017 Self-service sign-up to install, in a real browser with real mail
// (docs/plans/e2e-coverage/00-inventory.md §3).
//
// In Chromium, through the TLS gateway: the sign-up form refuses a leaked password and,
// with the range API down, asks to try again (and sends no mail either time). Then an
// organisation signs up; the confirmation mail goes from the server's SMTP sender and
// outbox loop through STARTTLS to the mail sink; its link is built from base_url. The
// session cookie is Secure, HttpOnly and SameSite=Lax, and every page carries the CSP.
// The admin turns the authenticator on (a wrong code first gives a new key; the QR code
// loads under the CSP), signs out, signs in with a code, then with a backup code, which
// works once. A key from the keys page installs with npm and pip. Then a personal
// account does the same, without the authenticator.

export const meta = {
  id: "E2E-017",
  title: "Self-service sign-up to install in Chromium with real mail (organisation and personal)",
  suites: ["pr", "nightly", "release"],
};

import { freshMailWindow } from "../harness/people.mjs";

const MAIL = "http://mail.e2e.test:8025/api/v1";

export default async function browserSignup(h) {
  const { expect } = h;
  freshMailWindow(h);
  const context = await h.browser();
  const page = await context.newPage();
  // The CSP violations Chromium reports, and every portal answer's CSP header.
  const violations = [];
  page.on("console", (message) => {
    if (/Content Security Policy/i.test(message.text())) violations.push(message.text());
  });
  page.on("response", (answer) => {
    if (answer.url().startsWith(h.portalUrl) && answer.request().resourceType() === "document") {
      const csp = answer.headers()["content-security-policy"] ?? "";
      if (!csp.includes("default-src 'self'")) violations.push(`no CSP on ${answer.url()}: ${csp}`);
    }
  });
  const text = () => page.locator("main").innerText();
  const mailsTo = async (email) => (await h.request(`${MAIL}/search?query=${encodeURIComponent(`to:"${email}"`)}`)).json().messages_count;

  const email = `${h.unique("founder")}@example.com`;
  const password = `e2e ${h.unique("pass")} horse`;
  const org = h.unique("Org");
  const fillSignup = async (pw) => {
    await page.goto("/signup");
    await page.fill("#email", email);
    await page.fill("#password", pw);
    await page.check("input[name=kind][value=org]");
    await page.fill("#org_name", org);
    await page.click("form[action='/signup'] button[type=submit]");
  };

  // A leaked password is refused on the form.
  await fillSignup("leaked-password-e2e");
  expect((await text()).includes("This password has appeared in a known data leak"), `leaked password:\n${await text()}`);
  // The range API down: the check fails closed and asks to try again.
  await h.fakes.faults([{ host: "api.pwnedpasswords.com", mode: "status", status: 503 }]);
  await fillSignup(password);
  expect((await text()).includes("We could not check this password just now. Please try again."), `range API down:\n${await text()}`);
  await h.fakes.faults([]);
  expect((await mailsTo(email)) === 0, "no mail went out for a refused sign-up");

  // The sign-up, the mail from the sink, the confirmation and the sign-in.
  await h.browserSignUp(page, { kind: "org", email, password, org });
  const mail = await h.mail.latest(email, { subject: "Confirm your email address" });
  const link = mail.text.match(/https?:\/\/\S+/)?.[0];
  expect(link?.startsWith("https://portal.e2e.test/verify-email?token="), `the link is built from base_url: ${link}`);
  expect(new URL(page.url()).pathname === "/account", `signed in at /account: ${page.url()}`);
  const session = (await context.cookies()).find((cookie) => cookie.httpOnly);
  expect(session?.secure && session.httpOnly && session.sameSite === "Lax", `session cookie: ${JSON.stringify(session)}`);
  const placeLabel = await page.locator("#place-switcher option[selected]").textContent();
  expect(placeLabel === `${org} (organisation)`, `the new organisation is the place: ${placeLabel}`);

  // The authenticator: a wrong code first gives a new key; the QR code loads.
  await page.click("form[action='/account/totp/setup'] button[type=submit]");
  const firstKey = await page.locator("#totp-key").textContent();
  await page.fill("#code", "000000");
  await page.click("form[action='/account/totp/enable'] button[type=submit]");
  expect((await text()).includes("Set up an authenticator"), "a wrong code stays on the set-up page");
  const key = await page.locator("#totp-key").textContent();
  expect(key !== firstKey, "a wrong code gives a new key");
  const qr = await page.locator("img.qr").evaluate((img) => img.complete && img.naturalWidth > 0);
  expect(qr, "the QR code image loads under the CSP");
  const backup = (await page.locator("#backup-codes").textContent()).split("\n").map((c) => c.trim()).filter(Boolean);
  expect(backup.length === 10, `10 backup codes: ${backup}`);
  const auth = new h.Authenticator(key);
  await page.fill("#code", await auth.code());
  await page.click("form[action='/account/totp/enable'] button[type=submit]");
  expect((await text()).includes("Authenticator app: on"), `authenticator on:\n${await text()}`);

  const signOut = () => page.click("header form[action='/signout'] button");
  const signInWith = async (code) => {
    await signOut();
    await h.browserSignIn(page, { email, password });
    expect(new URL(page.url()).pathname === "/totp", `asked for a code: ${page.url()}`);
    await page.fill("#code", code);
    await page.click("form[action='/totp'] button[type=submit]");
  };
  await signInWith(await auth.code());
  expect(new URL(page.url()).pathname === "/account", `signed in with a code: ${page.url()}`);
  await signInWith(backup[0]);
  expect(new URL(page.url()).pathname === "/account", `signed in with a backup code: ${page.url()}`);
  await signInWith(backup[0]);
  expect((await text()).includes("That code is wrong"), "a backup code works once");
  await page.fill("#code", await auth.code());
  await page.click("form[action='/totp'] button[type=submit]");
  expect(new URL(page.url()).pathname === "/account", `then a code: ${page.url()}`);

  // A key from the keys page, with npm and with pip.
  const lines = await h.browserCreateKey(page, "laptop");
  let run = h.npm("install e2e-left@1.0.0 --no-audit --no-fund && node -p \"require('e2e-left/package.json').version\"", { npmrc: lines.npmrc });
  expect(run.status === 0 && run.stdout.trim().endsWith("1.0.0"), `npm with the organisation's key: ${run.status}\n${run.stdout}\n${run.stderr}`);
  run = h.pip("install --no-cache-dir e2e-left==1.0.0 && python -c \"import importlib.metadata as m; print(m.version('e2e-left'))\"", { pipConf: lines.pipConf });
  expect(run.status === 0 && run.stdout.trim().endsWith("1.0.0"), `pip with the organisation's key: ${run.status}\n${run.stdout}\n${run.stderr}`);

  // The same as a personal account, in a fresh browser.
  const personal = await (await h.browser()).newPage();
  await h.browserSignUp(personal, { kind: "personal" });
  const label = await personal.locator("#place-switcher option[selected]").textContent();
  expect(label === "Personal account", `the personal account is the place: ${label}`);
  const own = await h.browserCreateKey(personal, "home");
  run = h.npm("install e2e-right@1.0.0 --no-audit --no-fund && node -p \"require('e2e-left/package.json').version\"", { npmrc: own.npmrc });
  expect(run.status === 0 && run.stdout.trim().endsWith("1.1.0"), `npm with the personal key: ${run.status}\n${run.stdout}\n${run.stderr}`);
  run = h.pip("install --no-cache-dir e2e-left==1.1.0", { pipConf: own.pipConf });
  expect(run.status === 0, `pip with the personal key: ${run.status}\n${run.stdout}\n${run.stderr}`);

  expect(violations.length === 0, `CSP problems:\n${violations.join("\n")}`);
}
