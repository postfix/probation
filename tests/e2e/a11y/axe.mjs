// A11Y-axe and the automatable part of A11Y-keyboard (03 § Test plan, C84: WCAG 2.2 AA).
// The nightly e2e suite runs it on the e2e stack (scenarios/a11y-axe.mjs, D11); by hand:
//
//   node tests/e2e/a11y/axe.mjs --slice 5
//   node tests/e2e/a11y/axe.mjs --slice 6
//   node tests/e2e/a11y/axe.mjs --slice 7
//
// against a portal on a database seeded by crates/probation-server/tests/seed.sql (by hand:
// the portal served with crates/probation-server/tests/portal.toml at PORTAL_URL). With
// A11Y_PROXY set, Chromium reaches the portal through that HTTP proxy (the e2e bridge)
// and accepts the e2e CA's certificate.
// The slice 6 run turns on an authenticator for oli@acme.test and the slice 7 run one for
// admin@probation.test, so run each once per seeded database, after the slice 5 run.
// Playwright Chromium signs in through the real sign-in form with the seeded logins,
// visits every page and state of the slice, runs axe-core on each, and walks each page
// with the Tab key: the focus order follows the DOM, every focused control shows a focus
// indicator, the skip link reaches the main content, and Tab leaves the page at its end
// (no trap). Exits non-zero on any axe violation or keyboard failure. What axe and these
// checks cannot judge is listed as manual in evidence/tdd-slice-5.md.

import { createHmac } from 'node:crypto';
import { chromium } from 'playwright';
import { AxeBuilder } from '@axe-core/playwright';

const BASE = process.env.PORTAL_URL ?? 'http://127.0.0.1:8088';
const PASSWORD = process.env.A11Y_PASSWORD ?? 'a11y test passphrase';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

const slice = (() => {
  const at = process.argv.indexOf('--slice');
  return at >= 0 ? process.argv[at + 1] : undefined;
})();
if (slice !== '5' && slice !== '6' && slice !== '7') {
  console.error('usage: node axe.mjs --slice 5|6|7');
  process.exit(2);
}

const results = [];

/** axe-core and the keyboard walk on the page as it is now. */
async function audit(page, name) {
  const axe = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const keyboard = await walk(page);
  results.push({ name, url: page.url(), violations: axe.violations, keyboard });
}

/** A short, stable name for an element. */
function describeIn(page, handle) {
  return page.evaluate((el) => {
    if (!el || el === document.body) return 'body';
    const label = el.getAttribute('aria-label') || el.id || el.getAttribute('name') || el.textContent.trim().slice(0, 30);
    return `${el.tagName.toLowerCase()}[${label}]`;
  }, handle);
}

/** Tab through the page from the top and check order, visible focus, skip link and traps. */
async function walk(page) {
  const problems = [];
  const expected = await page.evaluate(() => {
    const selector = 'a[href], button:not([disabled]), input:not([disabled]):not([type=hidden]), select:not([disabled]), textarea:not([disabled]), [tabindex]';
    const positive = [...document.querySelectorAll('[tabindex]')].filter((el) => el.tabIndex > 0);
    const seenRadio = new Set();
    const order = [];
    for (const el of document.querySelectorAll(selector)) {
      if (el.tabIndex < 0 || el.getClientRects().length === 0) continue;
      if (el.type === 'radio') {
        // One stop per radio group: the checked one, or the first.
        if (seenRadio.has(el.name)) continue;
        const group = [...document.querySelectorAll(`input[type=radio][name="${el.name}"]`)];
        const stop = group.find((radio) => radio.checked) ?? group[0];
        seenRadio.add(el.name);
        if (stop !== el) {
          order.push(stop);
          continue;
        }
      }
      order.push(el);
    }
    const name = (el) => {
      const label = el.getAttribute('aria-label') || el.id || el.getAttribute('name') || el.textContent.trim().slice(0, 30);
      return `${el.tagName.toLowerCase()}[${label}]`;
    };
    return { order: order.map(name), positive: positive.map(name) };
  });
  for (const el of expected.positive) problems.push(`positive tabindex on ${el}`);

  await page.evaluate(() => {
    document.activeElement?.blur();
    window.scrollTo(0, 0);
  });
  const visited = [];
  for (let n = 0; n < expected.order.length; n += 1) {
    await page.keyboard.press('Tab');
    const focused = await page.evaluateHandle(() => document.activeElement);
    const name = await describeIn(page, focused);
    const visible = await page.evaluate((el) => {
      if (!el || el === document.body) return false;
      const style = getComputedStyle(el);
      const outline = style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0;
      const box = el.getBoundingClientRect();
      return outline && box.width > 0 && box.height > 0 && box.right > 0 && box.bottom > 0;
    }, focused);
    if (!visible) problems.push(`no visible focus indicator on ${name}`);
    visited.push(name);
  }
  if (JSON.stringify(visited) !== JSON.stringify(expected.order)) {
    problems.push(`tab order ${JSON.stringify(visited)} differs from the DOM order ${JSON.stringify(expected.order)}`);
  }
  // At the end, Tab leaves the page's controls: nothing traps the focus.
  await page.keyboard.press('Tab');
  const after = await describeIn(page, await page.evaluateHandle(() => document.activeElement));
  if (expected.order.length > 0 && after === expected.order[expected.order.length - 1]) {
    problems.push(`focus is trapped on ${after}`);
  }
  // The skip link moves the next Tab into the main content.
  await page.evaluate(() => document.activeElement?.blur());
  await page.keyboard.press('Tab');
  const first = await page.evaluate(() => document.activeElement?.classList.contains('skip'));
  if (!first) {
    problems.push('the first Tab stop is not the skip link');
  } else {
    await page.keyboard.press('Enter');
    await page.keyboard.press('Tab');
    const inMain = await page.evaluate(() => {
      const el = document.activeElement;
      return Boolean(el && document.querySelector('main')?.contains(el)) || !document.querySelector('main a, main button, main input, main select');
    });
    if (!inMain) problems.push('the skip link does not lead into the main content');
  }
  await page.evaluate(() => document.activeElement?.blur());
  return problems;
}

async function go(page, path) {
  const answer = await page.goto(new URL(path, BASE).href);
  return answer?.status();
}

/** Signs in through the real form. */
async function signIn(page, email, password = PASSWORD) {
  await go(page, '/signin');
  await page.locator('form[action="/signin"] input[name=email]').fill(email);
  await page.locator('form[action="/signin"] input[name=password]').fill(password);
  await Promise.all([page.waitForLoadState('load'), page.locator('form[action="/signin"] button[type=submit]').click()]);
}

async function submit(page, selector) {
  await Promise.all([page.waitForLoadState('load'), page.locator(selector).click()]);
}

/** RFC 6238: the 6-digit code of a base32 secret at time `at` (seconds). */
function totp(base32, at = Date.now() / 1000) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of base32.replace(/[\s=]/g, '').toUpperCase()) {
    bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  }
  const bytes = Buffer.from(bits.match(/.{8}/g).map((byte) => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30)));
  const mac = createHmac('sha1', bytes).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

/** Turns the signed-in login's authenticator on from Account settings. */
async function turnTotpOn(page) {
  await go(page, '/account');
  await submit(page, 'form[action="/account/totp/setup"] button[type=submit]');
  const key = await page.locator('#totp-key').textContent();
  await page.locator('#code').fill(totp(key));
  await submit(page, 'form[action="/account/totp/enable"] button[type=submit]');
}

/** Every page and state of slice 6: keys, policy, activity, organisation, audit log. */
async function slice6(browser) {
  // Mia, a member: her keys, a key shown once, a refused name, her own policy layer,
  // her activity, her organisation page with her leave request, and the audit log.
  {
    const context = await browser.newContext({ ignoreHTTPSErrors: Boolean(process.env.A11Y_PROXY) });
    const page = await context.newPage();
    await signIn(page, 'mia@acme.test');
    await go(page, '/keys');
    await audit(page, 'API keys (member)');
    if (await go(page, '/certificates/setup') !== 200) throw new Error('member setup page did not open');
    await audit(page, 'Package client setup (member)');
    await go(page, '/keys');
    await page.locator('#key-name').fill('a11y laptop');
    await submit(page, 'form[action="/keys"] button[type=submit]');
    if (!(await page.locator('#new-key').count())) throw new Error('no key was shown once');
    await audit(page, 'API keys: new key shown once');
    await page.locator('#key-name').fill('   ');
    await submit(page, 'form[action="/keys"] button[type=submit]');
    await audit(page, 'API keys: error');
    await go(page, '/policy');
    await audit(page, 'Policy (own layer)');
    await go(page, '/activity');
    await audit(page, 'Activity (member)');
    await go(page, '/org');
    await audit(page, 'Organisation (member, leave request waiting)');
    await go(page, '/audit');
    await audit(page, 'Audit log (member: not shown)');
    await context.close();
  }

  // Bob, a group admin (no authenticator needed, C24): his group's policy and a refused
  // looser freeze, and its log.
  {
    const context = await browser.newContext({ ignoreHTTPSErrors: Boolean(process.env.A11Y_PROXY) });
    const page = await context.newPage();
    await signIn(page, 'bob@acme.test');
    await go(page, '/policy');
    await audit(page, 'Policy (group layer)');
    await page.locator('#freeze').fill('1');
    await submit(page, 'form:has(input[name=action][value=save]) button[type=submit]');
    await audit(page, 'Policy: looser change refused');
    await go(page, '/keys');
    await audit(page, 'API keys (group admin)');
    await go(page, '/audit');
    await audit(page, 'Audit log (group admin)');
    await context.close();
  }

  // Oli, an org admin: an authenticator first (C24), then the organisation page and
  // its states, service keys, the organisation's policy, activity and audit log.
  {
    const context = await browser.newContext({ ignoreHTTPSErrors: Boolean(process.env.A11Y_PROXY) });
    const page = await context.newPage();
    await signIn(page, 'oli@acme.test');
    await turnTotpOn(page);
    await go(page, '/org');
    if (!/\/org\/\d+$/.test(page.url())) throw new Error(`/org did not open Acme: ${page.url()}`);
    await audit(page, 'Organisation (org admin)');
    await page.getByRole('link', { name: 'Users and groups' }).click();
    await audit(page, 'Users and groups (org admin)');
    await go(page, '/org');
    await page.locator('#invite-email').fill('erin@acme.test');
    await submit(page, 'form[action$="/invitations"] button[type=submit]');
    await audit(page, 'Organisation: invitation waiting');
    await page.locator('#range-cidr').fill('192.0.2.300/24');
    await submit(page, 'form[action$="/ranges"] button[type=submit]');
    await audit(page, 'Organisation: range refused as invalid');
    await page.locator('#group-name').fill('Data');
    await submit(page, 'form[action$="/groups"] button[type=submit]');
    await page.locator('a[href$="/delete"]').first().click();
    await page.waitForLoadState('load');
    await audit(page, 'Delete a group: confirmation');
    await go(page, '/invite?token=not-a-token');
    await audit(page, 'Invitation link expired');
    await go(page, '/keys');
    await page.locator('#service-name').fill('Frontend devices');
    await submit(page, 'form[action="/keys/service"] button[type=submit]');
    await audit(page, 'API keys (org admin, service key shown once)');
    await go(page, '/policy');
    await audit(page, 'Policy (organisation layer)');
    await go(page, '/activity');
    await audit(page, 'Activity (org admin)');
    await go(page, '/audit');
    await audit(page, 'Audit log (org admin)');
    await context.close();
  }

  // Pat, a personal account only; and the global admin's audit log.
  for (const [email, pages] of [
    ['pat@home.test', [['/keys', 'API keys (personal account)'], ['/policy', 'Policy (personal account)'], ['/activity', 'Activity (personal account, empty)'], ['/org', 'Organisation (no organisation)'], ['/audit', 'Audit log (personal account)']]],
    ['admin@probation.test', [['/audit', 'Audit log (global admin)']]],
  ]) {
    const context = await browser.newContext({ ignoreHTTPSErrors: Boolean(process.env.A11Y_PROXY) });
    const page = await context.newPage();
    await signIn(page, email);
    for (const [path, name] of pages) {
      await go(page, path);
      await audit(page, name);
    }
    await context.close();
  }
}

/** Every page and state of slice 7: global admin, fleet, the organisation page's
 * automation tokens and blocklist file, and the suspended banner. */
async function slice7(browser) {
  // The global admin: an authenticator first (C24), then /admin and /fleet and their states.
  {
    const context = await browser.newContext({ ignoreHTTPSErrors: Boolean(process.env.A11Y_PROXY) });
    const page = await context.newPage();
    await signIn(page, 'admin@probation.test');
    await turnTotpOn(page);
    await go(page, '/admin');
    await audit(page, 'Global admin');
    await go(page, '/admin/private-egress');
    await audit(page, 'Private egress approvals');
    await go(page, '/admin');
    await page.locator('#token-name').fill('a11y platform tool');
    await submit(page, 'form[action="/admin/tokens"] button[type=submit]');
    if (!(await page.locator('#new-token').count())) throw new Error('no platform token was shown once');
    await audit(page, 'Global admin: platform token shown once');
    // The server's own refusal, as a browser that skips the form's `min` check gets it.
    await page.locator('#retention-activity').fill('6');
    await page.evaluate(() => { document.querySelector('form[action="/admin/retention"]').noValidate = true; });
    await submit(page, 'form[action="/admin/retention"] button[type=submit]');
    await audit(page, 'Global admin: retention refused');
    for (const [selector, name] of [
      ['a[href^="/admin/orgs/"][href$="/suspend"]', 'Global admin: suspend an organisation?'],
      ['a[href^="/admin/personal/"][href$="/delete"]', 'Global admin: delete a personal account?'],
    ]) {
      await go(page, '/admin');
      await page.locator(selector).first().click();
      await page.waitForLoadState('load');
      await audit(page, name);
    }
    await go(page, '/fleet');
    await audit(page, 'Fleet (unhealthy, halted rollout)');
    await page.locator('#register-name').fill('fw-a11y-3');
    await page.locator('#register-sources').fill('127.0.0.1/32');
    await submit(page, 'form[action="/fleet/register"] button[type=submit]');
    if (!(await page.locator('#new-token').count())) throw new Error('no firewall token was shown once');
    await audit(page, 'Fleet: firewall registered, token shown once');
    await page.locator('input[name=firewall]').first().check();
    await page.locator('#settings-toml').fill('listen = "0.0.0.0:1"');
    await submit(page, 'form[action="/fleet/settings"] button[type=submit]');
    await audit(page, 'Fleet: settings refused');
    // Inside Acme as an org admin: its automation tokens and blocklist file.
    await go(page, '/admin');
    await page.locator('a[href^="/org/"]').first().click();
    await page.waitForLoadState('load');
    await audit(page, 'Organisation (global admin inside it)');
    const orgPath = new URL(page.url()).pathname;
    await go(page, `${orgPath}/registries`);
    await audit(page, 'Package registries');
    await go(page, `${orgPath}/certificates`);
    await audit(page, 'Enterprise certificate settings');
    await go(page, `${orgPath}/certificates/lookup`);
    await audit(page, 'Find member certificates');
    await go(page, orgPath);
    await page.locator('#token-name').fill('a11y org tool');
    await submit(page, 'form[action$="/automation"] button[type=submit]');
    if (!(await page.locator('#new-token').count())) throw new Error('no org token was shown once');
    await audit(page, 'Organisation: automation token shown once');
    await context.close();
  }

  // Ivy, a member of the suspended Initech: read-only with the banner (C64).
  {
    const context = await browser.newContext({ ignoreHTTPSErrors: Boolean(process.env.A11Y_PROXY) });
    const page = await context.newPage();
    await signIn(page, 'ivy@initech.test');
    await go(page, '/keys');
    if (!(await page.getByText('is suspended by the service operator').count())) {
      throw new Error('no suspension banner');
    }
    await audit(page, 'API keys (suspended organisation)');
    await go(page, '/org');
    await audit(page, 'Organisation (suspended, member)');
    await context.close();
  }
}

const browser = await chromium.launch(process.env.A11Y_PROXY ? { proxy: { server: process.env.A11Y_PROXY } } : {});
try {
  if (slice === '6') {
    await slice6(browser);
  } else if (slice === '7') {
    await slice7(browser);
  } else {
  // Signed out.
  {
    const context = await browser.newContext({ ignoreHTTPSErrors: Boolean(process.env.A11Y_PROXY) });
    const page = await context.newPage();
    await go(page, '/signin');
    await audit(page, 'Sign in');
    await signIn(page, 'ana@acme.test', 'not the right password');
    await audit(page, 'Sign in: wrong email or password');
    await go(page, '/signup');
    await audit(page, 'Sign up');
    await go(page, '/reset');
    await audit(page, 'Forgot password');
    await page.locator('form[action="/reset"] input[name=email]').fill('pat@home.test');
    await submit(page, 'form[action="/reset"] button[type=submit]');
    await audit(page, 'Forgot password: sent');
    await go(page, '/reset/confirm?token=not-a-token');
    await audit(page, 'Reset link expired');
    await go(page, '/verify-email?token=not-a-token');
    await audit(page, 'Confirmation link expired');
    await page.locator('form[action="/verify-email/resend"] input[name=email]').fill('someone@home.test');
    await submit(page, 'form[action="/verify-email/resend"] button[type=submit]');
    await audit(page, 'Check your email');
    await context.close();
  }

  // Account settings for each role.
  for (const [email, role] of [
    ['admin@probation.test', 'global admin'],
    ['ana@acme.test', 'org admin with a personal account'],
    ['bob@acme.test', 'group admin'],
    ['mia@acme.test', 'member'],
    ['gus@globex.test', 'Globex org admin'],
    ['pat@home.test', 'personal account only'],
  ]) {
    const context = await browser.newContext({ ignoreHTTPSErrors: Boolean(process.env.A11Y_PROXY) });
    const page = await context.newPage();
    await signIn(page, email);
    if (!page.url().endsWith('/account')) throw new Error(`${email} did not reach /account: ${page.url()}`);
    await audit(page, `Account settings (${role})`);
    await context.close();
  }

  // Pat: a password error, then the authenticator set-up, the code step and its error.
  {
    const context = await browser.newContext({ ignoreHTTPSErrors: Boolean(process.env.A11Y_PROXY) });
    const page = await context.newPage();
    await signIn(page, 'pat@home.test');
    await page.locator('#current').fill('not my password at all');
    await page.locator('#new').fill('another long passphrase');
    await page.locator('#again').fill('another long passphrase');
    await submit(page, 'form[action="/account/password"] button[type=submit]');
    await audit(page, 'Account settings: password error');
    await go(page, '/account');
    await submit(page, 'form[action="/account/totp/setup"] button[type=submit]');
    await audit(page, 'Set up an authenticator');
    const key = await page.locator('#totp-key').textContent();
    const codes = (await page.locator('#backup-codes').textContent()).split(/\s+/).filter(Boolean);
    await page.locator('#code').fill(totp(key));
    await submit(page, 'form[action="/account/totp/enable"] button[type=submit]');
    await audit(page, 'Account settings: authenticator on');
    await submit(page, 'form[action="/signout"] button[type=submit]');
    await signIn(page, 'pat@home.test');
    await audit(page, 'Authenticator code');
    await page.locator('#code').fill('000000');
    await submit(page, 'form[action="/totp"] button[type=submit]');
    await audit(page, 'Authenticator code: wrong');
    await page.locator('#code').fill(codes[0]);
    await submit(page, 'form[action="/totp"] button[type=submit]');
    if (!page.url().endsWith('/account')) throw new Error(`the backup code did not sign in: ${page.url()}`);
    // Leave the seed as it was.
    await submit(page, 'form[action="/account/totp/disable"] button[type=submit]');
    await context.close();
  }

  // Ana deletes and restores her personal account; her login stays in Acme.
  {
    const context = await browser.newContext({ ignoreHTTPSErrors: Boolean(process.env.A11Y_PROXY) });
    const page = await context.newPage();
    await signIn(page, 'ana@acme.test');
    await page.locator('#confirm-personal').fill('delete');
    await submit(page, 'form[action="/account/personal/delete"] button[type=submit]');
    await audit(page, 'Account settings: personal account deleted');
    await submit(page, 'form[action="/account/personal/restore"] button[type=submit]');
    await context.close();
  }

  // A deleted login (C94) and an unconfirmed one (C41).
  for (const [email, name, path] of [
    ['del@home.test', 'This login was deleted', '/deleted'],
    ['new@home.test', 'Confirm your email', '/verify-email'],
  ]) {
    const context = await browser.newContext({ ignoreHTTPSErrors: Boolean(process.env.A11Y_PROXY) });
    const page = await context.newPage();
    await signIn(page, email);
    if (!page.url().endsWith(path)) throw new Error(`${email} did not reach ${path}: ${page.url()}`);
    await audit(page, name);
    await context.close();
  }
  }
} finally {
  await browser.close();
}

let failed = 0;
for (const { name, url, violations, keyboard } of results) {
  const bad = violations.length + keyboard.length;
  failed += bad;
  console.log(`${bad === 0 ? 'PASS' : 'FAIL'} ${name} (${url})`);
  for (const violation of violations) {
    console.log(`  axe ${violation.id} (${violation.impact}): ${violation.help}`);
    for (const node of violation.nodes) console.log(`    ${node.target.join(' ')}`);
  }
  for (const problem of keyboard) console.log(`  keyboard: ${problem}`);
}
console.log(`A11Y slice ${slice}: ${results.length} pages, ${failed} problems`);
process.exit(failed === 0 ? 0 : 1);
