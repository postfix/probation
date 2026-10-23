// A11Y-axe and the automatable part of A11Y-keyboard (03 § Test plan, C84: WCAG 2.2 AA).
//
//   node crates/probation-server/tests/a11y/axe.mjs --slice 5
//
// against the portal served with tests/portal.toml on a database seeded by tests/seed.sql.
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
if (slice !== '5') {
  console.error('usage: node axe.mjs --slice 5 (slices 6 and 7 add their pages here)');
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

const browser = await chromium.launch();
try {
  // Signed out.
  {
    const context = await browser.newContext();
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
    const context = await browser.newContext();
    const page = await context.newPage();
    await signIn(page, email);
    if (!page.url().endsWith('/account')) throw new Error(`${email} did not reach /account: ${page.url()}`);
    await audit(page, `Account settings (${role})`);
    await context.close();
  }

  // Pat: a password error, then the authenticator set-up, the code step and its error.
  {
    const context = await browser.newContext();
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
    const context = await browser.newContext();
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
    const context = await browser.newContext();
    const page = await context.newPage();
    await signIn(page, email);
    if (!page.url().endsWith(path)) throw new Error(`${email} did not reach ${path}: ${page.url()}`);
    await audit(page, name);
    await context.close();
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
