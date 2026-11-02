// Smoke the main portal areas through the same browser controls users operate.
import { browserAs } from "../harness/ops.mjs";

export const meta = {
  id: "E2E-portal-areas-browser",
  title: "account, keys, policy, organisation, activity, audit and operator areas in Chromium",
  suites: ["pr", "nightly", "release"],
};

export default async function portalAreasBrowser(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const page = await (await browserAs(h, admin)).newPage();
  const operator = await (await browserAs(h, h.operator)).newPage();

  await operator.goto("/policy/platform-1");
  await operator.getByLabel("Allow package exceptions").check();
  await operator.getByRole("button", { name: "Save changes" }).click();

  await page.goto("/account");
  h.expect(await page.getByRole("heading", { name: "Account settings" }).count() === 1,
    "account settings opens in Chromium");

  await page.getByRole("link", { name: "API keys" }).click();
  await page.getByLabel("New key name").fill("browser smoke");
  await page.getByRole("button", { name: "Create key" }).click();
  h.expect(await page.locator("#new-key").count() === 1,
    "key secret is shown once after browser creation");
  await page.getByRole("button", { name: "Revoke browser smoke" }).click();
  h.expect(await page.getByRole("button", { name: "Revoke browser smoke" }).count() === 0,
    "the revoked key disappears from the active list");

  await page.getByRole("link", { name: "Policy", exact: true }).click();
  await page.getByLabel("Hold new versions for").fill("2");
  await page.getByLabel("Unit", { exact: true }).selectOption("days");
  await page.getByRole("group", { name: "OSV malicious-package check" }).getByRole("radio", { name: "On: block them" }).check();
  await page.getByRole("button", { name: "Save changes" }).click();
  h.expect(await page.getByLabel("Hold new versions for").inputValue() === "2"
    && await page.getByLabel("Unit", { exact: true }).inputValue() === "days",
    "the release-age freeze persists after browser submission");
  h.expect(await page.getByRole("group", { name: "OSV malicious-package check" }).getByRole("radio", { name: "On: block them" }).isChecked(),
    "the OSV block setting persists after browser submission");
  await page.getByRole("group", { name: "Add a block" }).getByLabel("Package name").fill("browser-smoke-package");
  await page.getByRole("button", { name: "Add block" }).click();
  h.expect(await page.getByRole("button", { name: /Remove the block on browser-smoke-package/ }).count() === 1,
    "a policy block appears after browser submission");
  await page.getByRole("button", { name: /Remove the block on browser-smoke-package/ }).click();
  h.expect(await page.getByRole("button", { name: /Remove the block on browser-smoke-package/ }).count() === 0,
    "the policy block can be removed in the browser");
  await page.getByRole("group", { name: "Add an exception" }).getByLabel("Package name").fill("browser-smoke-package");
  await page.getByRole("group", { name: "Add an exception" }).getByLabel("Blocklist").check();
  await page.getByRole("button", { name: "Add exception" }).click();
  h.expect(await page.getByRole("button", { name: "Remove the exception on browser-smoke-package" }).count() === 1,
    "a policy exception appears after browser submission");
  await page.getByRole("button", { name: "Remove the exception on browser-smoke-package" }).click();
  h.expect(await page.getByRole("button", { name: "Remove the exception on browser-smoke-package" }).count() === 0,
    "the policy exception can be removed in the browser");

  await page.getByRole("link", { name: "Organisation", exact: true }).click();
  await page.getByLabel("Group name").fill("browser group");
  await page.getByRole("button", { name: "Create group" }).click();
  h.expect(await page.getByRole("link", { name: "Delete the browser group group" }).count() === 1,
    "a new group appears in the organisation area");
  await page.getByLabel("New name for browser group").fill("browser renamed");
  await page.getByRole("button", { name: "Rename" }).click();
  h.expect(await page.getByRole("link", { name: "Delete the browser renamed group" }).count() === 1,
    "the group rename persists");
  await page.getByRole("link", { name: "Delete the browser renamed group" }).click();
  h.expect(await page.getByRole("heading", { name: "Delete the browser renamed group?" }).count() === 1,
    "group deletion has a confirmation page");
  await page.getByRole("button", { name: "Delete group" }).click();
  h.expect(await page.getByRole("link", { name: "Delete the browser renamed group" }).count() === 0,
    "the deleted group is gone");

  for (const [link, heading] of [["Activity", "Activity"], ["Audit log", "Audit log"]]) {
    await page.getByRole("link", { name: link, exact: true }).click();
    h.expect(await page.getByRole("heading", { name: heading, exact: true }).count() === 1,
      `${heading} opens in Chromium`);
  }

  await page.getByRole("link", { name: "Account", exact: true }).click();
  await page.getByRole("button", { name: "Add a personal account" }).click();
  h.expect(await page.getByRole("button", { name: "Delete personal account" }).count() === 1,
    "the personal account can be added in the browser");
  await page.locator("#confirm-personal").fill("delete");
  await page.getByRole("button", { name: "Delete personal account" }).click();
  h.expect(await page.getByRole("button", { name: "Restore personal account" }).count() === 1,
    "personal deletion offers restoration");
  await page.getByRole("button", { name: "Restore personal account" }).click();
  h.expect(await page.getByRole("button", { name: "Delete personal account" }).count() === 1,
    "the personal account restores in the browser");

  for (const [path, heading] of [["/admin", "Global admin"], ["/fleet", "Fleet"]]) {
    await operator.goto(path);
    h.expect(await operator.getByRole("heading", { name: heading, exact: true }).count() === 1,
      `${heading} opens for the operator in Chromium`);
  }
  await operator.goto("/admin");
  await operator.locator("#limit-personal-rate").fill("17");
  await operator.getByRole("button", { name: "Save personal account limits" }).click();
  h.expect(await operator.locator("#limit-personal-rate").inputValue() === "17",
    "operator account limits persist after browser submission");

  await operator.goto("/fleet");
  await operator.locator("#register-name").fill("browser firewall");
  await operator.locator("#register-sources").fill("203.0.113.10/32");
  await operator.getByRole("button", { name: "Register firewall" }).click();
  h.expect(await operator.locator("#new-token").count() === 1,
    "fleet registration shows its token once");
  await operator.getByLabel("Select browser firewall").check();
  await operator.locator("#settings-toml").fill("sync_interval_seconds = 60");
  await operator.getByRole("button", { name: "Save and apply" }).click();
  h.expect((await operator.getByRole("heading", { name: /Saved .*: Applying/ }).count()) >= 1,
    "the fleet settings rollout appears in the browser");
  await operator.getByLabel("Type browser firewall to retire it").fill("browser firewall");
  await operator.getByRole("button", { name: "Retire browser firewall" }).click();
  h.expect(await operator.getByRole("button", { name: "Retire browser firewall" }).count() === 0,
    "a retired firewall no longer offers the retire action");

  await operator.goto("/admin");
  await operator.locator("#retention-activity").fill("91");
  await operator.locator("#retention-audit").fill("366");
  await operator.locator('form[action="/admin/retention"] button').click();
  h.expect(await operator.locator("#retention-activity").inputValue() === "91"
    && await operator.locator("#retention-audit").inputValue() === "366",
  "operator retention settings persist");
  await operator.getByRole("link", { name: `Suspend ${admin.org}` }).click();
  h.expect(await operator.getByRole("heading", { name: `Suspend ${admin.org}?` }).count() === 1,
    "organisation suspension asks for confirmation");
  await operator.getByRole("button", { name: "Suspend", exact: true }).click();
  h.expect(await operator.getByRole("row").filter({ hasText: admin.org }).getByText("Suspended").count() === 1,
    "the operator can suspend the organisation");
  await operator.getByRole("button", { name: `Re-activate ${admin.org}` }).click();
  h.expect(await operator.getByRole("row").filter({ hasText: admin.org }).getByText("Active").count() === 1,
    "the operator can reactivate the organisation");
}
