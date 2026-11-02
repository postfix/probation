// A personal-only login can recover from the account deletion screen in Chromium.
import { browserAs } from "../harness/ops.mjs";

export const meta = {
  id: "E2E-portal-login-deletion-browser",
  title: "personal login deletion and restoration in Chromium",
  suites: ["pr", "nightly", "release"],
};

export default async function portalLoginDeletionBrowser(h) {
  const person = await h.signUp({ kind: "personal" });
  const page = await (await browserAs(h, person)).newPage();
  await page.goto("/account");
  await page.locator("#confirm-personal").fill("delete");
  await page.getByRole("button", { name: "Delete personal account" }).click();
  h.expect(new URL(page.url()).pathname === "/signin",
    "deleting the only personal account signs the login out");

  await page.getByLabel("Email", { exact: true }).fill(person.email);
  await page.getByLabel("Password", { exact: true }).fill(person.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  h.expect(await page.getByRole("button", { name: "Restore login" }).count() === 1,
    "the deleted login offers restoration after authentication");
  await page.getByRole("button", { name: "Restore login" }).click();
  h.expect(await page.getByRole("heading", { name: "Account settings" }).count() === 1,
    "the login and its personal account are restored in Chromium");
}
