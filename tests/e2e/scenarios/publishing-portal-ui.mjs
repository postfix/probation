// The administrator reaches and edits publishing settings through Chromium.
import { browserAs } from "../harness/ops.mjs";
import { issueIssuerLeafFor } from "../harness/issuer-setup.mjs";

export const meta = {
  id: "E2E-publishing-portal-ui",
  title: "publishing settings through the portal UI",
  suites: ["pr", "nightly", "release"],
};

export default async function publishingPortalUi(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const page = await (await browserAs(h, admin)).newPage();
  await page.goto("/org");
  const orgPath = new URL(page.url()).pathname;
  h.expect(await page.getByRole("link", { name: "Package registries" }).count() === 1,
    "the organisation page links to package registries");
  await page.getByRole("link", { name: "Package registries" }).click();
  h.expect(await page.getByRole("heading", { name: "Package registries" }).count() === 1,
    "the registry catalog opens in the browser");
  await page.getByLabel("Name", { exact: true }).fill("Browser npm");
  await page.getByLabel("Ecosystem").selectOption("npm");
  await page.getByLabel("HTTPS target", { exact: true }).fill("https://registry.npmjs.org/");
  await page.getByRole("button", { name: "Add registry" }).click();
  h.expect(await page.locator("li").filter({ hasText: "Browser npm" }).count() === 1,
    "the new registry appears in the browser catalog");
  const registry = page.locator("li").filter({ hasText: "Browser npm" });
  await registry.getByLabel("Skip age delay").check();
  await registry.getByRole("button", { name: "Save trust" }).click();
  h.expect(await page.locator("li").filter({ hasText: "Browser npm" }).getByLabel("Skip age delay").isChecked(),
    "the trust setting survives a browser form submission");
  await page.locator("li").filter({ hasText: "Browser npm" }).getByLabel("Read-only Authorization").fill("Bearer browser-secret");
  await page.locator("li").filter({ hasText: "Browser npm" }).getByRole("button", { name: "Save credential" }).click();
  h.expect(await page.locator("li").filter({ hasText: "Browser npm" }).getByLabel("Read-only Authorization (configured)").count() === 1,
    "the registry read credential is saved without showing its value");
  await page.locator("li").filter({ hasText: "Browser npm" }).getByLabel("Deletion HTTPS origin").fill("https://tarballs.example.test");
  await page.locator("li").filter({ hasText: "Browser npm" }).getByLabel("Path prefix").fill("/packages");
  await page.locator("li").filter({ hasText: "Browser npm" }).getByRole("button", { name: "Approve deletion destination" }).click();
  h.expect(await page.locator("li").filter({ hasText: "tarballs.example.test/packages" }).count() === 1,
    "the approved deletion destination appears in the catalog");
  await page.locator("li").filter({ hasText: "tarballs.example.test/packages" }).getByRole("button", { name: "Remove destination" }).click();
  h.expect(await page.locator("li").filter({ hasText: "tarballs.example.test/packages" }).count() === 0,
    "the approved deletion destination can be removed");
  await page.getByLabel("Saved HTTPS target").fill("https://registry.npmjs.org/");
  await page.getByLabel("Allowed CIDR").fill("10.30.0.0/24");
  await page.getByRole("button", { name: "Request operator approval" }).click();
  await page.goto(orgPath);
  h.expect(await page.getByRole("link", { name: "Enterprise certificates" }).count() === 1,
    "the organisation page links to enterprise certificates");
  h.expect(await page.getByRole("link", { name: "Package client setup" }).count() === 1,
    "the organisation page links to member package setup");
  await page.getByRole("link", { name: "Package client setup" }).click();
  h.expect(await page.getByRole("button", { name: "Download my setup bundle" }).count() === 1,
    "members can reach package client setup");
  const [bundle] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Download my setup bundle" }).click(),
  ]);
  h.expect(bundle.suggestedFilename() === "probation-setup.sh",
    "browser setup issues a downloadable client bundle");
  await bundle.path();
  await page.goto(orgPath);
  await page.getByLabel("Find one member's package certificate by email").fill(admin.email);
  await page.getByRole("button", { name: "Find certificate" }).click();
  h.expect(await page.getByRole("button", { name: "Revoke this certificate" }).count() === 1,
    "the newly issued certificate is visible to its organisation admin");
  await page.getByRole("button", { name: "Revoke this certificate" }).click();
  await page.goto(`${orgPath}/certificates/lookup?email=${encodeURIComponent(admin.email)}`);
  h.expect(await page.getByRole("button", { name: "Revoke this certificate" }).isDisabled(),
    "the browser shows the certificate as revoked");
  await page.goto(orgPath);
  await page.getByRole("link", { name: "Enterprise certificates" }).click();
  h.expect(await page.getByRole("heading", { name: "Enterprise certificates" }).count() === 1,
    "admins can reach enterprise certificate settings");
  const orgId = Number(orgPath.split("/").pop());
  const sample = await issueIssuerLeafFor(h, orgId, admin.email);
  await page.getByLabel("Expected OCSP AIA URL").fill(sample.ocspUrl);
  await page.getByLabel("CA certificate PEM").fill(sample.rootPem);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByLabel("Sample leaf and issuer chain PEM").fill(sample.leafPem);
  await page.getByRole("button", { name: "Check good sample" }).click();
  await h.fakes.revokeEnterprise("a", sample.id);
  await page.goto(`${orgPath}/certificates`);
  await page.getByLabel("Sample leaf and issuer chain PEM").fill(sample.leafPem);
  await page.getByRole("button", { name: "Check committed revocation and activate" }).click();
  h.expect(h.stack.sql(`SELECT kind FROM registry_certificate_providers WHERE org_id = ${orgId}`) === "organisation",
    "the enterprise issuer activates after the browser checks committed revocation");
  const operatorPage = await (await browserAs(h, h.operator)).newPage();
  await operatorPage.goto("/admin");
  h.expect(await operatorPage.getByRole("link", { name: "Private egress approvals" }).count() === 1,
    "the global admin page links to private egress approvals");
  await operatorPage.getByRole("link", { name: "Private egress approvals" }).click();
  const request = operatorPage.locator("li").filter({ hasText: "10.30.0.0/24" });
  h.expect(await request.count() === 1, "the private destination request reaches the operator queue");
  await request.getByRole("button", { name: "Approve" }).click();
  h.expect(await operatorPage.locator("li").filter({ hasText: "10.30.0.0/24" }).getByText("approved").count() === 1,
    "the operator approval persists in the browser");
  await page.goto(`${orgPath}/registries`);
  await page.locator("li").filter({ hasText: "Browser npm" }).getByRole("button", { name: "Remove", exact: true }).click();
  h.expect(await page.locator("li").filter({ hasText: "Browser npm" }).count() === 0,
    "the registry can be removed in the browser");
}
