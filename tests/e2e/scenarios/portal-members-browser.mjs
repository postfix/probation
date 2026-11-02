// Membership and network-lock changes through the signed-in portal controls.
import { browserAs } from "../harness/ops.mjs";

export const meta = {
  id: "E2E-portal-members-browser",
  title: "member role and group, removal, and network-lock approval in Chromium",
  suites: ["pr", "nightly", "release"],
};

export default async function portalMembersBrowser(h) {
  const admin = await h.signUp({ kind: "org" });
  const member = await h.signUp({ kind: "personal" });
  await h.enableTotp(admin);
  const page = await (await browserAs(h, admin)).newPage();
  await page.goto("/org");
  const orgPath = new URL(page.url()).pathname;

  await page.getByLabel("Group name").fill("reviewers");
  await page.getByRole("button", { name: "Create group" }).click();
  await page.getByRole("group", { name: "Invite someone" }).getByLabel("Email address").fill(member.email);
  await page.getByRole("button", { name: "Send invitation" }).click();
  const invitation = await h.mail.link(member.email, /^\/invite$/, { subject: "invitation" });
  await h.enableTotp(member);
  const memberPage = await (await browserAs(h, member)).newPage();
  await memberPage.goto(invitation.toString());
  await memberPage.getByRole("button", { name: "Accept" }).click();
  h.expect(new URL(memberPage.url()).pathname === orgPath,
    "the invited member joins the organisation through Chromium");
  const deniedUsers = await memberPage.goto(`${orgPath}/users`);
  h.expect(deniedUsers.status() === 403, "a regular member cannot open organisation user controls");
  await memberPage.goto(orgPath);
  await memberPage.getByRole("button", { name: `Ask to leave ${admin.org}` }).click();
  h.expect(await memberPage.getByRole("button", { name: "Cancel my request" }).count() === 1,
    "the member can request to leave");
  await memberPage.getByRole("button", { name: "Cancel my request" }).click();
  h.expect(await memberPage.getByRole("button", { name: `Ask to leave ${admin.org}` }).count() === 1,
    "the member can cancel a leave request");

  await page.goto(orgPath);
  const row = page.getByRole("row").filter({ hasText: member.email });
  await row.getByLabel(`Group of ${member.email}`).selectOption({ label: "reviewers" });
  await row.getByRole("button", { name: "Move", exact: true }).click();
  h.expect(await page.getByRole("row").filter({ hasText: member.email }).getByLabel(`Group of ${member.email}`).inputValue() !== "none",
    "the member's group persists");
  await page.getByRole("row").filter({ hasText: member.email }).getByLabel(`Role of ${member.email}`).selectOption("group_admin");
  await page.getByRole("row").filter({ hasText: member.email }).getByRole("button", { name: "Change role" }).click();
  h.expect(await page.getByRole("row").filter({ hasText: member.email }).getByLabel(`Role of ${member.email}`).inputValue() === "group_admin",
    "the member's role persists");
  const loginId = Number(h.stack.sql(`SELECT login_id FROM sign_in_methods WHERE email = '${member.email}'`));
  h.expect(Number.isInteger(loginId) && loginId > 0, "the fixture member has a login");
  h.stack.sql(`DELETE FROM personal_accounts WHERE login_id = ${loginId}`);
  await page.goto(orgPath);
  const resetAuthenticator = page.getByRole("row").filter({ hasText: member.email })
    .getByRole("button", { name: `Reset authenticator of ${member.email}` });
  h.expect(await resetAuthenticator.count() === 1,
    "an org admin can reset an org-only member's authenticator");
  await resetAuthenticator.click();
  h.expect(h.stack.sql(`SELECT count(*) FROM totp WHERE login_id = ${loginId}`) === "0",
    "the authenticator reset takes effect for the member");
  const cancelledEmail = `${h.unique("cancel")}@example.com`;
  await page.getByRole("group", { name: "Invite someone" }).getByLabel("Email address").fill(cancelledEmail);
  await page.getByRole("button", { name: "Send invitation" }).click();
  await page.getByRole("button", { name: `Cancel invitation to ${cancelledEmail}` }).click();
  h.expect(await page.getByRole("button", { name: `Cancel invitation to ${cancelledEmail}` }).count() === 0,
    "the invitation can be cancelled in Chromium");

  await page.getByLabel("IP range").fill("198.51.100.0/24");
  await page.getByRole("button", { name: "Add range" }).click();
  h.expect(await page.getByText("Waiting for operator approval").count() === 1,
    "the network-lock range waits for operator approval");
  const operator = await (await browserAs(h, h.operator)).newPage();
  await operator.goto("/admin");
  await operator.getByRole("button", { name: `Approve the range 198.51.100.0/24 of ${admin.org}` }).click();
  await page.goto(orgPath);
  h.expect(await page.getByRole("row").filter({ hasText: "198.51.100.0/24" }).getByText("Approved").count() === 1,
    "the approved range appears in the organisation page");
  await page.getByRole("button", { name: "Remove the range 198.51.100.0/24" }).click();
  h.expect(await page.getByRole("row").filter({ hasText: "198.51.100.0/24" }).count() === 0,
    "the range is removed through the browser");
  await page.getByLabel("IP range").fill("198.51.101.0/24");
  await page.getByRole("button", { name: "Add range" }).click();
  await operator.goto("/admin");
  const refused = operator.getByRole("row").filter({ hasText: "198.51.101.0/24" });
  await refused.getByLabel("Reason").fill("needs review");
  await refused.getByRole("button", { name: `Refuse the range 198.51.101.0/24 of ${admin.org}` }).click();
  await page.goto(orgPath);
  h.expect(await page.getByText("Refused by operator: needs review").count() === 1,
    "the refusal reason is shown to the organisation");
  await page.getByRole("button", { name: "Resubmit the range 198.51.101.0/24" }).click();
  await operator.goto("/admin");
  await operator.getByRole("button", { name: `Approve the range 198.51.101.0/24 of ${admin.org}` }).click();
  await page.goto(orgPath);
  h.expect(await page.getByRole("row").filter({ hasText: "198.51.101.0/24" }).getByText("Approved").count() === 1,
    "a resubmitted range can be approved");

  await page.getByRole("link", { name: "Users and groups" }).click();
  const managedMember = page.getByRole("row").filter({ hasText: member.email });
  await managedMember.getByRole("button", { name: `Disable package access for ${member.email}` }).click();
  await page.goto(`${orgPath}/users`);
  h.expect(await page.getByRole("row").filter({ hasText: member.email }).getByText("Disabled").count() === 1,
    "the Users panel shows that the member's package access is disabled");
  await page.getByRole("row").filter({ hasText: member.email })
    .getByRole("button", { name: `Find certificates for ${member.email}` }).click();
  h.expect(await page.getByText(`Certificates for ${member.email}`).count() === 1,
    "the Users panel opens the selected member's certificate list");

  await page.goto(orgPath);
  await page.getByRole("button", { name: `Remove ${member.email} from ${admin.org}` }).click();
  h.expect(await page.getByRole("row").filter({ hasText: member.email }).count() === 0,
    "the removed member no longer appears");
}
