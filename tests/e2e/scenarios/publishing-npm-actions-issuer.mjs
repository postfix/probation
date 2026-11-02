import npmActions from "./publishing-npm-actions.mjs";

export const meta = {
  id: "E2E-publishing-npm-actions-issuer",
  title: "organization-issued npm selected-registry actions",
  suites: ["release"],
};

export default (h) => npmActions(h, { organizationIssued: true });
