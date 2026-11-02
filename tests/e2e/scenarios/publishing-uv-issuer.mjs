import publishingUv from "./publishing-uv.mjs";

export const meta = {
  id: "E2E-publishing-uv-issuer",
  title: "organization-issued uv selected-registry workflows",
  suites: ["release"],
};

export default (h) => publishingUv(h, { organizationIssued: true });
