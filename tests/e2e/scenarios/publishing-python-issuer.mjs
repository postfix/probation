import publishingPython from "./publishing-python.mjs";

export const meta = {
  id: "E2E-publishing-python-issuer",
  title: "organization-issued pip and Twine selected-registry workflows",
  suites: ["release"],
};

export default (h) => publishingPython(h, { organizationIssued: true });
