// A shared registry credential is confined to ordinary reads, including artifacts.
import { orgId } from "../harness/people.mjs";
import { hidden } from "../harness/net.mjs";

const PROBE = `
import https from "node:https";
import { readFileSync } from "node:fs";
const home = process.env.HOME;
const request = https.get(process.argv[2], {
  ca: readFileSync("/e2e/ca/ca.pem"),
  cert: readFileSync(home + "/.config/probation/client-cert.pem"),
  key: readFileSync(home + "/.config/probation/client-key.pem"),
}, (response) => {
  const chunks = [];
  response.on("data", (chunk) => chunks.push(chunk));
  response.on("end", () => console.log(JSON.stringify({ status: response.statusCode,
    body: Buffer.concat(chunks).toString() })));
});
request.on("error", (error) => { console.error(error); process.exitCode = 2; });
`;

export const meta = {
  id: "E2E-publishing-private-read",
  title: "shared registry credential is used for private reads",
  suites: ["release"],
};

export default async function privateRead(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const page = await admin.portal.get(`/org/${org}/registries`);
  const added = await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(page.body, "csrf"), name: "Private npm", ecosystem: "npm",
    target_url: "https://registry-b.e2e.test/", read_authorization: "Bearer e2e-read",
  });
  h.expect(added.status === 303, `private registry setup: ${added.status}`);
  const listed = await admin.portal.get(`/org/${org}/registries`);
  h.expect(!listed.body.includes("e2e-read"), "the admin catalog does not display the credential");
  const registry = listed.body.match(/<li>(\d+) Private npm/)?.[1];
  h.expect(registry, "private registry gets a selected ID");

  const setup = await admin.portal.get("/certificates/setup");
  const bundle = await admin.portal.post("/certificates/setup", { csrf: hidden(setup.body, "csrf") });
  h.expect(bundle.status === 200, `member setup bundle: ${bundle.status}`);
  const installed = h.stack.exec("client-npm", ["sh"], { input: bundle.body });
  h.expect(installed.status === 0, `certificate installed: ${installed.stderr}`);

  const name = h.unique("read-private-package");
  await h.fakes.publishNpmB({ name, version: "1.0.0", ageSeconds: 400 * 86_400,
    files: { "marker.txt": "private registry artifact" } });
  const probe = (url) => {
    const result = h.client("client-npm", `node probe.mjs '${url}'`, { files: { "probe.mjs": PROBE } });
    h.expect(result.status === 0, `private read probe: ${result.stderr}`);
    return JSON.parse(result.stdout.trim());
  };
  const base = `https://fw1.e2e.test/registry/npm/${registry}/`;
  const metadata = probe(`${base}${name}`);
  h.expect(metadata.status === 200, `shared credential opens private metadata: ${metadata.status}`);
  const tarball = JSON.parse(metadata.body).versions["1.0.0"].dist.tarball;
  h.expect(new URL(tarball).pathname.startsWith(`/registry/npm/${registry}/artifacts/`),
    "private artifact stays behind the selected registry URL");
  const artifact = probe(tarball);
  h.expect(artifact.status === 200 && artifact.body.length > 0,
    `shared credential opens private artifact: ${artifact.status}`);
  const upstream = await h.fakes.requests("registry-b.e2e.test");
  const packageReads = upstream.filter((request) => request.path.includes(name));
  h.expect(packageReads.some((request) => request.credential === "other"),
    "private metadata or artifact fetch uses the shared read credential");
  h.expect(packageReads.every((request) => request.credential !== "developer-owner"),
    "an ordinary read does not send the developer token");

  const rotate = async (read_authorization) => {
    const catalog = await admin.portal.get(`/org/${org}/registries`);
    return admin.portal.post(`/org/${org}/registries/${registry}/read-credential`, {
      csrf: hidden(catalog.body, "csrf"), read_authorization,
      ...(read_authorization ? {} : { clear: "on" }),
    });
  };
  const other = h.unique("read-private-rotated");
  await h.fakes.publishNpmB({ name: other, version: "1.0.0", ageSeconds: 400 * 86_400 });
  h.expect((await rotate("Bearer e2e-denied")).status === 303, "admin can replace the saved credential");
  h.expect(probe(`${base}${other}`).status !== 200,
    "the next certificate admission uses the replaced credential");
  h.expect((await rotate("Bearer e2e-read")).status === 303, "admin can restore the saved credential");
  h.expect(probe(`${base}${other}`).status === 200,
    "the restored credential opens a private package on the next request");
  h.expect((await rotate("")).status === 303, "admin can clear the saved credential");
  const third = h.unique("read-private-cleared");
  await h.fakes.publishNpmB({ name: third, version: "1.0.0", ageSeconds: 400 * 86_400 });
  h.expect(probe(`${base}${third}`).status !== 200,
    "clearing the credential stops new private reads");
}
