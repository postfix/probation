// E2E-publishing-oci-service: `skopeo copy` (a push) and a pull through the shared service (row 24, class W like `conan upload`, `mvn deploy`,
// `gem push`, `cargo publish` and `dotnet nuget push`). The service org owns an OCI registry whose target is the fake Docker Hub; skopeo
// logs in with Basic (the registry's own token flow, through the firewall's `/v2/token`: the credential goes to the registry's allowed
// realm only), pushes a REAL image (the blob upload's POST, PATCH and PUT and the manifest PUT), and the firewall forwards each with that
// token and nothing of the service key, rewriting every Location into its own namespace. A write without a credential is answered with a
// Bearer challenge before any upstream request; a stranger's read of the pushed image is held by the cooldown.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";

export const meta = { id: "E2E-publishing-oci-service", title: "skopeo push and pull through the shared service", suites: ["release"], stack: "own" };

const CA = "SSL_CERT_FILE=/e2e/ca/ca.pem";

export default async function ociServicePublishing(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  h.expect((await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "Service OCI", ecosystem: "oci", target_url: "https://registry-1.docker.io/",
  })).status === 303, "service OCI registry added");
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const id = listed.body.match(/<li>(\d+) Service OCI oci/)?.[1];
  h.expect(id, "the OCI registry has an ID");
  // The registry redirects a blob to its storage host: the descriptor declares it, and only it.
  const archive = await admin.portal.submit(`/org/${org}/registries`, `/org/${org}/registries/${id}/archive-origin`, { archive_origin: "https://production.cloudfront.docker.com/" });
  h.expect(archive.status === 303, `the storage origin is declared: ${archive.status}`);
  await h.editPolicy(admin.portal, { action: "save", freeze: "7", unit: "days", osv: "on" });
  const issued = await admin.portal.submit("/keys", "/keys/service", { name: "oci-service", attach: "org" });
  h.expect(issued.status === 200, "service policy key issued");
  const serviceKey = h.between(issued.body, '<code id="new-key">', "</code>");
  h.stack.exec("firewall-standalone", ["sh", "-c", "umask 077; cat > /var/lib/probation/service.key; chmod 600 /var/lib/probation/service.key"], { input: `${serviceKey}\n`, check: true });
  const configPath = join(h.stack.work, "firewall-standalone.toml");
  writeFileSync(configPath, `allowed_peer_cidrs = ["${h.stack.net}.10/32"]\n${readFileSync(configPath, "utf8")}\n[service_policy]\nserver_url = "https://sync.e2e.test"\nservice_key_file = "/var/lib/probation/service.key"\n`);
  h.restart("firewall-standalone");
  await h.stack.firewallReady("fw-standalone");
  const service = "fw-standalone.e2e.test";
  await h.waitFor("the OCI registry is loaded", async () => [200, 401].includes((await h.request(`https://${service}/v2/`)).status), { timeout: 30_000 });

  const writes = async () => await h.fakes.ociWrites();
  const output = (run) => `${run.stdout}\n${run.stderr}`;

  // No credential: every write is answered with the challenge the client waits for, nothing reaches the registry.
  const before = (await writes()).length;
  const requestsBefore = (await h.fakes.ociSeen()).length;
  for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
    const answer = await h.request(`https://${service}/v2/team/pushed/blobs/uploads/`, { method, body: "x", headers: { connection: "close" } });
    h.expect(answer.status === 401 && /^Bearer realm="https:\/\/fw-standalone\.e2e\.test\/v2\/token"/.test(answer.headers["www-authenticate"] ?? ""), `${method} without a credential is challenged with this firewall's token endpoint: ${answer.status} ${answer.headers["www-authenticate"]}`);
  }
  h.expect((await writes()).length === before && (await h.fakes.ociSeen()).length === requestsBefore, "a challenged write made no upstream request");

  // The REAL tiny image of fixtures/oci as a skopeo `dir:` layout in the client container (its binary files travel as base64), pushed through
  // the service with the owner's login (the registry's own token flow).
  const fixture = (name) => readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "oci", name));
  const [manifest, config, layer] = ["hello-1-manifest", "hello-1-config", "hello-1-layer"].map(fixture);
  const hex = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const blobs = { [hex(config)]: config, [hex(layer)]: layer };
  const files = { "img/version": "Directory Transport Version: 1.1\n", "img/manifest.json": manifest.toString() };
  for (const [name, bytes] of Object.entries(blobs)) files[`img/${name}.b64`] = bytes.toString("base64");
  const decode = Object.keys(blobs).map((name) => `base64 -d img/${name}.b64 > img/${name} && rm img/${name}.b64`).join(" && ");
  let run = h.client("client-oci", `export ${CA}; ${decode} && skopeo copy --dest-creds e2e-owner:e2e-pass dir:img docker://${service}/team/pushed:v1`, { files });
  h.expect(run.status === 0, `skopeo pushes through the service: ${run.status}\n${output(run).slice(-800)}`);
  const sent = (await writes()).filter((w) => w.authorization === "Bearer tok-e2e-owner");
  const paths = sent.map((w) => `${w.method} ${w.path.split("?")[0]}`);
  h.expect(paths.some((p) => p.startsWith("POST /v2/team/pushed/blobs/uploads/")) && sent.some((w) => w.method === "PATCH" || (w.method === "PUT" && w.path.includes("digest="))) && paths.includes("PUT /v2/team/pushed/manifests/v1"), `the registry received the upload and the manifest with the owner's token: ${paths.join(", ")}`);
  const tokens = await h.fakes.ociTokens();
  h.expect(tokens.some((t) => t.basic && t.scope.includes("repository:team/pushed:pull,push")), `the owner's Basic credential was exchanged at the registry's realm for the push scope: ${JSON.stringify(tokens.slice(-4))}`);

  // The pushed image is on the registry; the pusher's existence checks work, a stranger meets the cooldown.
  const stranger = await h.request(`https://${service}/v2/team/pushed/manifests/v1`, { headers: { authorization: "Bearer tok-someone-else", connection: "close" } });
  h.expect(stranger.status === 403, `another caller meets the cooldown: ${stranger.status}`);
  const head = await h.request(`https://${service}/v2/team/pushed/manifests/v1`, { method: "HEAD", headers: { authorization: "Bearer tok-e2e-owner", connection: "close" } });
  h.expect(head.status === 200, `the depositor's own existence check meets no hold: ${head.status}`);

  // The registry's refusal (401 for the anonymous token on a push) is relayed as the challenge; the service key never reaches the registry.
  const all = await writes();
  h.expect(all.every((w) => !String(w.authorization ?? "").includes(serviceKey)), "the service key was never forwarded");
  const seenAll = await h.fakes.ociSeen();
  h.expect(seenAll.every((r) => !String(r.authorization ?? "").includes(serviceKey)), "the service key never reached any host of the hub");
  const count = seenAll.length;
  const wrong = await h.request(`https://${service}/registry/oci/999999/v2/team/pushed/blobs/uploads/`, { method: "POST", body: "x", headers: { authorization: "Bearer tok-e2e-owner", connection: "close" } });
  h.expect(wrong.status === 404 && (await h.fakes.ociSeen()).length === count, `an unknown OCI registry answers 404 with no upstream call: ${wrong.status}`);
}
