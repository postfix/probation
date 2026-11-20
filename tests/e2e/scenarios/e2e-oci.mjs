// E2E-oci: OCI images (Docker Hub shaped) through a managed firewall (row 24; docs/operations.md "OCI clients").
//
// The fake Docker Hub (fixtures/fakes/oci.mjs) answers as registry-1.docker.io, auth.docker.io and production.cloudfront.docker.com and
// serves the REAL tiny images of fixtures/oci. skopeo (containers/image, the registry client podman and CRI-O share) in the client
// container reads through firewall-1 with the key as the password of its login: it asks the firewall's own `/v2/token`, which answers the
// key itself as the token. The firewall asks the hub for its own anonymous token (the key never leaves), follows the blob's 307 to the
// storage host without a credential, and judges the digest of the exact manifest bytes it was given.
//
// 1. Under a 7-day freeze a young digest is HELD and nothing but the manifest was asked of the hub.
// 2. The policy releases it (a shorter freeze): the image is copied exactly (manifest digest and layer verified), the storage host saw no
//    credential and no token request carried the firewall key.
// 3. A block on a repository and on a tag is refused before the hub is asked anything.
// 4. A tag list is served and a managed firewall refuses every write verb.
// Activity shows the refusals; the firewall's decision log names them.

import { activityRow, changePlatform, policyPost } from "../harness/portal-steps.mjs";

export const meta = {
  id: "E2E-oci",
  title: "OCI through a managed firewall (token flow, digest identity, held then released, blob redirect without credentials, blocks, writes refused)",
  suites: ["pr", "nightly", "release"],
};

const CA = "SSL_CERT_FILE=/e2e/ca/ca.pem";

export default async function oci(h) {
  const { expect } = h;
  const fw1 = h.firewalls.fw1;
  const one = await h.fakes.publishOci({ repo: "team/app", tag: "v1", image: "hello-1" });
  const two = await h.fakes.publishOci({ repo: "team/app", tag: "v2", image: "hello-2" });
  await h.fakes.publishOci({ repo: "team/blocked", tag: "v1", image: "hello-1" });
  const foreign = await h.fakes.publishOciForeign({ repo: "win/base", tag: "ltsc", image: "hello-1" });

  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const { key } = await h.createKey(admin.portal, "oci-ci");
  const since = new Date();
  const skopeo = (args, extra = "") => h.client("client-oci", `export ${CA}; skopeo ${args} ${extra}`);
  const inspect = (ref) => skopeo(`inspect --creds key:${key} docker://fw1.e2e.test/${ref}`);
  const seen = async (host) => (await h.fakes.ociSeen()).filter((r) => r.host === host);
  const output = (run) => `${run.stdout}\n${run.stderr}`;

  const created = await admin.portal.submit("/keys", "/keys", { name: "oci-page" });
  expect(created.body.includes("docker login fw1.e2e.test") || created.body.includes("docker login"), `the keys page shows the Docker lines: ${created.body.slice(0, 300)}`);

  const restorePlatform = await changePlatform(h, { freeze: "7", unit: "days", allow: { allow_shorter_freeze: true } });
  try {
    await h.editPolicy(admin.portal, { action: "save", freeze: "", unit: "hours", osv: "on" });
    // The firewall answers the registry's challenge with its own token endpoint.
    const challenge = await h.request(`${fw1}/v2/`, { headers: { connection: "close" } });
    expect(challenge.status === 401 && /^Bearer realm="https:\/\/fw1\.e2e\.test\/v2\/token"/.test(challenge.headers["www-authenticate"] ?? ""), `an unauthenticated ping is the registry challenge naming this firewall's token endpoint: ${challenge.status} ${challenge.headers["www-authenticate"]}`);

    // 1. A young digest is held; the hub was asked for the manifest only, with its own anonymous token.
    let run = inspect("team/app:v1");
    expect(run.status !== 0 && /denied|403|cooldown/i.test(output(run)), `a young digest is held: ${run.status}\n${output(run).slice(-500)}`);
    const hub = await seen("registry-1.docker.io");
    expect(hub.some((r) => r.path === "/v2/team/app/manifests/v1") && !hub.some((r) => r.path.includes("/blobs/")), `only the manifest was asked of the hub: ${JSON.stringify(hub.slice(-4))}`);
    expect(hub.every((r) => !String(r.authorization ?? "").includes("prb_")), "the firewall's key never reached the hub");

    // 2. Released by policy: the image is copied exactly.
    await h.editPolicy(admin.portal, { action: "save", freeze: "0", unit: "hours", osv: "on" });
    await h.waitFor("the shorter freeze reaches firewall-1", async () => (inspect("team/app:v1")).status === 0, { timeout: 4 * h.syncInterval * 1000, every: 2000 });
    run = skopeo(`copy --src-creds key:${key} docker://fw1.e2e.test/team/app:v1 dir:/work/out-v1`);
    expect(run.status === 0, `skopeo copies the released image: ${run.status}\n${output(run).slice(-600)}`);
    const manifest = h.client("client-oci", "cd /work/out-v1 && sha256sum manifest.json && ls");
    expect(manifest.stdout.includes(one.digest.replace("sha256:", "")), `the manifest bytes are the hub's (digest ${one.digest}): ${manifest.stdout}`);
    expect(manifest.stdout.includes(one.layer.replace("sha256:", "")) && manifest.stdout.includes(one.config.replace("sha256:", "")), `the config and the layer were delivered: ${manifest.stdout}`);
    const storage = await seen("production.cloudfront.docker.com");
    expect(storage.length >= 2 && storage.every((r) => r.authorization === null), `the storage host saw the blob requests and no credential: ${JSON.stringify(storage)}`);
    const tokens = await h.fakes.ociTokens();
    expect(tokens.length >= 1 && tokens.every((t) => !t.basic) && tokens.some((t) => t.scope === "repository:team/app:pull"), `the firewall's own anonymous token for the repository's scope, never the key: ${JSON.stringify(tokens)}`);
    run = skopeo(`inspect --creds key:${key} docker://fw1.e2e.test/team/app@${two.digest}`);
    expect(run.status === 0 && run.stdout.includes('"Os": "linux"'), `a digest is pulled by its digest: ${run.status}\n${output(run).slice(-400)}`);

    // 2b. A foreign layer (Windows base images): the manifest naming a download URL is accepted, and the firewall serves the layer at the registry
    // blob route after fetching it itself from the listed host with no credential; a client that fetches the URL itself (skopeo does) is outside.
    run = inspect("win/base:ltsc");
    expect(run.status === 0 && run.stdout.includes("foreign.diff.tar.gzip") === false, `a manifest that names a foreign layer is accepted: ${run.status}\n${output(run).slice(-400)}`);
    const layerAnswer = await h.request(`${fw1}/v2/win/base/blobs/${foreign.layer}`, { headers: { connection: "close", authorization: `Bearer ${key}` } });
    expect(layerAnswer.status === 200 && layerAnswer.headers["docker-content-digest"] === foreign.layer, `the foreign layer is served at the registry blob route: ${layerAnswer.status}`);
    const mcr = await seen("mcr.microsoft.com");
    expect(mcr.length >= 1 && mcr.every((r) => r.authorization === null), `the listed host was asked by the firewall, with no credential: ${JSON.stringify(mcr)}`);

    // 3. A block on a repository and on one tag is refused before the hub is asked anything.
    const policy = await h.policyPath(admin.portal);
    for (const block of [{ name: "team/blocked", what: "package" }, { name: "team/app", what: "version", version: "v2" }]) {
      const saved = await policyPost(admin.portal, policy, { action: "add_block", ecosystem: "oci", ...block });
      expect(saved.status === 303, `the block ${JSON.stringify(block)} is saved: ${saved.status}\n${saved.body}`);
    }
    await h.waitFor("the blocks refuse", async () => inspect("team/blocked:v1").status !== 0 && inspect("team/app:v2").status !== 0, { timeout: 4 * h.syncInterval * 1000, every: 2000 });
    // (the polling above may have reached the hub before the block did: what counts is what happens once it is in force)
    const forBlocked = async () => (await h.fakes.ociSeen()).filter((r) => r.path.includes("team/blocked")).length;
    const asked = await forBlocked();
    run = inspect("team/blocked:v1");
    expect(run.status !== 0 && /denied|403/i.test(output(run)), `a blocked repository is refused: ${output(run).slice(-300)}`);
    run = skopeo(`list-tags --creds key:${key} docker://fw1.e2e.test/team/blocked`);
    expect(run.status !== 0, `its tag list is refused too: ${output(run).slice(-200)}`);
    expect((await forBlocked()) === asked, "a blocked repository reached no hub call once the block was in force");
    expect(inspect("team/app:v1").status === 0, "an unblocked tag of the same repository still works");

    // 4. The tag list, and every write verb is no route of a managed firewall.
    run = skopeo(`list-tags --creds key:${key} docker://fw1.e2e.test/team/app`);
    expect(run.status === 0 && run.stdout.includes('"v1"') && !run.stdout.includes('"v2"'), `the tag list is served without the blocked tag: ${run.status}\n${run.stdout}`);
    const before = (await h.fakes.ociWrites()).length;
    for (const method of ["POST", "PUT", "DELETE", "PATCH"]) {
      const answer = await h.request(`${fw1}/v2/team/app/blobs/uploads/`, { method, body: "x", headers: { connection: "close", authorization: `Bearer ${key}` } });
      expect(answer.status === 405 || answer.status === 404, `${method} is no route of a managed firewall: ${answer.status}`);
    }
    expect((await h.fakes.ociWrites()).length === before, "no write reached the hub");

    const dated = h.decisions("firewall-1", since).filter((d) => d.ecosystem === "oci");
    expect(dated.some((d) => d.package === "team/blocked" && String(d.status) === "403"), `a logged decision names the blocked repository: ${JSON.stringify(dated.slice(-6))}`);
    await activityRow(h, admin.portal, { package: "team/blocked" });
  } finally {
    await restorePlatform();
  }
}
