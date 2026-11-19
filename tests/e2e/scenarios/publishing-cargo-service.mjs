// E2E-publishing-cargo-service: Cargo's registry API through the shared service (row 18 follow-up,
// class W like `gem push` and the PyPI upload). The service org owns a Cargo registry whose target is
// the fake crates.io index; real cargo publishes, yanks, unyanks, changes owners and searches with its
// own token, the firewall forwards that token to the API root the registry's config.json names (the
// public pair index.crates.io -> crates.io) and nothing of the service key, and a write without a
// credential is refused locally with 401 before any upstream request.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";

export const meta = { id: "E2E-publishing-cargo-service", title: "cargo publish, yank, owner and search through the shared service", suites: ["release"], stack: "own" };

export default async function cargoServicePublishing(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  h.expect((await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "Service Cargo", ecosystem: "cargo", target_url: "https://index.crates.io/",
  })).status === 303, "service Cargo registry added");
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const id = listed.body.match(/<li>(\d+) Service Cargo cargo/)?.[1];
  h.expect(id, "the Cargo registry has an ID");
  const issued = await admin.portal.submit("/keys", "/keys/service", { name: "cargo-service", attach: "org" });
  h.expect(issued.status === 200, "service policy key issued");
  const serviceKey = h.between(issued.body, '<code id="new-key">', "</code>");
  h.stack.exec("firewall-standalone", ["sh", "-c", "umask 077; cat > /var/lib/probation/service.key; chmod 600 /var/lib/probation/service.key"], { input: `${serviceKey}\n`, check: true });
  const configPath = join(h.stack.work, "firewall-standalone.toml");
  writeFileSync(configPath, `allowed_peer_cidrs = ["${h.stack.net}.10/32"]\n${readFileSync(configPath, "utf8")}\n[service_policy]\nserver_url = "https://sync.e2e.test"\nservice_key_file = "/var/lib/probation/service.key"\nsync_interval_seconds = 1\n`);
  h.restart("firewall-standalone");
  await h.stack.firewallReady("fw-standalone");
  const host = `https://fw-standalone.e2e.test/registry/cargo/${id}/`;
  await h.waitFor("the Cargo registry is loaded", async () => (await h.request(`${host}config.json`)).status === 200, { timeout: 30_000 });

  const writes = async () => await h.fakes.cargoWrites();
  const name = h.unique("cg-publish").replaceAll("_", "-");
  // No credential: every write is refused locally, nothing reaches the registry.
  const before = (await writes()).length;
  for (const [method, path] of [["PUT", "api/v1/crates/new"], ["DELETE", `api/v1/crates/${name}/1.0.0/yank`], ["PUT", `api/v1/crates/${name}/1.0.0/unyank`], ["PUT", `api/v1/crates/${name}/owners`], ["DELETE", `api/v1/crates/${name}/owners`]]) {
    const answer = await h.request(`${host}${path}`, { method, body: "x", headers: { "content-type": "application/octet-stream", connection: "close" } });
    h.expect(answer.status === 401, `${method} ${path} without a credential is refused with 401, got ${answer.status}`);
  }
  h.expect((await writes()).length === before, "a refused write made no upstream request");

  const dir = `/work/${h.unique("cargo-pub")}`;
  const cargo = (token, args) => h.client("client-cargo", `export CARGO_HOME=$PWD/.cargo-home CARGO_TERM_COLOR=never CARGO_NET_RETRY=0 CARGO_PUBLISH_TIMEOUT=1 CARGO_REGISTRIES_PROBATION_TOKEN='${token}'; ${args}`, {
    dir,
    files: {
      "Cargo.toml": `[package]\nname = "${name}"\nversion = "1.0.0"\nedition = "2021"\ndescription = "e2e"\nlicense = "MIT"\n`,
      "src/lib.rs": "pub fn f() {}\n",
      ".cargo/config.toml": `[registries.probation]\nindex = "sparse+${host}"\ncredential-provider = "cargo:token"\n`,
    },
  });
  const ok = (what, run, pattern) => h.expect(run.status === 0 && pattern.test(run.stdout + run.stderr), `${what}: ${run.status}\n${run.stdout}${run.stderr}`);

  // The owner's token reaches the registry as the caller sent it, bare; the registry's 200 comes back.
  let run = cargo("e2e-owner", "cargo publish --registry probation --no-verify --allow-dirty");
  ok("cargo publish with the owner token", run, /Uploaded|Published|Uploading/);
  const publishes = (await writes()).filter((w) => w.method === "PUT" && w.path === "/api/v1/crates/new");
  h.expect(publishes.length === 1, `one publish reached the registry: ${JSON.stringify(publishes)}`);
  const [publish] = publishes;
  h.expect(publish.authorization === "e2e-owner", `the caller's own token arrived, not the service key: ${publish.authorization}`);
  h.expect(publish.bytes > 300, `the length-prefixed JSON and the crate arrived: ${publish.bytes} bytes`);

  // The registry's refusal (403) is the caller's answer.
  run = cargo("e2e-denied", "cargo publish --registry probation --no-verify --allow-dirty");
  h.expect(run.status !== 0 && /403|not allowed/.test(run.stdout + run.stderr), `the upstream 403 is passed on: ${run.status}\n${run.stdout}${run.stderr}`);

  // yank, unyank, owner add/remove/list and search.
  ok("cargo yank", cargo("e2e-owner", `cargo yank ${name}@1.0.0 --registry probation`), /Yank/i);
  ok("cargo yank --undo", cargo("e2e-owner", `cargo yank ${name}@1.0.0 --undo --registry probation`), /Yank/i);
  ok("cargo owner --add", cargo("e2e-owner", `cargo owner --add someone ${name} --registry probation`), /Owner/i);
  ok("cargo owner --remove", cargo("e2e-owner", `cargo owner --remove someone ${name} --registry probation`), /Owner/i);
  ok("cargo owner --list", cargo("e2e-owner", `cargo owner --list ${name} --registry probation`), /e2e-owner/);
  ok("cargo search", cargo("e2e-owner", "cargo search e2e --registry probation"), /e2e-seed/);
  const all = await writes();
  const shape = all.map((w) => `${w.method} ${w.path}`);
  for (const want of [`DELETE /api/v1/crates/${name}/1.0.0/yank`, `PUT /api/v1/crates/${name}/1.0.0/unyank`, `PUT /api/v1/crates/${name}/owners`, `DELETE /api/v1/crates/${name}/owners`, `GET /api/v1/crates/${name}/owners`, "GET /api/v1/crates"]) {
    h.expect(shape.includes(want), `the registry received ${want}: ${shape.join(", ")}`);
  }
  const owners = all.filter((w) => w.method === "PUT" && w.path.endsWith("/owners"));
  h.expect(owners.length === 1 && owners[0].body.includes('"someone"') && owners[0].authorization === "e2e-owner", `the owner change carried the caller's token and its JSON body: ${JSON.stringify(owners)}`);
  const search = all.find((w) => w.method === "GET" && w.path === "/api/v1/crates");
  h.expect(search.query?.startsWith("?q=e2e"), `the search query arrived: ${search.query}`);

  // A registry that answers a write with a redirect is not followed: the caller gets a refusal, and neither
  // the other path of the registry nor the archive host is ever asked, so the token goes nowhere else.
  for (const kind of ["same", "away"]) {
    const before = (await writes()).length;
    const answer = await h.request(`${host}api/v1/crates/redirect-${kind}-${name}/1.0.0/yank`, { method: "DELETE", headers: { authorization: "e2e-owner", connection: "close" } });
    h.expect(answer.status === 502, `a redirect from the registry's API is refused (502), got ${answer.status}`);
    const seen = (await writes()).slice(before);
    h.expect(seen.length === 1 && seen[0].path.includes(`redirect-${kind}-`) && seen[0].host === undefined, `only the original request reached the registry: ${JSON.stringify(seen)}`);
  }

  // The service key never reaches the registry, and an unknown registry makes no upstream call.
  h.expect((await writes()).every((w) => w.authorization !== serviceKey), "the service key was never forwarded");
  h.expect((await writes()).every((w) => w.host === undefined), "no credential ever reached the archive host");
  const count = (await writes()).length;
  const wrong = await h.request("https://fw-standalone.e2e.test/registry/cargo/999999/api/v1/crates/new", { method: "PUT", body: "x", headers: { authorization: "e2e-owner", "content-type": "application/octet-stream", connection: "close" } });
  h.expect(wrong.status === 404 && (await writes()).length === count, `an unknown Cargo registry answers 404 with no upstream call: ${wrong.status}`);
}
