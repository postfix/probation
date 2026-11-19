// E2E-publishing-rubygems-service: `gem push` and `gem yank` through the shared service (row 17,
// class W like the PyPI upload). The service org owns a RubyGems registry whose target is the fake
// rubygems.org; the real `gem` client pushes and yanks with its own API key, the firewall forwards
// the caller's Authorization, OTP and Content-Type and nothing of the service key, and a call
// without a credential is refused locally with 401 before any upstream request.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";

export const meta = { id: "E2E-publishing-rubygems-service", title: "gem push and gem yank through the shared service", suites: ["release"], stack: "own" };

const GEMSPEC = (name) => `Gem::Specification.new do |s|
  s.name = "${name}"; s.version = "1.0.0"; s.summary = "e2e"; s.authors = ["e2e"]; s.files = ["lib/${name.replaceAll("-", "_")}.rb"]
end
`;

export default async function rubygemsServicePublishing(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  h.expect((await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "Service RubyGems", ecosystem: "rubygems", target_url: "https://rubygems.org/",
  })).status === 303, "service RubyGems registry added");
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const id = listed.body.match(/<li>(\d+) Service RubyGems rubygems/)?.[1];
  h.expect(id, "the RubyGems registry has an ID");
  const issued = await admin.portal.submit("/keys", "/keys/service", { name: "rubygems-service", attach: "org" });
  h.expect(issued.status === 200, "service policy key issued");
  const serviceKey = h.between(issued.body, '<code id="new-key">', "</code>");
  h.stack.exec("firewall-standalone", ["sh", "-c", "umask 077; cat > /var/lib/probation/service.key; chmod 600 /var/lib/probation/service.key"], { input: `${serviceKey}\n`, check: true });
  const configPath = join(h.stack.work, "firewall-standalone.toml");
  writeFileSync(configPath, `allowed_peer_cidrs = ["${h.stack.net}.10/32"]\n${readFileSync(configPath, "utf8")}\n[service_policy]\nserver_url = "https://sync.e2e.test"\nservice_key_file = "/var/lib/probation/service.key"\nsync_interval_seconds = 1\n`);
  h.restart("firewall-standalone");
  await h.stack.firewallReady("fw-standalone");
  const host = `https://fw-standalone.e2e.test/registry/rubygems/${id}/`;
  const name = h.unique("rg-publish");
  await h.fakes.publishRubygems({ name: "e2e-warm", version: "1.0.0", ageSeconds: 400 * 86_400 });
  await h.waitFor("the RubyGems registry is loaded", async () => (await h.request(`${host}info/e2e-warm`)).status === 200, { timeout: 30_000 });

  const writes = async () => (await h.fakes.rubygemsWrites()).filter((w) => w.method !== undefined);
  // No credential: refused locally, nothing reaches the registry.
  const before = (await writes()).length;
  for (const [method, path] of [["POST", "api/v1/gems"], ["DELETE", "api/v1/gems/yank"]]) {
    const answer = await h.request(`${host}${path}`, { method, body: "x", headers: { "content-type": "application/octet-stream", connection: "close" } });
    h.expect(answer.status === 401, `${method} ${path} without a credential is refused with 401, got ${answer.status}`);
  }
  h.expect((await writes()).length === before, "a refused write made no upstream request");

  const dir = `/work/${h.unique("gem-push")}`;
  const gem = (key, args) => h.client("client-ruby", `export HOME=$PWD GEM_HOME=$PWD/.gems; mkdir -p $HOME/.gem && printf -- '---\\n:e2e: ${key}\\n' > $HOME/.gem/credentials && chmod 600 $HOME/.gem/credentials; ${args}`, { dir });
  const built = h.client("client-ruby", `export HOME=$PWD; mkdir -p lib && echo 'module X; end' > lib/${name.replaceAll("-", "_")}.rb && gem build ${name}.gemspec`, { dir, files: { [`${name}.gemspec`]: GEMSPEC(name) } });
  h.expect(built.status === 0, `gem build: ${built.stdout}${built.stderr}`);

  // The owner's key reaches the registry as the caller sent it; the registry's 200 comes back.
  let run = gem("e2e-owner", `SSL_CERT_FILE=/e2e/ca/ca.pem gem push ${name}-1.0.0.gem --host ${host.replace(/\/$/, "")} --key e2e --otp 123456`);
  h.expect(run.status === 0 && /Successfully registered gem/.test(run.stdout + run.stderr), `gem push with the owner key: ${run.status}\n${run.stdout}${run.stderr}`);
  const pushes = (await writes()).filter((w) => w.method === "POST");
  h.expect(pushes.length === 1, `one push reached the registry: ${JSON.stringify(pushes)}`);
  const [push] = pushes;
  h.expect(push.authorization === "e2e-owner", `the caller's own key arrived, not the service key: ${push.authorization}`);
  h.expect(push.otp === "123456", `the OTP header arrived: ${push.otp}`);
  h.expect(push.contentType === "application/octet-stream" && push.bytes > 500, `the content type and the gem body arrived: ${push.contentType} ${push.bytes}`);
  h.expect(push.path === "/api/v1/gems", `forwarded to the registry's own path: ${push.path}`);

  // The registry's refusal (403) is the caller's answer.
  run = gem("e2e-denied", `SSL_CERT_FILE=/e2e/ca/ca.pem gem push ${name}-1.0.0.gem --host ${host.replace(/\/$/, "")} --key e2e`);
  h.expect(run.status !== 0 && /403|does not allow/.test(run.stdout + run.stderr), `the upstream 403 is passed on: ${run.status}\n${run.stdout}${run.stderr}`);

  // gem yank: DELETE with the caller's key and the form body.
  run = gem("e2e-owner", `SSL_CERT_FILE=/e2e/ca/ca.pem gem yank ${name} -v 1.0.0 --host ${host.replace(/\/$/, "")} --key e2e --otp 654321`);
  h.expect(run.status === 0 && /Successfully yanked/.test(run.stdout + run.stderr), `gem yank: ${run.status}\n${run.stdout}${run.stderr}`);
  const yanks = (await writes()).filter((w) => w.method === "DELETE");
  h.expect(yanks.length === 1 && yanks[0].authorization === "e2e-owner" && yanks[0].otp === "654321" && yanks[0].path === "/api/v1/gems/yank", `the yank carried the caller's key and OTP: ${JSON.stringify(yanks)}`);
  h.expect(yanks[0].body.includes(`gem_name=${name}`) && yanks[0].body.includes("version=1.0.0"), `the yank body arrived: ${yanks[0].body}`);

  // The service key never reaches the registry, and an unknown registry makes no upstream call.
  const all = await writes();
  h.expect(all.every((w) => w.authorization !== serviceKey), "the service key was never forwarded");
  const count = all.length;
  const wrong = await h.request(`https://fw-standalone.e2e.test/registry/rubygems/999999/api/v1/gems`, { method: "POST", body: "x", headers: { authorization: "e2e-owner", "content-type": "application/octet-stream", connection: "close" } });
  h.expect(wrong.status === 404 && (await writes()).length === count, `an unknown RubyGems registry answers 404 with no upstream call: ${wrong.status}`);
}
