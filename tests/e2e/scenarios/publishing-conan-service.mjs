// E2E-publishing-conan-service: `conan upload` through the shared service (row 23, class W like `mvn deploy`, `gem push`, `cargo publish`
// and `dotnet nuget push`). The service org owns a Conan registry whose target is the fake ConanCenter; the REAL client logs in
// (`conan remote login`: the Basic credential goes to the registry's own `authenticate` and the token it hands out comes back), creates
// a header-only package and uploads it; the firewall forwards each PUT (the recipe's files and the package's) to the registry's own
// origin with that token and nothing of the service key, and a write without a credential is answered with a Bearer challenge before
// any upstream request. Reads of the same registry (an install) go through the same service.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";

export const meta = { id: "E2E-publishing-conan-service", title: "conan upload and an install through the shared service", suites: ["release"], stack: "own" };

export default async function conanServicePublishing(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  h.expect((await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "Service Conan", ecosystem: "conan", target_url: "https://center2.conan.io/",
  })).status === 303, "service Conan registry added");
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const id = listed.body.match(/<li>(\d+) Service Conan conan/)?.[1];
  h.expect(id, "the Conan registry has an ID");
  // A 7-day cooldown on the organisation, so that what is uploaded is held for everyone else (the case C23-3 is about).
  await h.editPolicy(admin.portal, { action: "save", freeze: "7", unit: "days", osv: "on" });
  const issued = await admin.portal.submit("/keys", "/keys/service", { name: "conan-service", attach: "org" });
  h.expect(issued.status === 200, "service policy key issued");
  const serviceKey = h.between(issued.body, '<code id="new-key">', "</code>");
  h.stack.exec("firewall-standalone", ["sh", "-c", "umask 077; cat > /var/lib/probation/service.key; chmod 600 /var/lib/probation/service.key"], { input: `${serviceKey}\n`, check: true });
  const configPath = join(h.stack.work, "firewall-standalone.toml");
  writeFileSync(configPath, `allowed_peer_cidrs = ["${h.stack.net}.10/32"]\n${readFileSync(configPath, "utf8")}\n[service_policy]\nserver_url = "https://sync.e2e.test"\nservice_key_file = "/var/lib/probation/service.key"\nsync_interval_seconds = 1\n`);
  h.restart("firewall-standalone");
  await h.stack.firewallReady("fw-standalone");
  const remote = `https://fw-standalone.e2e.test/registry/conan/${id}`;
  await h.waitFor("the Conan registry is loaded", async () => (await h.request(`${remote}/v2/conans/seed/1.0/_/_/revisions`)).status === 200, { timeout: 30_000 });

  const writes = async () => await h.fakes.conanWrites();
  const name = `pub${h.unique("cn").replace(/[^A-Za-z0-9]/g, "").toLowerCase()}`;
  const recipeOf = (pkg) => `from conan import ConanFile\nfrom conan.tools.files import copy\n\n\nclass PubConan(ConanFile):\n    name = "${pkg}"\n    version = "1.0"\n    package_type = "header-library"\n    settings = "os", "build_type"\n    exports_sources = "include/*"\n\n    def package(self):\n        copy(self, "*.h", self.source_folder, self.package_folder)\n`;
  const profile = "[settings]\nos=Linux\narch=x86_64\nbuild_type=Release\ncompiler=gcc\ncompiler.version=12\ncompiler.libcxx=libstdc++11\ncompiler.cppstd=17\n";
  const dir = `/work/${h.unique("conan-pub")}`;
  const prelude = `export CONAN_HOME=$PWD/home/.conan2 HOME=$PWD/home; mkdir -p $HOME $CONAN_HOME; printf 'core.net.http:cacert_path=/e2e/ca/ca.pem\\n' > $CONAN_HOME/global.conf; conan remote remove conancenter >/dev/null 2>&1; conan remote add svc ${remote} --force >/dev/null`;

  // No credential: every write is answered with the challenge the client waits for, nothing reaches the registry.
  const before = (await writes()).length;
  const requestsBefore = (await h.fakes.requests("center2.conan.io")).length;
  for (const method of ["PUT", "DELETE"]) {
    const answer = await h.request(`${remote}/v2/conans/${name}/1.0/_/_/revisions/aaaa/files/conanfile.py`, { method, body: "x", headers: { connection: "close" } });
    h.expect(answer.status === 401 && /^Bearer/.test(answer.headers["www-authenticate"] ?? ""), `${method} without a credential is challenged with 401 and Bearer, got ${answer.status}`);
  }
  h.expect((await writes()).length === before && (await h.fakes.requests("center2.conan.io")).length === requestsBefore, "a challenged write made no upstream request");

  const upload = (user, password, pkg = name, createArgs = "") => h.client("client-conan", `${prelude} && conan remote login svc ${user} -p ${password} >/dev/null && mkdir -p src/include && cp conanfile.py src/ && printf '#define PUB 1\\n' > src/include/pub.h && cd src && conan create . ${createArgs} -pr:h=../profile -pr:b=../profile >/dev/null && conan upload '${pkg}/1.0' -r svc --confirm`, {
    dir,
    files: { "conanfile.py": recipeOf(pkg), profile },
  });

  // `conan upload` sends the caller's own token: the login first (the registry's own answer), then every file.
  let run = upload("e2e-owner", "e2e-pass");
  h.expect(run.status === 0 && /Upload completed/.test(`${run.stdout}\n${run.stderr}`), `conan upload with the owner credential: ${run.status}\n${run.stdout.slice(-800)}${run.stderr.slice(-300)}`);
  const sent = (await writes()).filter((w) => w.authorization === "Bearer tok-e2e-owner");
  const paths = sent.map((w) => w.path);
  for (const want of ["conanfile.py", "conanmanifest.txt"]) {
    h.expect(paths.some((p) => p.startsWith(`/v2/conans/${name}/1.0/_/_/revisions/`) && p.endsWith(`/files/${want}`)), `the registry received the recipe's ${want}: ${paths.join(", ")}`);
  }
  h.expect(paths.some((p) => p.includes("/packages/") && p.endsWith("/files/conan_package.tgz")), `the registry received the package: ${paths.join(", ")}`);
  h.expect(sent.every((w) => w.method === "PUT"), "every file was a PUT");

  // C23-3: the SECOND binary of a recipe revision that is already on the registry (and, under the cooldown, still held for every other caller),
  // and a binary for a second platform, as a multi-platform CI uploads them: the depositor's own existence checks must not meet the hold.
  for (const [what, args] of [["a second binary (Debug)", "-s:h build_type=Debug"], ["a second platform (Windows)", "-s:h os=Windows"]]) {
    run = upload("e2e-owner", "e2e-pass", name, args);
    h.expect(run.status === 0 && /Upload completed/.test(`${run.stdout}\n${run.stderr}`), `conan upload of ${what} of a recipe revision still in its cooldown: ${run.status}\n${run.stdout.slice(-600)}\n${run.stderr.slice(-400)}`);
  }
  const ids = new Set((await writes()).filter((w) => w.authorization === "Bearer tok-e2e-owner").map((w) => w.path.match(/\/packages\/([^/]+)\//)?.[1]).filter(Boolean));
  h.expect(ids.size === 3, `three package ids of one recipe revision reached the registry: ${[...ids].join(", ")}`);
  const reread = await h.request(`${remote}/v2/conans/${name}/1.0/_/_/revisions`, { headers: { authorization: "Bearer tok-e2e-owner", connection: "close" } });
  h.expect(reread.status === 200 && reread.body.includes('"revision"'), `the depositor reads its own revision list during the cooldown: ${reread.status} ${reread.body.slice(0, 120)}`);
  const stranger = await h.request(`${remote}/v2/conans/${name}/1.0/_/_/revisions`, { headers: { authorization: "Bearer tok-someone-else", connection: "close" } });
  h.expect(stranger.status === 403, `another caller still meets the cooldown: ${stranger.status}`);

  // The registry's refusal (403) is the caller's answer.
  run = upload("e2e-denied", "x", `${name}d`); // (another package: a revision the registry already holds is skipped, not uploaded)
  h.expect(run.status !== 0 && /403|Forbidden|not authori[sz]ed/i.test(run.stdout + run.stderr), `the upstream 403 is passed on: ${run.status}\n${run.stdout.slice(-400)}\n${run.stderr.slice(-300)}`);

  // The service key never reaches the registry; an unknown registry makes no upstream call.
  const all = await writes();
  h.expect(all.every((w) => !String(w.authorization ?? "").includes(serviceKey)), "the service key was never forwarded");
  const count = (await h.fakes.requests("center2.conan.io")).length;
  const wrong = await h.request(`https://fw-standalone.e2e.test/registry/conan/999999/v2/conans/${name}/1.0/_/_/revisions/aaaa/files/conanfile.py`, { method: "PUT", body: "x", headers: { authorization: "Bearer tok-e2e-owner", connection: "close" } });
  h.expect(wrong.status === 404 && (await h.fakes.requests("center2.conan.io")).length === count, `an unknown Conan registry answers 404 with no upstream call: ${wrong.status}`);

  // Reads of the same registry go through the same service: an old package of the fake (its real files) installs with the caller's own login.
  await h.fakes.publishConan({ name: "hello", version: "1.0", ageSeconds: 400 * 86_400 });
  const resolve = h.client("client-conan", `${prelude} && conan remote login svc e2e-owner -p e2e-pass >/dev/null && conan install --requires=hello/1.0 -r svc -pr:h=profile -pr:b=profile`, { dir: `${dir}-read`, files: { profile } });
  h.expect(resolve.status === 0 && /Download \(svc\)/.test(`${resolve.stdout}\n${resolve.stderr}`), `an install through the shared service: ${resolve.status}\n${resolve.stdout.slice(-600)}\n${resolve.stderr.slice(-300)}`);
}
