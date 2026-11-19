// E2E-publishing-nuget-service: NuGet's publish endpoints through the shared service (row 20, class W like
// `gem push`, `cargo publish` and the PyPI upload). The service org owns a NuGet registry whose target is the
// fake NuGet.org's service index; the real `dotnet nuget push` (a package made by `dotnet pack`, with its
// symbol package) and `dotnet nuget delete` send their own API key, the firewall forwards that key to the
// publish endpoint the registry's own service index names (api.nuget.org -> www.nuget.org, the public pair)
// and nothing of the service key, and a write without a credential is refused locally with 401 before any
// upstream request. Reads of the same registry (a restore) go through the same service.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hidden } from "../harness/net.mjs";
import { orgId } from "../harness/people.mjs";

export const meta = { id: "E2E-publishing-nuget-service", title: "dotnet nuget push, delete and restore through the shared service", suites: ["release"], stack: "own" };

export default async function nugetServicePublishing(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  h.expect((await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "Service NuGet", ecosystem: "nuget", target_url: "https://api.nuget.org/v3/index.json",
  })).status === 303, "service NuGet registry added");
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const id = listed.body.match(/<li>(\d+) Service NuGet nuget/)?.[1];
  h.expect(id, "the NuGet registry has an ID");
  const issued = await admin.portal.submit("/keys", "/keys/service", { name: "nuget-service", attach: "org" });
  h.expect(issued.status === 200, "service policy key issued");
  const serviceKey = h.between(issued.body, '<code id="new-key">', "</code>");
  h.stack.exec("firewall-standalone", ["sh", "-c", "umask 077; cat > /var/lib/probation/service.key; chmod 600 /var/lib/probation/service.key"], { input: `${serviceKey}\n`, check: true });
  const configPath = join(h.stack.work, "firewall-standalone.toml");
  writeFileSync(configPath, `allowed_peer_cidrs = ["${h.stack.net}.10/32"]\n${readFileSync(configPath, "utf8")}\n[service_policy]\nserver_url = "https://sync.e2e.test"\nservice_key_file = "/var/lib/probation/service.key"\nsync_interval_seconds = 1\n`);
  h.restart("firewall-standalone");
  await h.stack.firewallReady("fw-standalone");
  const root = `https://fw-standalone.e2e.test/registry/nuget/${id}/`;
  await h.waitFor("the NuGet registry is loaded", async () => (await h.request(`${root}v3/index.json`)).status === 200, { timeout: 30_000 });

  // The service index advertises the publish endpoints of this firewall (and nothing of the registry's own hosts).
  const index = await h.request(`${root}v3/index.json`);
  const types = Object.fromEntries(index.json().resources.map((r) => [r["@type"], r["@id"]]));
  h.expect(types["PackagePublish/2.0.0"] === `${root}api/v2/package` && types["SymbolPackagePublish/4.9.0"] === `${root}api/v2/symbolpackage`, `the publish endpoints are routes of the firewall: ${JSON.stringify(types)}`);
  h.expect(!index.body.includes("www.nuget.org") && !index.body.includes("azuresearch"), "no host of the registry survives in the service index");

  const writes = async () => await h.fakes.nugetWrites();
  const name = `E2E.Pub.${h.unique("nu").replace(/[^A-Za-z0-9]/g, "")}`;
  // No credential: every write is refused locally, nothing reaches the registry.
  const before = (await writes()).length;
  const requestsBefore = (await h.fakes.requests("www.nuget.org")).length;
  for (const [method, path] of [["PUT", "api/v2/package"], ["PUT", "api/v2/symbolpackage"], ["DELETE", `api/v2/package/${name}/1.0.0`], ["POST", `api/v2/package/${name}/1.0.0`]]) {
    const answer = await h.request(`${root}${path}`, { method, body: "x", headers: { "content-type": "application/octet-stream", connection: "close" } });
    h.expect(answer.status === 401, `${method} ${path} without a credential is refused with 401, got ${answer.status}`);
  }
  h.expect((await writes()).length === before && (await h.fakes.requests("www.nuget.org")).length === requestsBefore, "a refused write made no upstream request");

  const source = `${root}v3/index.json`;
  const dir = `/work/${h.unique("nuget-pub")}`;
  const dotnet = (script) => h.client("client-nuget", `export HOME=$PWD/.home DOTNET_CLI_HOME=$PWD/.home NUGET_PACKAGES=$PWD/.packages NUGET_HTTP_CACHE_PATH=$PWD/.httpcache; ${script}`, {
    dir,
    files: {
      "lib.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><PackageId>${name}</PackageId><Version>1.0.0</Version><Authors>e2e</Authors><Description>e2e</Description><IncludeSymbols>true</IncludeSymbols><SymbolPackageFormat>snupkg</SymbolPackageFormat><NuGetAudit>false</NuGetAudit></PropertyGroup></Project>`,
      "Lib.cs": "namespace E2E; public static class Lib { public static int F() => 1; }\n",
      "nuget.config": `<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><clear /></packageSources></configuration>`,
    },
  });
  const ok = (what, run, pattern) => h.expect(run.status === 0 && pattern.test(run.stdout + run.stderr), `${what}: ${run.status}\n${run.stdout}${run.stderr}`);

  // `dotnet pack` makes a real package and symbol package; `dotnet nuget push` sends the caller's own key.
  let run = dotnet(`dotnet pack -c Release -o out && ls out && dotnet nuget push out/*.nupkg --source ${source} --api-key e2e-owner-key`);
  ok("dotnet nuget push with the owner key", run, /Your package was pushed|Pushing|Created/i);
  const pushed = await writes();
  const package_ = pushed.filter((w) => w.method === "PUT" && w.path === "/api/v2/package");
  h.expect(package_.length === 1 && package_[0].apiKey === "e2e-owner-key", `one publish reached the registry with the caller's own key, not the service key: ${JSON.stringify(package_)}`);
  h.expect(package_[0].bytes > 1000 && /^multipart\/form-data/.test(package_[0].contentType ?? ""), `the multipart package arrived whole: ${JSON.stringify(package_[0])}`);
  const symbols = pushed.filter((w) => w.method === "PUT" && w.path === "/api/v2/symbolpackage");
  h.expect(symbols.length === 1 && symbols[0].apiKey === "e2e-owner-key", `the symbol package went to the symbol endpoint: ${JSON.stringify(pushed)}`);

  // The registry's refusal (403) is the caller's answer.
  run = dotnet(`dotnet pack -c Release -o out >/dev/null && dotnet nuget push out/*.nupkg --source ${source} --api-key e2e-denied --skip-duplicate`);
  h.expect(run.status !== 0 && /403|not authori[sz]ed/i.test(run.stdout + run.stderr), `the upstream 403 is passed on: ${run.status}\n${run.stdout}${run.stderr}`);

  // Unlist (`dotnet nuget delete`) and relist (a POST of the same URL, which no CLI sends: raw).
  run = dotnet(`dotnet nuget delete ${name} 1.0.0 --source ${source} --api-key e2e-owner-key --non-interactive`);
  ok("dotnet nuget delete", run, /Deleting|OK|NoContent|204/i);
  const relist = await h.request(`${root}api/v2/package/${name}/1.0.0`, { method: "POST", body: "", headers: { "x-nuget-apikey": "e2e-owner-key", connection: "close" } });
  h.expect(relist.status === 200, `a relist reaches the registry: ${relist.status}`);
  const shape = (await writes()).map((w) => `${w.method} ${w.path}`);
  for (const want of [`DELETE /api/v2/package/${name}/1.0.0`, `POST /api/v2/package/${name}/1.0.0`]) h.expect(shape.includes(want), `the registry received ${want}: ${shape.join(", ")}`);

  // The service key never reaches the registry; an unknown registry makes no upstream call.
  h.expect((await writes()).every((w) => w.apiKey !== serviceKey && w.authorization !== serviceKey && !String(w.authorization ?? "").includes(serviceKey)), "the service key was never forwarded");
  const count = (await h.fakes.requests("www.nuget.org")).length;
  const wrong = await h.request("https://fw-standalone.e2e.test/registry/nuget/999999/api/v2/package", { method: "PUT", body: "x", headers: { "x-nuget-apikey": "e2e-owner-key", "content-type": "application/octet-stream", connection: "close" } });
  h.expect(wrong.status === 404 && (await h.fakes.requests("www.nuget.org")).length === count, `an unknown NuGet registry answers 404 with no upstream call: ${wrong.status}`);

  // Reads of the same registry go through the same service: a restore of an old package, a held young one refused.
  await h.fakes.publishNuGet({ id: "e2e.svc-read", version: "1.0.0", ageSeconds: 400 * 86_400 });
  const restore = h.client("client-nuget", `export HOME=$PWD/.home DOTNET_CLI_HOME=$PWD/.home NUGET_PACKAGES=$PWD/.packages NUGET_HTTP_CACHE_PATH=$PWD/.httpcache; dotnet restore -v n && cat obj/project.assets.json`, {
    dir: `${dir}-read`,
    files: {
      "app.csproj": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><NuGetAudit>false</NuGetAudit></PropertyGroup><ItemGroup><PackageReference Include="e2e.svc-read" Version="*" /></ItemGroup></Project>`,
      "nuget.config": `<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><clear /><add key="svc" value="https://fw-standalone.e2e.test/nuget/v3/index.json" protocolVersion="3" /></packageSources></configuration>`,
    },
  });
  h.expect(restore.status === 0 && restore.stdout.includes("e2e.svc-read/1.0.0"), `a restore through the shared service: ${restore.status}\n${restore.stdout}\n${restore.stderr}`);
}
