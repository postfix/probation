import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hidden } from "../harness/net.mjs";
import { act, keyId, orgId } from "../harness/people.mjs";

export const meta = { id: "E2E-publishing-python-service", title: "local-service PyPI publishing", suites: ["release"], stack: "own" };

export default async function servicePythonPublishing(h) {
  const admin = await h.signUp({ kind: "org" });
  await h.enableTotp(admin);
  const org = await orgId(admin.portal);
  const catalog = await admin.portal.get(`/org/${org}/registries`);
  h.expect((await admin.portal.post(`/org/${org}/registries`, {
    csrf: hidden(catalog.body, "csrf"), name: "Service Python", ecosystem: "pypi", target_url: "https://pypi.org/",
  })).status === 303, "service Python registry added");
  const listed = await admin.portal.get(`/org/${org}/registries`);
  const id = listed.body.match(/<li>(\d+) Service Python pypi/)?.[1];
  h.expect(id, "selected Python registry has an ID");
  const issued = await admin.portal.submit("/keys", "/keys/service", { name: "python-upload-service", attach: "org" });
  h.expect(issued.status === 200, "Python service policy key issued");
  const key = h.between(issued.body, '<code id="new-key">', "</code>");
  h.stack.exec("firewall-standalone", ["sh", "-c", "umask 077; cat > /var/lib/probation/service.key; chmod 600 /var/lib/probation/service.key"], { input: `${key}\n`, check: true });
  const configPath = join(h.stack.work, "firewall-standalone.toml");
  writeFileSync(configPath, `allowed_peer_cidrs = ["${h.stack.net}.10/32"]\n${readFileSync(configPath, "utf8")}\n[service_policy]\nserver_url = "https://sync.e2e.test"\nservice_key_file = "/var/lib/probation/service.key"\nsync_interval_seconds = 1\n`);
  h.restart("firewall-standalone");
  await h.stack.firewallReady("fw-standalone");
  const base = `https://fw-standalone.e2e.test/registry/pypi/${id}/`;
  const name = h.unique("service-python");
  await h.fakes.publishPypi({ name, version: "1.0.0", ageSeconds: 400 * 86_400, kinds: ["wheel", "sdist"], backend: "intree" });
  await h.waitFor("selected Python policy loaded", async () => (await h.request(`${base}simple/${name}/`)).status === 200, { timeout: 30_000 });
  const fetch = `import json, os, ssl, urllib.request
ctx=ssl.create_default_context(cafile="/e2e/ca/ca.pem")
request=urllib.request.Request(os.environ["INDEX"]+os.environ["PROJECT"]+"/", headers={"Accept":"application/vnd.pypi.simple.v1+json"})
with urllib.request.urlopen(request, context=ctx) as response:
    files=json.load(response)["files"]
os.makedirs("dist", exist_ok=True)
for file in files:
    with urllib.request.urlopen(file["url"], context=ctx) as response:
        data=response.read()
    with open("dist/"+file["filename"], "wb") as output:
        output.write(data)
`;
  const dir = `/work/${h.unique("service-twine")}`;
  const fetched = h.client("client-twine", `INDEX=${base}simple/ PROJECT=${name} python fetch.py`, { dir, files: { "fetch.py": fetch } });
  h.expect(fetched.status === 0, `selected Python files fetched for Twine: ${fetched.stderr}`);
  const twine = (password) => h.client("client-twine", `TWINE_USERNAME=__token__ TWINE_PASSWORD=${password} TWINE_CERT=/e2e/ca/ca.pem twine upload --non-interactive --repository-url ${base} dist/*`, { dir });
  const owner = twine("e2e-owner");
  h.expect(owner.status === 0, `Twine Basic owner uploads wheel and sdist through local service: ${owner.stderr}`);
  const denied = twine("e2e-denied");
  h.expect(denied.status !== 0 && `${denied.stdout}\n${denied.stderr}`.includes("403"), "upstream denied Twine Basic upload");
  const bearer = `import glob, ssl, sys, urllib.error, urllib.request
url, token=sys.argv[1:]
data=open(glob.glob("dist/*.whl")[0], "rb").read()
boundary="e2e-bearer"
body=(f'--{boundary}\\r\\nContent-Disposition: form-data; name="name"\\r\\n\\r\\n${name}\\r\\n'
      f'--{boundary}\\r\\nContent-Disposition: form-data; name="version"\\r\\n\\r\\n1.0.0\\r\\n'
      f'--{boundary}\\r\\nContent-Disposition: form-data; name="content"; filename="bearer.whl"\\r\\n\\r\\n').encode()+data+f'\\r\\n--{boundary}--\\r\\n'.encode()
request=urllib.request.Request(url, body, {"Authorization":"Bearer "+token, "Content-Type":"multipart/form-data; boundary="+boundary})
try:
    with urllib.request.urlopen(request, context=ssl.create_default_context(cafile="/e2e/ca/ca.pem")) as response: print(response.status)
except urllib.error.HTTPError as error: print(error.code)
`;
  for (const [token, status] of [["e2e-owner", "200"], ["e2e-denied", "403"]]) {
    const result = h.client("client-twine", `python bearer.py ${base} ${token}`, { dir, files: { "bearer.py": bearer } });
    h.expect(result.status === 0 && result.stdout.trim() === status, `Bearer ${token} preserves upstream ${status}: ${result.stdout} ${result.stderr}`);
  }
  // A large upload outlives the 30-second metadata deadline: the registry takes 33 s to answer a 2 MiB body.
  const large = bearer.replace('data=open(glob.glob("dist/*.whl")[0], "rb").read()', 'data=open(glob.glob("dist/*.whl")[0], "rb").read()+b"0"*(2<<20)')
    .replace("context=ssl.create_default_context(cafile=\"/e2e/ca/ca.pem\"))", "context=ssl.create_default_context(cafile=\"/e2e/ca/ca.pem\"), timeout=240)");
  await h.fakes.faults([{ host: "pypi.org", method: "POST", mode: "delay", ms: 33_000, times: 1 }]);
  const slow = h.client("client-twine", `python large.py ${base} e2e-owner`, { dir, files: { "large.py": large } });
  await h.fakes.faults([]);
  h.expect(slow.status === 0 && slow.stdout.trim() === "200", `a 2 MiB upload that outlives 30 s is not cut off by the metadata deadline: ${slow.stdout} ${slow.stderr}`);
  const beforeWrong = (await h.fakes.requests("pypi.org")).length;
  const wrong = await h.request(`https://fw-standalone.e2e.test/registry/pypi/999999/`, { method: "POST", headers: { authorization: "Bearer e2e-owner", "content-type": "multipart/form-data; boundary=x" }, body: "x" });
  h.expect(wrong.status === 404 && (await h.fakes.requests("pypi.org")).length === beforeWrong, "unknown Python registry makes zero upstream calls");
  const uploads = (await h.fakes.requests("pypi.org")).filter((row) => row.method === "POST");
  const tally = (credential, status) => uploads.filter((row) => row.credential === credential && row.status === status).length;
  h.expect(uploads.length === 6 && uploads.every((row) => row.path === "/")
    && tally("other", 200) === 2 && tally("other", 403) === 1
    && tally("developer-owner", 200) === 2 && tally("developer-denied", 403) === 1,
  `selected PyPI sees exactly the six package-manager uploads and preserves Basic/Bearer allow/deny: ${JSON.stringify(uploads.map((row) => [row.credential, row.status]))}`);
  const everyPypiRow = [...await h.fakes.requests("pypi.org"), ...await h.fakes.requests("files.pythonhosted.org")];
  h.expect(!everyPypiRow.some((row) => row.credential === "policy-key"),
    "policy key never reaches Python registry on any request");
  await act(admin.portal, "/keys", `/keys/${await keyId(admin.portal, "python-upload-service")}/revoke`);
  await h.waitFor("service key refusal closes Python policy", async () =>
    (await h.request(`${base}simple/${name}/`)).status === 503, { timeout: 30_000 });
  h.expect((await h.request(base, { method: "POST", headers: { authorization: "Bearer e2e-owner", "content-type": "multipart/form-data; boundary=x" }, body: "x" })).status === 503,
    "managed policy refusal closes Python upload");
  h.expect((await h.fakes.requests("pypi.org")).filter((row) => row.method === "POST").length === uploads.length,
    "managed policy refusal prevents another upstream Python write");
}
