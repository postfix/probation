// E2E-031 smoke subset: installs through the deployed stack from the real public
// registries (no fakes): a scoped transitive npm tree with audit on, a large packument,
// and pip packages from pypi.org and files.pythonhosted.org. Alerts only (D1, D6).

export const meta = {
  id: "E2E-031-canary",
  title: "Live public registries canary (smoke subset)",
  suites: ["canary"],
};

export default async function canary(h) {
  const { key } = h.bootstrap;
  const npmrc = `registry=https://fw1.e2e.test/npm/\n//fw1.e2e.test/npm/:_authToken=${key}\n`;
  const pipConf = `[global]\nindex-url = https://key:${key}@fw1.e2e.test/pypi/simple/\n`;

  let run = h.npm("install express @babel/core typescript --no-fund", { npmrc });
  h.expect(run.status === 0, `npm install exited ${run.status}\n${run.stdout}\n${run.stderr}`);
  run = h.pip("install --no-cache-dir requests", { pipConf });
  h.expect(run.status === 0, `pip install exited ${run.status}\n${run.stdout}\n${run.stderr}`);
  h.log("live installs passed");
}
