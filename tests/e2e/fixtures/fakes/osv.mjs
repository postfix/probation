// The fake OSV API, answering as https://api.osv.dev: POST /v1/querybatch. The
// ecosystem must be spelled exactly as OSV's schema does (`npm`, `PyPI`); anything
// else is refused with 400, as a misspelt ecosystem must never look like "no finding".

import { normalize } from "./pypi.mjs";

const ECOSYSTEMS = new Set(["npm", "PyPI"]);
const key = (ecosystem, name, version) => `${ecosystem}\0${ecosystem === "PyPI" ? normalize(name) : name}\0${version}`;

export class Osv {
  constructor() {
    this.reset();
  }

  reset() {
    this.vulns = new Map();
    this.queries = [];
  }

  /// Marks (ecosystem, name, version) with advisory `ids` (for example `MAL-2026-1`,
  /// `GHSA-xxxx`); an empty list clears it.
  flag({ ecosystem, name, version, ids }) {
    if (ids.length) this.vulns.set(key(ecosystem, name, version), ids);
    else this.vulns.delete(key(ecosystem, name, version));
  }

  handle(req, path, host, body) {
    if (req.method !== "POST" || path !== "/v1/querybatch") return { status: 404, body: '{"code":5,"message":"Not Found"}' };
    let queries;
    try {
      queries = JSON.parse(body.toString()).queries;
    } catch {
      return { status: 400, body: '{"code":3,"message":"Invalid JSON"}' };
    }
    if (!Array.isArray(queries)) return { status: 400, body: '{"code":3,"message":"queries missing"}' };
    for (const query of queries) {
      this.queries.push(query);
      if (!ECOSYSTEMS.has(query?.package?.ecosystem)) {
        return { status: 400, body: JSON.stringify({ code: 3, message: `Invalid ecosystem ${JSON.stringify(query?.package?.ecosystem)}` }) };
      }
    }
    const modified = new Date().toISOString();
    const results = queries.map(({ package: p, version }) => {
      const ids = this.vulns.get(key(p.ecosystem, p.name, version)) ?? [];
      return ids.length ? { vulns: ids.map((id) => ({ id, modified })) } : {};
    });
    return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify({ results }) };
  }
}
