// The fake leaked-password range API, answering as https://api.pwnedpasswords.com:
// GET /range/<first 5 hex of SHA-1> lists `SUFFIX:COUNT` lines (k-anonymity).

import { createHash } from "node:crypto";

export class Hibp {
  constructor() {
    this.reset();
  }

  reset() {
    this.leaked = new Set();
    for (const password of ["password1234", "correcthorsebatterystaple", "leaked-password-e2e"]) this.leak(password);
  }

  leak(password) {
    this.leaked.add(createHash("sha1").update(password).digest("hex").toUpperCase());
  }

  handle(req, path) {
    const match = path.match(/^\/range\/([0-9A-Fa-f]{5})$/);
    if (!match) return { status: 404, body: "Not Found" };
    const prefix = match[1].toUpperCase();
    const lines = [...this.leaked].filter((hash) => hash.startsWith(prefix)).map((hash) => `${hash.slice(5)}:42`);
    return { status: 200, headers: { "content-type": "text/plain" }, body: lines.join("\r\n") };
  }
}
