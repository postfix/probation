// A log collector, answering as https://fakes.e2e.test/siem: it stores every batch a
// firewall POSTs (`siem_url`), with the credential header it came with.

export class Siem {
  constructor() {
    this.reset();
  }

  reset() {
    this.batches = [];
  }

  handle(req, path, host, body) {
    if (req.method !== "POST" || !path.startsWith("/siem")) return { status: 404, body: "not found\n" };
    const records = body.toString().split("\n").filter(Boolean).map((line) => JSON.parse(line));
    this.batches.push({ at: new Date().toISOString(), auth: req.headers.authorization ?? null, contentType: req.headers["content-type"], records });
    return { status: 200, body: "" };
  }
}
