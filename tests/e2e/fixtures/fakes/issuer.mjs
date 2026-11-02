// Disposable nonce-capable issuer. OpenSSL signs live OCSP responses from its
// on-disk revocation index, so a control revocation changes the next answer.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const BASE = process.env.E2E_ISSUER_DIR ?? "/e2e/issuer";

function openssl(dir, ...args) {
  const run = spawnSync("openssl", args, { cwd: dir, encoding: "utf8", maxBuffer: 1024 * 1024 });
  if (run.status !== 0) throw new Error(`fake issuer openssl ${args[0]}: ${run.stderr}`);
}

function derAt(bytes, offset) {
  const tag = bytes[offset];
  let length = bytes[offset + 1];
  let start = offset + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (!count || count > 4) throw new Error("invalid fixture DER length");
    length = 0;
    for (let i = 0; i < count; i++) length = (length << 8) | bytes[start++];
  }
  if (start + length > bytes.length) throw new Error("truncated fixture DER");
  return { tag, start, end: start + length };
}

function derChild(bytes, parent, index) {
  let offset = parent.start;
  for (let i = 0; i <= index; i++) {
    const child = derAt(bytes, offset);
    if (child.end > parent.end) throw new Error("fixture DER child escapes parent");
    if (i === index) return child;
    offset = child.end;
  }
}

function corruptSignature(response) {
  const invalid = Buffer.from(response);
  const outer = derAt(invalid, 0); // OCSPResponse SEQUENCE
  const wrapped = derChild(invalid, outer, 1); // responseBytes [0]
  const responseBytes = derChild(invalid, wrapped, 0); // SEQUENCE
  const octets = derChild(invalid, responseBytes, 1); // BasicOCSPResponse OCTET STRING
  const basic = derAt(invalid, octets.start); // BasicOCSPResponse SEQUENCE
  const signature = derChild(invalid, basic, 2); // signature BIT STRING
  if (outer.tag !== 0x30 || wrapped.tag !== 0xa0 || responseBytes.tag !== 0x30
      || octets.tag !== 0x04 || basic.tag !== 0x30 || signature.tag !== 0x03
      || signature.end - signature.start < 2) throw new Error("no signed OCSP bytes");
  invalid[signature.start + 1] ^= 1; // skip BIT STRING's unused-bits byte
  return invalid;
}

function requestSerial(bytes) {
  const outer = derAt(bytes, 0);
  const tbs = derChild(bytes, outer, 0);
  const list = derChild(bytes, tbs, 0);
  const entry = derChild(bytes, list, 0);
  const certId = derChild(bytes, entry, 0);
  const serial = derChild(bytes, certId, 3);
  if (serial.tag !== 0x02 || serial.end === serial.start) throw new Error("OCSP request lacks a serial");
  return bytes.subarray(serial.start, serial.end).toString("hex");
}

export class Issuer {
  constructor(name) {
    this.name = name;
    this.dir = join(BASE, name);
    this.leaves = new Map();
    this.statusMode = "normal";
    this.previousResponse = null;
  }

  reset() {
    rmSync(this.dir, { recursive: true, force: true });
    this.leaves.clear();
    this.statusMode = "normal";
    this.previousResponse = null;
  }

  init() {
    mkdirSync(this.dir, { recursive: true });
    writeFileSync(join(this.dir, "index.txt"), "");
    writeFileSync(join(this.dir, "serial"), "1000\n");
    writeFileSync(join(this.dir, "ca.conf"),
      `[ca]\ndefault_ca=main\n[main]\ndatabase=${this.dir}/index.txt\nserial=${this.dir}/serial\nnew_certs_dir=${this.dir}\ncertificate=${this.dir}/ca.pem\nprivate_key=${this.dir}/ca.key\ndefault_md=sha256\npolicy=policy\nunique_subject=no\n[policy]\ncommonName=supplied\n`);
    openssl(this.dir, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
      "-subj", `/CN=probation-e2e-issuer-${this.name}`, "-addext", "basicConstraints=critical,CA:TRUE",
      "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", "ca.key", "-out", "ca.pem");
  }

  issue(memberUuid, aiaUrl = `https://ocsp-${this.name}.e2e.test/status`) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(memberUuid)) {
      throw new Error("a canonical member UUID is required");
    }
    if (!this.leaves.size && !readable(join(this.dir, "ca.pem"))) this.init();
    const id = randomBytes(8).toString("hex");
    openssl(this.dir, "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", `/CN=e2e-${id}`,
      "-keyout", `${id}.key`, "-out", `${id}.csr`);
    const ocspUrl = aiaUrl;
    if (!/^https:\/\/(?:ocsp-[ab]|private-ocsp)\.e2e\.test\/status$/.test(ocspUrl)) throw new Error("invalid fixture OCSP AIA");
    writeFileSync(join(this.dir, `${id}.ext`),
      `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:probation:member:${memberUuid}\nauthorityInfoAccess=OCSP;URI:${ocspUrl}\n`);
    openssl(this.dir, "ca", "-batch", "-config", "ca.conf", "-days", "2", "-in", `${id}.csr`,
      "-out", `${id}.pem`, "-extfile", `${id}.ext`, "-notext");
    const leafPem = readFileSync(join(this.dir, `${id}.pem`), "utf8");
    const rootPem = readFileSync(join(this.dir, "ca.pem"), "utf8");
    this.leaves.set(id, `${id}.pem`);
    return { id, memberUuid, ocspUrl, leafPem, rootPem,
      keyPem: readFileSync(join(this.dir, `${id}.key`), "utf8"), chainPem: leafPem + rootPem };
  }

  revoke(id) {
    const leaf = this.leaves.get(id);
    if (!leaf) throw new Error("unknown sample leaf");
    openssl(this.dir, "ca", "-config", "ca.conf", "-revoke", leaf);
    return { ok: true };
  }

  mode(mode) {
    if (!["normal", "no-nonce", "wrong-nonce", "wrong-serial", "wrong-issuer", "bad-signature", "replay"].includes(mode)) throw new Error("unknown OCSP mode");
    this.statusMode = mode;
    return { ok: true };
  }

  respond(request) {
    if (this.statusMode === "replay" && this.previousResponse) return this.previousResponse;
    const token = randomBytes(8).toString("hex");
    const requestFile = `${token}.req`;
    const responseFile = `${token}.resp`;
    let signedRequest = request;
    if (this.statusMode === "wrong-nonce") {
      signedRequest = Buffer.from(request);
      // The firewall sends 32 bytes; OpenSSL CLI probes send 16.
      let length = 32;
      let at = signedRequest.lastIndexOf(Buffer.from([0x04, length]));
      if (at < 0) { length = 16; at = signedRequest.lastIndexOf(Buffer.from([0x04, length])); }
      if (at < 0 || at + 2 + length > signedRequest.length) throw new Error("OCSP request lacks nonce");
      signedRequest[at + 2] ^= 1;
    } else if (this.statusMode === "wrong-serial") {
      signedRequest = Buffer.from(request);
      const serial = Buffer.from([0x02, 0x02, 0x10]);
      const at = signedRequest.indexOf(serial);
      if (at < 0) throw new Error("OCSP request lacks fixture serial");
      signedRequest[at + 3] ^= 0x7f;
    }
    writeFileSync(join(this.dir, requestFile), signedRequest);
    const args = ["ocsp", "-index", "index.txt", "-rsigner", "ca.pem", "-rkey", "ca.key", "-CA", "ca.pem"];
    if (this.statusMode === "no-nonce") {
      // -reqin copies the request nonce even with -no_nonce. Generate by issuer
      // and serial instead, keeping the CertID while omitting the nonce.
      args.push("-issuer", "ca.pem", "-serial", `0x${requestSerial(request)}`, "-no_nonce");
    } else {
      args.push("-reqin", requestFile);
    }
    args.push("-nmin", "2", "-respout", responseFile);
    try {
      openssl(this.dir, ...args);
      const response = readFileSync(join(this.dir, responseFile));
      if (this.statusMode === "bad-signature") {
        return corruptSignature(response);
      }
      this.previousResponse = response;
      return response;
    } finally {
      rmSync(join(this.dir, requestFile), { force: true });
      rmSync(join(this.dir, responseFile), { force: true });
    }
  }
}

function readable(path) {
  try { readFileSync(path); return true; } catch { return false; }
}
