import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";

/// An OCI image-layout archive (what `ctr images import` and `skopeo copy oci-archive:` read) of one image of fixtures/oci: its manifest, config
/// and layer under blobs/sha256, `oci-layout`, and an `index.json` naming the manifest. The manifest digest is the image's digest (the
/// reference of a preload is `repository@<that digest>`). Returns { digest, archive }.
export function buildOciArchive({ fixtures, image, dir, name = "image.tar" }) {
  const read = (kind) => readFileSync(join(fixtures, `${image}-${kind}`));
  const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const stage = join(dir, "layout");
  rmSync(stage, { recursive: true, force: true });
  mkdirSync(join(stage, "blobs/sha256"), { recursive: true });
  const manifest = read("manifest");
  for (const bytes of [manifest, read("config"), read("layer")]) writeFileSync(join(stage, "blobs/sha256", sha(bytes)), bytes);
  writeFileSync(join(stage, "oci-layout"), JSON.stringify({ imageLayoutVersion: "1.0.0" }));
  writeFileSync(join(stage, "index.json"), JSON.stringify({ schemaVersion: 2, manifests: [{ mediaType: "application/vnd.oci.image.manifest.v1+json", digest: `sha256:${sha(manifest)}`, size: manifest.length }] }));
  const archive = join(dir, name);
  mkdirSync(dirname(archive), { recursive: true });
  const made = spawnSync("tar", ["-C", stage, "-cf", archive, "."], { encoding: "utf8" });
  if (made.status !== 0) throw new Error(`tar failed: ${made.stderr}`);
  return { digest: `sha256:${sha(manifest)}`, archive };
}
