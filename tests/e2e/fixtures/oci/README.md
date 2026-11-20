Row 24 fixtures: two real, tiny OCI images (one gzip tar layer with `hello.txt`, a config whose `created` is 2001 and whose
`rootfs.diff_ids` is the real digest of the uncompressed layer, and an image manifest), written by a script that is not kept (Python's
`tarfile` and `gzip` with a zero mtime, so the bytes are reproducible). `hello-1-*` is manifest digest sha256:577b279fbb75714946d1ac0d52740df5e7581024846ab74bd2c629bb82e534dd; `hello-2-*` is sha256:3da4e5095800a66b5b5fa190bfd9fa30cbfcc188a72c3d8d2bf74f510e18dd9a.
Podman (the native lane) and skopeo (the E2E client) unpack and verify them like any image.
