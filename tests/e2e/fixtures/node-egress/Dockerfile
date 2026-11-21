# The node egress rules (deploy/kubernetes/node) loaded into a throwaway network namespace: a rootless container with CAP_NET_ADMIN gets
# its own netns, so nothing here touches the host firewall. The base is pinned by digest (a moving tag is a supply-chain input to a test
# that holds CAP_NET_ADMIN); `apk add` still runs at build time.
FROM docker.io/library/alpine@sha256:9db2934886712d877c932e07249c75a59e6ca27adfbccc05261987a17bef2d63
RUN apk add --no-cache nftables iproute2 busybox-extras socat
