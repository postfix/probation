# A Go client container: the pinned Go image (Go 1.26.0). The stack itself is offline, so nothing is
# installed at run time; the module proxy is the firewall, reached over TLS (the CA is SSL_CERT_FILE).
ARG GO_IMAGE=docker.io/library/golang:1.26.0-bookworm
FROM ${GO_IMAGE}
WORKDIR /work
