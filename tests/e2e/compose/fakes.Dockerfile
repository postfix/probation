FROM docker.io/library/node:24.22.1-bookworm-slim
RUN apt-get update \
 && apt-get install --yes --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
