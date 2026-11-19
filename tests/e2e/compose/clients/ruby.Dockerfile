# A Ruby client container: the pinned Ruby image, which carries RubyGems and Bundler (the stack
# itself is offline, so nothing is installed at run time).
ARG RUBY_IMAGE=docker.io/library/ruby:3.3.8-slim-bookworm
FROM ${RUBY_IMAGE}
WORKDIR /work
