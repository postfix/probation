# A NuGet client container: the pinned .NET SDK image (8.0.416, NuGet 6.11). The stack itself is offline, so
# nothing is installed at run time; the package source is the firewall, reached over TLS (the CA is SSL_CERT_FILE).
ARG DOTNET_IMAGE=mcr.microsoft.com/dotnet/sdk:8.0.416-bookworm-slim
FROM ${DOTNET_IMAGE}
WORKDIR /work
