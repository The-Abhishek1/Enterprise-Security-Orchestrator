FROM debian:bookworm-slim
LABEL maintainer="xcloak-eso" tool="whatweb"

RUN apt-get update && apt-get install -y --no-install-recommends \
    whatweb ruby curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scan
RUN whatweb --version
CMD ["sleep", "infinity"]
