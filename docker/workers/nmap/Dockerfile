FROM debian:bookworm-slim
LABEL maintainer="xcloak-eso" tool="nmap"

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap nmap-common curl iputils-ping dnsutils procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scan
RUN nmap --version
CMD ["sleep", "infinity"]
