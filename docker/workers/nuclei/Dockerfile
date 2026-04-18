FROM debian:bookworm-slim
LABEL maintainer="xcloak-eso" tool="nuclei"

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates curl unzip procps git \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei binary
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.4/nuclei_3.2.4_linux_amd64.zip \
    -O /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /tmp/ \
    && mv /tmp/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei*

WORKDIR /scan

# Pre-download templates (speeds up first scan)
RUN nuclei -update-templates 2>/dev/null || true
RUN nuclei -version

CMD ["sleep", "infinity"]
