FROM debian:bookworm-slim
LABEL maintainer="xcloak-eso" tool="sqlmap"

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip git curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /opt/sqlmap/sqlmap.py

WORKDIR /scan
RUN python3 /opt/sqlmap/sqlmap.py --version
CMD ["sleep", "infinity"]
