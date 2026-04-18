FROM debian:bookworm-slim
LABEL maintainer="xcloak-eso" tool="gobuster"

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz \
    -O /tmp/gobuster.tar.gz \
    && tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster \
    && chmod +x /usr/local/bin/gobuster \
    && rm -rf /tmp/gobuster*

# Install wordlists
RUN mkdir -p /usr/share/wordlists/dirb && \
    wget -q https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt \
    -O /usr/share/wordlists/dirb/common.txt 2>/dev/null || \
    printf 'index.php\nadmin\nlogin\nwp-admin\napi\nstatic\njs\ncss\nconfig\nbackup\ntest\ndev\n' \
    > /usr/share/wordlists/dirb/common.txt

WORKDIR /scan
RUN gobuster help 2>&1 | head -1
CMD ["sleep", "infinity"]
