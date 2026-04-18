FROM debian:bookworm-slim
LABEL maintainer="xcloak-eso" tool="ffuf"

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    -O /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm -rf /tmp/ffuf*

RUN mkdir -p /usr/share/seclists/Discovery/Web-Content && \
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    -O /usr/share/seclists/Discovery/Web-Content/common.txt 2>/dev/null || \
    printf 'index.php\nadmin\napi\nlogin\nstatic\n.env\nconfig\nbackup\n' \
    > /usr/share/seclists/Discovery/Web-Content/common.txt

WORKDIR /scan
RUN ffuf -V
CMD ["sleep", "infinity"]
