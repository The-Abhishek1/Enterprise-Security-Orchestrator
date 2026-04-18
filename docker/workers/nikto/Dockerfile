FROM debian:bookworm-slim
LABEL maintainer="xcloak-eso" tool="nikto"

RUN apt-get update && apt-get install -y --no-install-recommends \
    perl git curl ca-certificates procps \
    libnet-ssleay-perl libio-socket-ssl-perl \
    libjson-perl libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

WORKDIR /scan
RUN perl /opt/nikto/program/nikto.pl -Version
CMD ["sleep", "infinity"]
