FROM alpine:3.19

LABEL eso.tool="true" \
    eso.tool.name="nikto" \
    eso.tool.version="2.5.0" \
    eso.tool.command="nikto" \
    eso.tool.description="Web server vulnerability scanner" \
    eso.tool.capabilities="web_vuln_scan,server_misconfiguration" \
    eso.tool.cpu="0.5" \
    eso.tool.memory="256Mi" \
    eso.tool.disk="100Mi" \
    eso.tool.timeout="600"

RUN apk add --no-cache \
    perl \
    perl-net-ssleay \
    perl-io-socket-ssl \
    perl-json \
    git \
    bash \
    curl

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    chmod +x /opt/nikto/program/nikto.pl && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

RUN nikto -h || true

ENTRYPOINT []
CMD ["sleep", "infinity"]
