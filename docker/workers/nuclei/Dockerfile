FROM projectdiscovery/nuclei:latest AS nuclei-bin

FROM alpine:3.19

LABEL eso.tool="true" \
      eso.tool.name="nuclei" \
      eso.tool.version="3.1.0" \
      eso.tool.command="nuclei" \
      eso.tool.description="Fast vulnerability scanner" \
      eso.tool.capabilities="vuln_scan,template_based,web_scan" \
      eso.tool.cpu="1.0" \
      eso.tool.memory="1Gi" \
      eso.tool.disk="500Mi" \
      eso.tool.timeout="1200"

RUN apk add --no-cache \
    bash \
    curl \
    ca-certificates \
    bind-tools \
    git

# Copy nuclei binary from official image
COPY --from=nuclei-bin /usr/local/bin/nuclei /usr/local/bin/nuclei

# Pre-download templates so first scan doesn't waste 60s
RUN nuclei -update-templates 2>/dev/null || true

# Verify
RUN nuclei -version

ENTRYPOINT []
CMD ["sleep", "infinity"]
