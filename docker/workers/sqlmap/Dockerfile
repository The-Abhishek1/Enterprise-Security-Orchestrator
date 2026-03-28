FROM alpine:3.19

LABEL eso.tool="true" \
      eso.tool.name="sqlmap" \
      eso.tool.version="1.8" \
      eso.tool.command="sqlmap" \
      eso.tool.description="SQL injection detection and exploitation" \
      eso.tool.capabilities="sql_injection" \
      eso.tool.cpu="0.5" \
      eso.tool.memory="512Mi" \
      eso.tool.disk="100Mi" \
      eso.tool.timeout="600"

RUN apk add --no-cache \
    python3 \
    py3-pip \
    bash \
    curl \
    ca-certificates \
    bind-tools \
    git

# Install sqlmap from git (always latest)
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# Create wrapper script
RUN printf '#!/bin/sh\npython3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap && \
    chmod +x /usr/local/bin/sqlmap

# Verify
RUN sqlmap --version

ENTRYPOINT []
CMD ["sleep", "infinity"]
