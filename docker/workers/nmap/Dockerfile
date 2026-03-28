FROM alpine:3.19

LABEL eso.tool="true" \
      eso.tool.name="nmap" \
      eso.tool.version="7.94" \
      eso.tool.command="nmap" \
      eso.tool.description="Network discovery and port scanning" \
      eso.tool.capabilities="port_scan,service_detection,os_detection,network_scan" \
      eso.tool.cpu="0.5" \
      eso.tool.memory="512Mi" \
      eso.tool.disk="100Mi" \
      eso.tool.timeout="600"

RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    nmap-nselibs \
    bash \
    curl \
    bind-tools

# Verify nmap works with NSE
RUN nmap --version && \
    ls /usr/share/nmap/scripts/ | head -5

# No entrypoint — container runs sleep infinity, commands via docker exec
ENTRYPOINT []
CMD ["sleep", "infinity"]
