FROM ghcr.io/oj/gobuster:latest AS gobuster-bin

FROM alpine:3.19

LABEL eso.tool="true" \
  eso.tool.name="gobuster" \
  eso.tool.version="3.6.0" \
  eso.tool.command="gobuster" \
  eso.tool.description="Directory and DNS brute-forcing" \
  eso.tool.capabilities="directory_bruteforce,dns_enumeration" \
  eso.tool.cpu="0.5" \
  eso.tool.memory="512Mi" \
  eso.tool.disk="200Mi" \
  eso.tool.timeout="900"

RUN apk add --no-cache \
  bash \
  curl \
  ca-certificates \
  bind-tools

# Copy gobuster binary
COPY --from=gobuster-bin /app/gobuster /usr/local/bin/gobuster

# Install common wordlists
RUN mkdir -p /usr/share/wordlists/dirb && \
  curl -sL https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt \
  -o /usr/share/wordlists/dirb/common.txt && \
  curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt \
  -o /usr/share/wordlists/dirb/directory-list-2.3-small.txt

# Verify
RUN gobuster help

ENTRYPOINT []
CMD ["sleep", "infinity"]
