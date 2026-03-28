FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git && \
    go install github.com/ffuf/ffuf/v2@latest

FROM alpine:3.19

LABEL eso.tool="true" \
      eso.tool.name="ffuf" \
      eso.tool.version="2.1.0" \
      eso.tool.command="ffuf" \
      eso.tool.description="Fast web fuzzer for directory/file/parameter discovery" \
      eso.tool.capabilities="directory_bruteforce,parameter_fuzzing,vhost_discovery" \
      eso.tool.cpu="0.5" \
      eso.tool.memory="256Mi" \
      eso.tool.disk="100Mi" \
      eso.tool.timeout="300"

COPY --from=builder /go/bin/ffuf /usr/local/bin/ffuf

RUN apk add --no-cache bash curl && \
    mkdir -p /usr/share/wordlists/dirb && \
    wget -q -O /usr/share/wordlists/dirb/common.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt && \
    wget -q -O /usr/share/wordlists/dirb/big.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt

RUN ffuf -V

ENTRYPOINT []
CMD ["sleep", "infinity"]
