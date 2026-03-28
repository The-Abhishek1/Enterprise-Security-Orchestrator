FROM ruby:3.2-alpine

LABEL eso.tool="true" \
    eso.tool.name="whatweb" \
    eso.tool.version="0.5.5" \
    eso.tool.command="whatweb" \
    eso.tool.description="Web technology fingerprinting and identification" \
    eso.tool.capabilities="tech_detection,web_fingerprint" \
    eso.tool.cpu="0.3" \
    eso.tool.memory="256Mi" \
    eso.tool.disk="100Mi" \
    eso.tool.timeout="120"

RUN apk add --no-cache \
    bash curl git build-base \
    ruby-dev yaml-dev

RUN gem install whatweb --no-document || \
    (git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    cd /opt/whatweb && bundle install --without development && \
    ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb)

RUN whatweb --version || true

ENTRYPOINT []
CMD ["sleep", "infinity"]
