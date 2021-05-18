FROM python:alpine
LABEL MAINTAINER="Greg White grewhit25@gmail.com"

ENV TZ=Europe/London
ARG S6_VERSION='2.2.0.3'

RUN apk -U upgrade -a && \
    apk add --no-cache build-base gcc bash 

# Install s6 overlay
RUN apk add --no-cache wget && \
    ARCH="$(uname -m)"; \
    if [ "$ARCH" = 'armv7l' ]; then ARCH='armhf'; \
    elif [ "$ARCH" = 'x86_64' ]; then ARCH='x86'; \
    fi; \
    wget --no-check-certificate -qO /tmp/s6-overlay-$ARCH-installer https://github.com/just-containers/s6-overlay/releases/download/v${S6_VERSION}/s6-overlay-${ARCH}-installer && \
    chmod +x /tmp/s6-overlay-$ARCH-installer && /tmp/s6-overlay-$ARCH-installer / && \
    apk del wget

RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install pycryptodome paho-mqtt

WORKDIR /kettle
COPY *.py /kettle/
COPY root /

ENTRYPOINT ["/init"]