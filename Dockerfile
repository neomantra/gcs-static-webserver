# Dockerfile
# Copyright (c) 2020 Neomantra Corp

###############################################################################
# Builder stage
###############################################################################

ARG GOLANG_IMAGE_BASE="golang"
ARG GOLANG_IMAGE_TAG="1.13-alpine"

ARG RUNTIME_IMAGE_BASE="alpine"
ARG RUNTIME_IMAGE_TAG="3.11"

FROM ${GOLANG_IMAGE_BASE}:${GOLANG_IMAGE_TAG} as builder

RUN apk update && apk upgrade && \
    apk add --no-cache bash git openssh openssl-dev build-base

RUN mkdir -p /src
ADD . /src
WORKDIR /src

RUN go mod tidy && go get -v all

RUN go build -o gcs-static-webserver


###############################################################################
# Production stage
###############################################################################

ARG RUNTIME_IMAGE_BASE="alpine"
ARG RUNTIME_IMAGE_TAG="3.11"

FROM ${RUNTIME_IMAGE_BASE}:${RUNTIME_IMAGE_TAG}

COPY --from=builder /src/gcs-static-webserver /app/

ENTRYPOINT /app/gcs-static-webserver

# Use SIGINT instead of default SIGTERM to cleanly drain requests
STOPSIGNAL SIGINT
