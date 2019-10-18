FROM golang:1.13.1-alpine3.10 as builder

RUN apk add --update --no-cache ca-certificates tzdata git make && update-ca-certificates

ADD . /opt
WORKDIR /opt

RUN git update-index --refresh; make observatorium

FROM scratch as runner

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /opt/observatorium /bin/observatorium

ARG BUILD_DATE
ARG VERSION
ARG VCS_REF
ARG DOCKERFILE_PATH

LABEL vendor="Observatorium" \
    name="observatorium/observatorium" \
    description="Observatorium API" \
    io.k8s.display-name="observatorium/observatorium" \
    io.k8s.description="Observatorium API" \
    maintainer="Observatorium <team-monitoring@redhat.com>" \
    version="$VERSION" \
    org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.description="Observatorium API" \
    org.label-schema.docker.cmd="docker run --rm observatorium/observatorium" \
    org.label-schema.docker.dockerfile=$DOCKERFILE_PATH \
    org.label-schema.name="observatorium/observatorium" \
    org.label-schema.schema-version="1.0" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/observatorium/observatorium" \
    org.label-schema.vendor="observatorium/observatorium" \
    org.label-schema.version=$VERSION

ENTRYPOINT ["/bin/observatorium"]
