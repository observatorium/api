FROM golang:1.16-alpine3.14 as builder

RUN apk add --update --no-cache ca-certificates tzdata git make bash && update-ca-certificates

ADD . /opt
WORKDIR /opt

RUN git update-index --refresh; make build

FROM alpine:3.14 as runner

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /opt/observatorium-api /bin/observatorium-api

ARG BUILD_DATE
ARG VERSION
ARG VCS_REF
ARG DOCKERFILE_PATH

LABEL vendor="Observatorium" \
    name="observatorium/api" \
    description="Observatorium API" \
    io.k8s.display-name="observatorium/api" \
    io.k8s.description="Observatorium API" \
    maintainer="Observatorium <team-monitoring@redhat.com>" \
    version="$VERSION" \
    org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.description="Observatorium API" \
    org.label-schema.docker.cmd="docker run --rm observatorium/api" \
    org.label-schema.docker.dockerfile=$DOCKERFILE_PATH \
    org.label-schema.name="observatorium/api" \
    org.label-schema.schema-version="1.0" \
    org.label-schema.vcs-branch=$VCS_BRANCH \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/observatorium/api" \
    org.label-schema.vendor="observatorium/api" \
    org.label-schema.version=$VERSION


ENTRYPOINT ["/bin/observatorium-api"]
