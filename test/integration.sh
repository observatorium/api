#!/bin/bash

# Runs a semi-realistic integration test with one producer generating metrics,
# a Observatorium API, a thanos receive for ingestion, and a thanos query for querying the metrics.

set -euo pipefail

result=1
trap 'kill $(jobs -p); exit $result' EXIT

(
  ./observatorium \
    --web.listen=0.0.0.0:8443 \
    --tls-cert-file=./tmp/certs/server.pem \
    --tls-client-ca-file=./tmp/certs/ca.pem \
    --tls-private-key-file=./tmp/certs/server.key \
    --metrics.read.endpoint=http://127.0.0.1:9091 \
    --metrics.write.endpoint=http://127.0.0.1:19291/api/v1/receive \
    --log.level=debug
) &

(
  ./tmp/bin/thanos receive \
    --grpc-address=127.0.0.1:10901 \
    --http-address=127.0.0.1:10902 \
    --remote-write.address=127.0.0.1:19291 \
    --log.level=debug \
    --tsdb.path="$(mktemp -d)"
) &

(
  ./tmp/bin/thanos query \
    --grpc-address=127.0.0.1:10911 \
    --http-address=127.0.0.1:9091 \
    --store=127.0.0.1:10901 \
    --log.level=debug \
    --web.external-prefix=/ui/metrics/v1
) &

printf "\t## waiting for dependencies to come up..."
sleep 5

if ./tmp/bin/up \
  --listen=0.0.0.0:8888 \
  --tls-ca-file=./tmp/certs/ca.pem \
  --tls-client-cert-file=./tmp/certs/client.pem \
  --tls-client-private-key-file=./tmp/certs/client.key \
  --endpoint-read=https://127.0.0.1:8443/api/metrics/v1/api/v1/query \
  --endpoint-write=https://127.0.0.1:8443/api/metrics/v1/write \
  --period=500ms \
  --initial-query-delay=250ms \
  --threshold=1 \
  --latency=10s \
  --duration=10s \
  --log.level=debug \
  --name=observatorium_write \
  --labels='_id="test"'; then
  result=0
  printf "\t## tests: ok"
  exit 0
fi

printf "\t## tests: failed" 1>&2
result=1
exit 1
