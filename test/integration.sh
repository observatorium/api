#!/bin/bash

# Runs a semi-realistic integration test with one producer generating metrics,
# a Observatorium API, a thanos receive for ingestion, and a thanos query for querying the metrics.

set -euo pipefail

result=1
trap 'kill $(jobs -p); exit $result' EXIT

(
  ./observatorium \
    --web.listen=0.0.0.0:8080 \
    --metrics.ui.endpoint=http://127.0.0.1:9091/ \
    --metrics.read.endpoint=http://127.0.0.1:9091/api/v1 \
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

echo "## waiting for dependencies to come up..."
sleep 5

if ./tmp/bin/up \
  --listen=0.0.0.0:8888 \
  --endpoint-read=http://127.0.0.1:8080/api/metrics/v1/api/v1/query \
  --endpoint-write=http://127.0.0.1:8080/api/metrics/v1/write \
  --period=500ms \
  --initial-query-delay=250ms \
  --threshold=1 \
  --latency=10s \
  --duration=10s \
  --log.level=debug \
  --name=observatorium_write \
  --labels='_id="test"'; then
  result=0
  echo "## tests: ok"
  exit 0
fi

echo "## tests: failed" 1>&2
result=1
exit 1
