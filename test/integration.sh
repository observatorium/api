#!/bin/bash

# Runs a semi-realistic integration test with one producer generating metrics,
# a Observatorium API, a thanos receive for ingestion, and a thanos query for querying the metrics.

set -euo pipefail

trap 'kill $(jobs -p); exit 0' EXIT

(
  ./observatorium \
    --web.listen=0.0.0.0:8080 \
    --metrics.ui.endpoint=http://127.0.0.1:9091/ \
    --metrics.query.endpoint=http://127.0.0.1:9091/api/v1/query \
    --metrics.write.endpoint=http://127.0.0.1:19291/api/v1/receive \
    --log.level=debug
) &

(
  ./tmp/bin/thanos receive \
    --grpc-address=127.0.0.1:10901 \
    --http-address=127.0.0.1:10902 \
    --remote-write.address=127.0.0.1:19291 \
    --tsdb.path="$(mktemp -d)"
  # --log.level=debug \
) &

(
  ./tmp/bin/thanos query \
    --grpc-address=127.0.0.1:10911 \
    --http-address=127.0.0.1:9091 \
    --store=127.0.0.1:10901 \
    --web.external-prefix=http://localhost:8080/ui/v1/metrics
  #    --log.level=debug \
) &

tmpresult=$(mktemp)
(
./tmp/bin/up \
  --listen=0.0.0.0:8888 \
  --endpoint-read=http://127.0.0.1:8080/api/v1/metrics/query \
  --endpoint-write=http://127.0.0.1:8080/api/v1/metrics/write \
  --period=1s \
  --threshold=1 \
  --latency=10s \
  --duration=10s \
  --log.level=debug \
  --name=observatorium_write \
  --labels='_id="test"'; echo $? > "$tmpresult"
) &

wait $!
read -r result < "$tmpresult"
pkill -P $$

if [ "$result" -eq 0 ]; then
  echo "tests: ok"
  exit 0
fi

echo "tests: failed" 1>&2
exit 1
