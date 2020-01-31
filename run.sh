#!/bin/bash

# Run Observatorium API Gateway with its dependencies.

set -euo pipefail

result=1
trap 'kill $(jobs -p); exit $result' EXIT

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
    --web.external-prefix=/ui/v1/metrics
) &

./observatorium \
  --web.listen=0.0.0.0:8080 \
  --metrics.ui.endpoint=http://127.0.0.1:9091/ \
  --metrics.query.endpoint=http://127.0.0.1:9091/api/v1/query \
  --metrics.write.endpoint=http://127.0.0.1:19291/api/v1/receive \
  --log.level=debug
