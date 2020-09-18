#!/bin/bash

# Runs a minimal setup with local binaries locally.
# This should be most helpful when working on Observatorium API specific features.

set -euo pipefail

result=1
trap 'kill $(jobs -p); exit $result' EXIT

(./tmp/bin/dex serve ./test/config/dex.yaml) &

(
  ./observatorium \
    --web.listen=0.0.0.0:8443 \
    --web.internal.listen=0.0.0.0:8448 \
    --web.healthchecks.url=https://localhost:8443 \
    --tls.server.cert-file=./tmp/certs/server.pem \
    --tls.server.key-file=./tmp/certs/server.key \
    --tls.healthchecks.server-ca-file=./tmp/certs/ca.pem \
    --logs.read.endpoint=http://127.0.0.1:3100 \
    --logs.tail.endpoint=http://127.0.0.1:3100 \
    --logs.write.endpoint=http://127.0.0.1:3100 \
    --metrics.read.endpoint=http://127.0.0.1:9091 \
    --metrics.write.endpoint=http://127.0.0.1:19291 \
    --rbac.config=./test/config/rbac.yaml \
    --tenants.config=./test/config/tenants.yaml \
    --log.level=debug
) &

(
  ./tmp/bin/thanos receive \
    --receive.hashrings-file=./test/config/hashrings.json \
    --receive.local-endpoint=127.0.0.1:10901 \
    --receive.default-tenant-id="1610b0c3-c509-4592-a256-a1871353dbfa" \
    --grpc-address=127.0.0.1:10901 \
    --http-address=127.0.0.1:10902 \
    --remote-write.address=127.0.0.1:19291 \
    --log.level=error \
    --tsdb.path="$(mktemp -d)"
) &

(
  ./tmp/bin/thanos query \
    --grpc-address=127.0.0.1:10911 \
    --http-address=127.0.0.1:9091 \
    --store=127.0.0.1:10901 \
    --log.level=error \
    --web.external-prefix=/ui/metrics/v1
) &

(
  ./tmp/bin/loki \
    -log.level=error \
    -target=all \
    -config.file=./test/config/loki.yml
) &

echo "-------------------------------------------"
echo "- Waiting for dependencies to come up...  -"
echo "-------------------------------------------"
sleep 10

until curl --output /dev/null --silent --fail http://localhost:8448/ready; do
  printf '.'
  sleep 1
done

echo "---------------------------------------------"
echo "- You can start testing things locally now! -"
echo "---------------------------------------------"

wait

exit 0
