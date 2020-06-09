#!/bin/bash

# Runs a semi-realistic integration test with one producer generating metrics,
# a Observatorium API, a thanos receive for ingestion, a thanos query for querying the metrics
# and a loki for reading and writing logs.

set -euo pipefail

result=1
trap 'kill $(jobs -p); exit $result' EXIT

DEFAULT_TLS_CONFIG="mtls"
UP_BIN="./tmp/bin/up"
OBSERVATORIUM_BIN="./observatorium"

usage() {
    echo
    echo "Usage: $(basename "$0")"
    echo "            [-t|--tls **mtls** | tls | no-tls]"
    echo "            [-h|--help]"
    echo
    echo "        '-t|--tls' tests TLS configuration (default: $DEFAULT_TLS_CONFIG)"
    echo "        '-h|--help' display help"
    echo
    exit 1
}

if [ $# -eq 0 ]; then
    TLS_CFG=${TLS_CFG:-$DEFAULT_TLS_CONFIG}
else
    case "$1" in
        -t|--tls)
            TLS_CFG="$2"
            if [ "$TLS_CFG" != "mtls" ] && [ "$TLS_CFG" != "tls" ] &&  [ "$TLS_CFG" != "no-tls" ]; then
                echo "ERROR: valid tests TLS configuration options are: mtls | tls | no-tls"
                exit 1
            fi
            ;;
        -h|--help)
            usage
            ;;
            *)
            usage
            ;;
        esac
fi

if [ "$TLS_CFG" = "mtls" ]; then
    OBSERVATORIUM_TLS_ARGS="
    --tls-cert-file=./tmp/certs/server.pem
    --tls-client-ca-file=./tmp/certs/ca.pem
    --tls-private-key-file=./tmp/certs/server.key
    "
    UP_TLS_ARGS="
    --tls-ca-file=./tmp/certs/ca.pem
    --tls-client-cert-file=./tmp/certs/client.pem
    --tls-client-private-key-file=./tmp/certs/client.key
    "
    UP_ENDPOINT_URL_PREFIX="https"
elif [ "$TLS_CFG" = "tls" ]; then
    OBSERVATORIUM_TLS_ARGS="
    --tls-cert-file=./tmp/certs/server.pem
    --tls-private-key-file=./tmp/certs/server.key
    "
    UP_TLS_ARGS="
    --tls-ca-file=./tmp/certs/ca.pem
    --tls-client-cert-file=./tmp/certs/client.pem
    --tls-client-private-key-file=./tmp/certs/client.key
    "
    UP_ENDPOINT_URL_PREFIX="https"
elif [ "$TLS_CFG" = "no-tls" ]; then
    OBSERVATORIUM_TLS_ARGS=""
    UP_TLS_ARGS=""
    UP_ENDPOINT_URL_PREFIX="http"
fi
OBSERVATORIUM_TLS_ARGS=$(echo "$OBSERVATORIUM_TLS_ARGS"|tr -d '\n')
UP_TLS_ARGS=$(echo "$UP_TLS_ARGS"|tr -d '\n')

(./tmp/bin/dex serve ./test/config/dex.yaml) &

printf "\t## getting authentication token..."
sleep 2

token=$(curl --request POST \
    --silent \
    --url http://localhost:5556/dex/token \
    --header 'content-type: application/x-www-form-urlencoded' \
    --data grant_type=password \
    --data username=admin@example.com \
    --data password=password \
    --data client_id=test \
    --data client_secret=ZXhhbXBsZS1hcHAtc2VjcmV0  \
    --data scope="openid email" | sed 's/^{.*"id_token":[^"]*"\([^"]*\)".*}/\1/')

(
  OBSERVATORIUM_ARGS=$(echo "
    --web.listen=0.0.0.0:8443
    --logs.read.endpoint=http://127.0.0.1:3100
    --logs.write.endpoint=http://127.0.0.1:3100
    --metrics.read.endpoint=http://127.0.0.1:9091
    --metrics.write.endpoint=http://127.0.0.1:19291
    --rbac.config=./test/config/rbac.yaml
    --tenants.config=./test/config/tenants.yaml
    --log.level=debug
    $OBSERVATORIUM_TLS_ARGS
  "| tr -d '\n')

  eval "$OBSERVATORIUM_BIN" "$OBSERVATORIUM_ARGS"
) &

(
  ./tmp/bin/thanos receive \
    --receive.hashrings-file=./test/config/hashrings.json \
    --receive.local-endpoint=127.0.0.1:10901 \
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

(
  ./tmp/bin/loki \
    -log.level=info \
    -target=all \
    -config.file=./test/config/loki.yml
) &

printf "\t## waiting for dependencies to come up..."
sleep 10

echo "-------------------------------------------"
echo "- Metrics tests                           -"
echo "-------------------------------------------"

UP_METRICS_TEST_FLAGS=$(echo "
  --listen=0.0.0.0:8888
  --endpoint-type=metrics
  --endpoint-read=$UP_ENDPOINT_URL_PREFIX://127.0.0.1:8443/api/metrics/v1/test/api/v1/query
  --endpoint-write=$UP_ENDPOINT_URL_PREFIX://127.0.0.1:8443/api/metrics/v1/test/api/v1/receive
  --period=500ms
  --initial-query-delay=250ms
  --threshold=1
  --latency=10s
  --duration=10s
  --log.level=debug
  --name=observatorium_write
  --labels='_id=\"test\"'
  $UP_TLS_ARGS
  --token=$token
"| tr -d '\n')

if eval "$UP_BIN" "$UP_METRICS_TEST_FLAGS"; then
  result=0
  printf "\t## metrics tests: ok\n\n"
else
  result=1
  printf "\t## metrics tests: failed\n\n"
  exit 1
fi

echo "-------------------------------------------"
echo "- Logs tests                              -"
echo "-------------------------------------------"

UP_LOGS_TEST_FLAGS=$(echo "
  --listen=0.0.0.0:8888
  --endpoint-type=logs
  --endpoint-read=$UP_ENDPOINT_URL_PREFIX://127.0.0.1:8443/api/logs/v1/test/api/v1/query
  --endpoint-write=$UP_ENDPOINT_URL_PREFIX://127.0.0.1:8443/api/logs/v1/test/api/v1/push
  --period=500ms
  --initial-query-delay=250ms
  --threshold=1
  --latency=10s
  --duration=10s
  --log.level=debug
  --name=up_test
  --labels='foo=\"bar\"'
  --logs='[\"$(date '+%s%N')\",\"log line 1\"]'
  $UP_TLS_ARGS
  --token=$token
"| tr -d '\n')

if eval "$UP_BIN" "$UP_LOGS_TEST_FLAGS"; then
  result=0
  echo "## logs tests: ok"
else
  result=1
  printf "## logs tests: failed\n\n"
  exit 1
fi

printf "\t## all tests: ok\n\n" 1>&2
exit 0
