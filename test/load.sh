#!/bin/bash
set -euo pipefail

BIN_DIR=./tmp/bin
RESULT_DIR=./tmp/results

trap 'kill $(jobs -p); exit 0' EXIT

save() {
    # export the data for the last hour from http://localhost:9090
    mkdir -p "$RESULT_DIR"
    $BIN_DIR/styx 'histogram_quantile(0.99, sum by (job, le) (rate(http_request_duration_seconds_bucket{job="observatorium", handler="query_range"}[1m])))' >$RESULT_DIR/query_dur_99.csv
    $BIN_DIR/styx 'histogram_quantile(0.50, sum by (job, le) (rate(http_request_duration_seconds_bucket{job="observatorium", handler="query_range"}[1m])))' >$RESULT_DIR/query_dur_50.csv
    $BIN_DIR/styx 'sum(rate(http_request_duration_seconds_sum{job="observatorium", handler="query_range"}[1m])) * 100 / sum(rate(http_request_duration_seconds_count{job="observatorium", handler="query_range"}[1m]))' >$RESULT_DIR/query_dur_avg.csv
    $BIN_DIR/styx 'histogram_quantile(0.99, sum by (job, le) (rate(http_request_duration_seconds_bucket{job="observatorium", handler="write"}[1m])))' >$RESULT_DIR/write_dur_99.csv
    $BIN_DIR/styx 'histogram_quantile(0.50, sum by (job, le) (rate(http_request_duration_seconds_bucket{job="observatorium", handler="write"}[1m])))' >$RESULT_DIR/write_dur_50.csv
    $BIN_DIR/styx 'sum(rate(http_request_duration_seconds_sum{job="observatorium", handler="write"}[1m])) * 100 / sum(rate(http_request_duration_seconds_count{job="observatorium", handler="write"}[1m]))' >$RESULT_DIR/write_dur_avg.csv
}

(
    ./observatorium \
        --web.listen=0.0.0.0:8080 \
        --metrics.ui.endpoint=http://127.0.0.1:9091/ \
        --metrics.query.endpoint=http://127.0.0.1:9091/api/v1/query \
        --metrics.query-range.endpoint=http://127.0.0.1:9091/api/v1/query_range \
        --metrics.write.endpoint=http://127.0.0.1:19291/api/v1/receive
) &

(
    $BIN_DIR/thanos receive \
        --grpc-address=127.0.0.1:10901 \
        --http-address=127.0.0.1:10902 \
        --remote-write.address=127.0.0.1:19291 \
        --tsdb.path="$(mktemp -d)"
) &

(
    $BIN_DIR/thanos query \
        --grpc-address=127.0.0.1:10911 \
        --http-address=127.0.0.1:9091 \
        --store=127.0.0.1:10901 \
        --web.external-prefix=http://localhost:8080/ui/v1/metrics
) &

(
    $BIN_DIR/prometheus \
        --log.level=debug \
        --config.file=./test/config/prometheus.yml \
        --storage.tsdb.path="$(mktemp -d)"
) &

printf "\tWaiting for dependencies to come up...\n"
sleep 5

(
    $BIN_DIR/promremotebench \
        -query=true \
        -query-target=http://127.0.0.1:8080/api/v1/metrics/query_range \
        -query-step=30s \
        -query-concurrency=10 \
        -write=true \
        -target=http://127.0.0.1:8080/api/v1/metrics/write \
        -hosts=150 \
        -interval=5
) &

printf "\tRunning...\n"
sleep 30

printf "\tGenerating report\n"
save

exit $?
