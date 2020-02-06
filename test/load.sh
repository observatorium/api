#!/bin/bash
set -euo pipefail

BIN_DIR=./tmp/bin
RESULT_DIR=./tmp/results

result=1
trap 'kill $(jobs -p); exit $result' EXIT

SN=${1:-10}
MN=${2:-10}
LN=${3:-10}
GOAL=${4:-5000}

test_load() {
    local current=$1
    local goal=$2
    local sn=$3
    local mn=$4
    local ln=$5
    local success=0
    while [ "$goal" == 0 ] || [ "$success" -lt "$goal" ]; do
        write "$current" "$sn" "$mn" "$ln"
        if ! save "$current"; then
            break
        fi
        jobs -p | xargs -r kill
        success=$current
        current=$((current + 1000))
    done
    printf "\tSuccessfully handled %s requests!\n" "$success"

    # Only return non-zero if we set a goal and didn't meet it.
    if [ "$goal" -gt 0 ] && [ "$success" -lt "$goal" ]; then
        return 1
    fi
    return 0
}

write() {
    local rwn=$1
    local sn=$2
    local mn=$3
    local ln=$4
    $BIN_DIR/avalanche \
        --remote-url=http://127.0.0.1:8080/api/v1/metrics/write \
        --metric-count="$mn" \
        --label-count="$ln" \
        --series-count="$sn" \
        --remote-requests-count="$rwn" \
        --value-interval=5
}

query() {
    curl --fail --silent -G -k http://127.0.0.1:8080/api/v1/metrics/query --data-urlencode 'query=sum_over_time(count({job="observatorium"})[1h:])' >/dev/null
}

save() {
    local n=$1
    # export the data for the last hour from http://localhost:9090
    mkdir -p "$RESULT_DIR"
    $BIN_DIR/styx 'irate(process_cpu_seconds_total{job="observatorium")[1m]} * 100' >$RESULT_DIR/"$n"_cpu.csv
    $BIN_DIR/styx 'process_resident_memory_bytes{job="observatorium"}' >$RESULT_DIR/"$n"_mem.csv
    $BIN_DIR/styx 'histogram_quantile(0.99, sum by (job, le) (http_request_duration_seconds_bucket{job="observatorium", handler="query_range"}[1m]))' >$RESULT_DIR/"$n"_dur_99.csv
    $BIN_DIR/styx 'histogram_quantile(0.50, sum by (job, le) (http_request_duration_seconds_bucket{job="observatorium", handler="query_range"}[1m]))' >$RESULT_DIR/"$n"_dur_50.csv
    $BIN_DIR/styx 'sum(rate(http_request_duration_seconds_sum{job="observatorium"}[1m])) * %s / sum(rate(http_request_duration_seconds_count{job="observatorium"}[1m]))' >$RESULT_DIR/"$n"_dur_avg.csv
}

(
    ./observatorium \
        --web.listen=0.0.0.0:8080 \
        --metrics.ui.endpoint=http://127.0.0.1:9091/ \
        --metrics.query.endpoint=http://127.0.0.1:9091/api/v1/query \
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
        --config.file=./test/config/prometheus.yml \
        --storage.tsdb.path="$(mktemp -d)"
) &

printf "\tWaiting for dependencies to come up..."
sleep 5

(
    while query; do
        printf "\tno query failures; "
        printf "checking again in 1s...\n"
        sleep 1
    done
    printf "\tQuery failed; "
    exit 1
) &

test_load "1000" "$GOAL" "$SN" "$MN" "$LN"

exit $?
