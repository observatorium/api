#!/bin/bash
set -euo pipefail

DATA_DIR=./docs/loadtests/results
DOC_DIR=./docs

STYX=${STYX:-styx}
PROMETHEUS=${PROMETHEUS:-prometheus}
MOCKPROVIDER=${MOCKPROVIDER:-mockprovider}
PROMREMOTEBENCH=${PROMREMOTEBENCH:-promremotebench}

trap 'kill $(jobs -p); exit 0' EXIT

generate_report() {
    printf "\tGenerating report...\n"

    mkdir -p "$DATA_DIR"

    case $1 in
    csv)
        collect "$STYX" "$1"
        ;;

    gnuplot)
        collect "$STYX gnuplot" "$1"
        plot
        ;;
    *)
        echo "usage: $(basename "$0") { csv | gnuplot }"
        ;;
    esac
}

collect() {
    cmd=$1
    ext=$2
    # export the data for the last hour from http://127.0.0.1:9090
    # See https://github.com/go-pluto/styx for further details.
    $cmd 'rate(process_cpu_seconds_total{job="observatorium"}[1m]) * 1000' >$DATA_DIR/cpu."$ext"
    $cmd 'process_resident_memory_bytes{job="observatorium"}' >$DATA_DIR/mem."$ext"
    $cmd 'go_goroutines{job="observatorium"}' >$DATA_DIR/goroutines."$ext"

    $cmd 'histogram_quantile(0.99, sum by (job, le) (rate(http_request_duration_seconds_bucket{job="observatorium", handler="write"}[1m])))' >$DATA_DIR/write_dur_99."$ext"
    $cmd 'histogram_quantile(0.99, sum by (job, le) (rate(http_request_duration_seconds_bucket{job="observatorium", handler="query_range"}[1m])))' >$DATA_DIR/query_range_dur_99."$ext"

    $cmd 'histogram_quantile(0.50, sum by (job, le) (rate(http_request_duration_seconds_bucket{job="observatorium", handler="write"}[1m])))' >$DATA_DIR/write_dur_50."$ext"
    $cmd 'histogram_quantile(0.50, sum by (job, le) (rate(http_request_duration_seconds_bucket{job="observatorium", handler="query_range"}[1m])))' >$DATA_DIR/query_range_dur_50."$ext"

    $cmd '100 * (sum by (job) (rate(http_request_duration_seconds_sum{job="observatorium", handler="write"}[1m])) / sum by (job) (rate(http_request_duration_seconds_count{job="observatorium", handler="write"}[1m])))' >$DATA_DIR/write_dur_avg."$ext"
    $cmd '100 * (sum by (job) (rate(http_request_duration_seconds_sum{job="observatorium", handler="query_range"}[1m])) / sum by (job) (rate(http_request_duration_seconds_count{job="observatorium", handler="query_range"}[1m])))' >$DATA_DIR/query_range_dur_avg."$ext"
}

png() {
    output_dir=$1
    filename=$(basename -- "$2")
    filename="${filename%.*}"
    gnuplot -e "set term png; set output '$output_dir/$filename.png'" "$2"
}

plot() {
    output_dir="$DOC_DIR"/loadtests
    mkdir -p "$output_dir"
    printf "\tPlot thickens...\n"
    for filename in "$DATA_DIR"/*.gnuplot; do
        [ -e "$filename" ] || continue
        png "$output_dir" "$filename"
    done
}

# ---

(
    # In order to collect process metrics, it needs to run in container. os x doesn't support it.
    platform="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case $platform in
    linux)
        ./observatorium-api \
            --web.listen=0.0.0.0:8080 \
            --metrics.read.endpoint=http://127.0.0.1:9091/api/v1 \
            --metrics.write.endpoint=http://127.0.0.1:19291/
        ;;

    darwin)
        docker run --rm -u="$(id -u):$(id -g)" -e USER=deadbeef -p 8080:8080 \
            quay.io/observatorium/api \
            --web.listen=0.0.0.0:8080 \
            --metrics.read.endpoint=http://host.docker.internal:8888/ \
            --metrics.write.endpoint=http://host.docker.internal:8888/
        ;;
    *)
        echo "unknown platform: $platform"
        ;;
    esac
) &

(
    $MOCKPROVIDER \
        --listen=0.0.0.0:8888
) &

(
    $PROMETHEUS \
        --log.level=warn \
        --config.file=./test/config/prometheus.yml \
        --storage.tsdb.path="$(mktemp -d)"
) &

usage="$(basename "$0") [-h] [-r n] [-c n] [-m n] [-q n] [-o csv|gnuplot] -- program to test synthetic load on observatorium api and report results.

where:
    -h  show this help text
    -r  set number of seconds to run (default: 300)
    -c  set number of cluster to simulate (default: 5000)
    -m  set number of machines per cluster to simulate (default: 2)
    -q  set number of concurrent queries to execute (default: 10)
    -o  set the output format (default: csv. options: csv, gnuplot)"

output_format="csv" # Initialize our own variables.
run_for="300"
number_of_clusters="5000"
number_of_machines="2"
number_of_concurrent_queries="10"
while getopts "h?o:r:c:m:q:" opt; do
    case "$opt" in
    h)
        echo "$usage"
        exit 0
        ;;
    o)
        output_format=$OPTARG
        if ! [[ $output_format =~ (^csv|gnuplot$) ]]; then
            printf "illegal argument: -%s\n" "$OPTARG" >&2
            echo "$usage" >&2
            exit 1
        fi

        if [[ $output_format == "gnuplot" ]] && ! command -v gnuplot >/dev/null; then
            printf "No gnuplot in found in your path\n%s\nPlease install it:\n\tbrew install gnuplot # macOS\n\tapt-get install gnuplot # Debian / Ubuntu\n\tpacman -S gnuplot # ArchLinux\n" "$PATH"
            exit 1
        fi
        ;;
    r)
        run_for=$OPTARG
        ;;
    c)
        number_of_clusters=$OPTARG
        ;;
    m)
        number_of_machines=$OPTARG
        ;;
    q)
        number_of_concurrent_queries=$OPTARG
        ;;
    \?)
        printf "illegal option: -%s\n" "$OPTARG" >&2
        echo "$usage" >&2
        exit 1
        ;;
    esac
done
shift $((OPTIND - 1))

hosts=$((number_of_clusters * number_of_machines))
printf "\tStarting with %s clusters, will run for %s.\n", "$hosts", "$run_for"

printf "\tWaiting for dependencies to come up...\n"
sleep 5

(
    $PROMREMOTEBENCH \
        -query=true \
        -query-target=http://127.0.0.1:8080/api/metrics/v1/api/v1/query_range \
        -query-step=30s \
        -query-concurrency="$number_of_concurrent_queries" \
        -write=true \
        -target=http://127.0.0.1:8080/api/metrics/v1/api/v1/receive \
        -hosts="$hosts" \
        -interval=5
) &

printf "\tRunning...\n"

sleep "$run_for"

printf "\tFinished, after %s seconds.\n" "$run_for"

generate_report "$output_format"

printf "\tDone.\n"

exit $?
