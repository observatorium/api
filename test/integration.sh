#!/bin/bash

# Runs a semi-realistic integration test with one producer generating metrics,
# a Observatorium API, a thanos receive for ingestion, and a thanos query for querying the metrics.

set -euo pipefail

trap 'kill $(jobs -p); exit 0' EXIT

(
	./observatorium \
		--web.listen=0.0.0.0:8080 \
		--metrics.query.endpoint=http://127.0.0.1:9091/api/v1/ \
		--metrics.ui.endpoint=http://127.0.0.1:9091/ \
		--metrics.write.endpoint=http://127.0.0.1:19291/api/v1/receive \
		--log.level=debug
) &

(
./tmp/bin/prometheus \
    --config.file=./test/config/prometheus.yml \
    --storage.tsdb.path="$(mktemp -d)" \
    --log.level=debug
) &

(
	up \
	  --listen=0.0.0.0:8888 \
		--endpoint=http://127.0.0.1:8080/api/v1/metrics/write \
		--period=1s \
		--name=observatorium_write \
		--labels='_id="test"'
) &

(
	thanos receive \
		--grpc-address=127.0.0.1:10901 \
		--http-address=127.0.0.1:10902 \
		--remote-write.address=127.0.0.1:19291 \
		--tsdb.path="$(mktemp -d)" \
		--log.level=debug
) &

(
	thanos query \
		--grpc-address=127.0.0.1:10911 \
		--http-address=127.0.0.1:9091 \
		--store=127.0.0.1:10901 \
		--web.external-prefix=http://localhost:8080/ui/v1/metrics \
		--log.level=debug
) &

sleep 1

retries=100
while true; do
	if [[ "${retries}" -lt 0 ]]; then
		echo "error: Did not successfully retrieve cluster metrics from the local Thanos query server" 1>&2
		exit 1
	fi
	# verify we scrape metrics from the test cluster and give it _id test
	if [[ "$(curl http://localhost:8080/api/v1/metrics/query --data-urlencode 'query=count({_id="test"})' -G 2>/dev/null | python3 -c 'import sys, json; print(json.load(sys.stdin)["data"]["result"][0]["value"][1])' 2>/dev/null)" -eq 0 ]]; then
		retries=$((retries - 1))
		sleep 1
		continue
	fi
	break
done
echo "tests: ok"
exit 0

for i in $(jobs -p); do wait "$i"; done
