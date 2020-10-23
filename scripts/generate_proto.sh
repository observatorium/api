#!/usr/bin/env bash

set -euo pipefail

PROTOC_BIN=${PROTOC_BIN:-protoc}
DIRS=${DIRS:-"ratelimit/gubernator"}
PROTOC_INCLUDE=${PROTOC_INCLUDE:-"tmp/protoc/include"}

if ! [[ "scripts/generate_proto.sh" =~ $0 ]]; then
  echo "must be run from repository root"
  exit 255
fi

if ! [[ $(${PROTOC_BIN} --version) == *"3.13.0"* ]]; then
  echo "could not find protoc 3.13.0, is it installed + in PATH?"
  exit 255
fi

echo "generating code"
for dir in ${DIRS}; do
  ${PROTOC_BIN} --go_out=plugins=grpc:. \
    -I=. \
    -I="${dir}"/proto \
    -I="${PROTOC_INCLUDE}" \
    "${dir}"/*.proto
done

