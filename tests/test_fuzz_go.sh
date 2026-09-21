#!/usr/bin/env bash
# Bounded native Go fuzzing. Package arguments override the default input boundaries.
set -euo pipefail

FUZZ_TIME=${FUZZ_TIME:-15s}
FUZZ_WORKERS=${FUZZ_WORKERS:-2}
FUZZ_TIMEOUT=${FUZZ_TIMEOUT:-5m}
FUZZ_LOG_DIR=${FUZZ_LOG_DIR:-fuzz-logs}
mkdir -p "$FUZZ_LOG_DIR"

if [ "$#" -eq 0 ]; then
    set -- ./internal/detector/rules ./internal/detector ./internal/detector/configaudit \
        ./internal/state ./internal/detector/credentials
fi

status=0
for package in "$@"; do
    # Discovery also compiles the package and must fail the job if compilation fails.
    listing=$(go test "$package" -list '^Fuzz')
    targets=$(printf '%s\n' "$listing" | awk '/^Fuzz[A-Za-z0-9_]+$/ { print $0 }')
    if [ -z "$targets" ]; then
        echo "No fuzz targets found in $package" >&2
        exit 1
    fi
    package_label=${package//\//_}
    while IFS= read -r target; do
        echo "Fuzzing $package / $target for $FUZZ_TIME ($FUZZ_WORKERS workers)"
        if ! go test "$package" -run '^$' -fuzz "^${target}$" \
            -fuzztime "$FUZZ_TIME" -parallel "$FUZZ_WORKERS" -timeout "$FUZZ_TIMEOUT" \
            2>&1 | tee "$FUZZ_LOG_DIR/${package_label}-${target}.log"; then
            status=1
        fi
    done <<< "$targets"
done
exit "$status"
