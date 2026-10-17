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
    package_label=${package#./}
    package_label=${package_label//\//_}
    while IFS= read -r target; do
        log="$FUZZ_LOG_DIR/${package_label}-${target}.log"
        for attempt in 1 2; do
            echo "Fuzzing $package / $target for $FUZZ_TIME ($FUZZ_WORKERS workers, attempt $attempt)"
            if go test "$package" -run '^$' -fuzz "^${target}$" \
                -fuzztime "$FUZZ_TIME" -parallel "$FUZZ_WORKERS" -timeout "$FUZZ_TIMEOUT" \
                2>&1 | tee "$log"; then
                break
            fi
            # go test can report "context deadline exceeded" with no failing
            # input when -fuzztime ends mid-input; that isn't a finding. A real
            # one always writes a crasher. Retry once, then don't fail on it.
            if grep -q 'Failing input written to' "$log" || ! grep -q 'context deadline exceeded' "$log"; then
                status=1
                break
            fi
            if [ "$attempt" -eq 2 ]; then
                echo "::warning::$package / $target: fuzz deadline ended mid-input twice with no failing input"
            fi
        done
    done <<< "$targets"
done
exit "$status"
