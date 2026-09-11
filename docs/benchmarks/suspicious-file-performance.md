# Suspicious-file scan performance

Measured on 2026-09-11 against upstream main `0a33c0e`, using the same
Go 1.26.5 toolchain and pure-Go Linux builds.

The earlier optimization helped mixed wildcard workloads, but did not improve
the real four-rule bundle. CPU profiling identified optional content regexes
and full-path construction for irrelevant files as avoidable work. The updated
scanner checks mandatory conditions first and constructs paths only for
candidate files and directories. Reported files retain every group's evidence.

## Full-agent benchmark

Fedora 42, EC2 t3.xlarge (4 logical CPUs, approximately 15.4 GiB RAM), scanning
`/home/fedora`: 88,623 directories and 575,739 file entries. The frozen backend
bundle contains four rules targeting agent settings, binding.gyp, package.json,
and .github/setup.js or setup.mjs. No artificial wildcard was added.

Eight runs alternated main/optimized/optimized/main twice, with a warm
filesystem cache, fresh agent state per run, identical search roots, and an
isolated local backend. The installed agent and customer configuration were
not modified. Values below are medians of four runs per binary.

| Metric | Main | Optimized | Reduction |
| --- | ---: | ---: | ---: |
| Malicious-file CPU | 2,231.5 ms | 1,442 ms | 35.4% |
| Malicious-file elapsed time | 2,097 ms | 1,337.5 ms | 36.2% |
| Full-agent elapsed time | 14,990.5 ms | 14,125 ms | 5.8% |
| Process RSS sampled during malicious-file phase | 19.27 MiB | 18.78 MiB | 2.5% |
| Full-agent peak RSS | 38.62 MiB | 38.49 MiB | 0.3% |

Every run exited successfully, reported complete scans for all four rules,
and returned exactly the same five findings, including metadata and condition
results. Canonical JSON SHA-256 of `rule_scan`:
`b17ad9c8eb1e1588ce980dc13c9f29f43ebb8803370f9668ae9da80c137bce35`.

Separate ten-scan profiles measured approximately 2.06 GiB allocated before
versus 1.30 GiB after (37% less allocation churn). This is cumulative allocation,
not retained memory. The profile comparison used the previous PR implementation;
its real-rule performance was equivalent to main.

Peak RAM is effectively unchanged. These results demonstrate improvement on
this Linux workload; native macOS/Windows and customer-specific filesystems
still need validation. Directory enumeration remains the dominant cost.

## Reproduction

Build main and the PR with `CGO_ENABLED=0 go build -trimpath`, freeze the same
backend rules, and alternate full `send-telemetry` runs with `--force-scan`,
`--rules-file`, `--search-dirs`, isolated `--install-dir`, and `--telemetry-out`.
Compare the `malicious_file_scan` CPU/duration in `run-metrics.jsonl`, and compare
the complete `rule_scan` objects. Use a local benchmark backend to isolate
network and policy changes. Do not reuse incremental state across variants.

The offline `BenchmarkScanPackageJSON` benchmark exercises the real mandatory
and optional regex structure against ordinary dependency metadata. Run it with
`go test ./internal/detector/rules -run '^$' -bench BenchmarkScanPackageJSON -benchmem`.
