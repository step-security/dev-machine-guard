# Fuzz testing

Fuzzing mutates synthetic inputs and checks properties that must hold for every
input. It complements unit tests, integration tests and benchmarks; it does not
prove correctness or replace resource profiling.

## Scope and plan

Start with deterministic, in-process boundaries that consume untrusted data.
Use Go's built-in fuzzing; no new dependencies or external services are needed.

| Priority | Target | Input and correctness check |
|---|---|---|
| 1 | `FuzzGlobMatch` | Relative globs and paths; compare the compiled regex against an independent wildcard interpreter. |
| 1 | `FuzzRuleSetPrepare` | Rule JSON; accepted bundles retain their validated meaning across repeated preparation and JSON round trips, with bounded file sizes. |
| 1 | `FuzzRuleScreening` | File bytes, condition flags and expressions; mandatory-condition screening agrees with complete group evaluation. |
| 1 | `FuzzNodeLockfiles` | npm, pnpm, Yarn and Bun text; parsing is deterministic after normalization, with valid unique package identities and consistent direct-dependency flags. |
| 1 | `FuzzPythonMetadata` | Python metadata headers and arbitrary bodies; body text cannot override package identity. |
| 1 | `FuzzNPMRCSecrets` | Synthetic tokens and arbitrary npmrc text; auth values remain redacted and correctly fingerprinted, with environment references preserved literally. |
| 1 | `FuzzCanonicalHashJSON` | JSON and malformed bytes; equivalent formatting hashes identically, malformed input still has a raw-byte hash. |
| 1 | `FuzzStateTransitions` | Sequences of successful/failed scans, full syncs and removals; compare inventory hashes, upload provenance and pending removals against a small reference model. |
| Existing | `FuzzParseSource` | Credential formats; parser outputs obey count/protection invariants and malformed input cannot crash the scanner. |

Inputs are bounded per target so mutation explores structure without spending its
budget on huge allocations. No target reads the developer's files, accesses the
network, runs package managers, uses real credentials, or executes generated text.
State and mock executors are recreated inside each invocation. Time comes from a
fixed test clock. Generated filesystem paths are data, never live scan roots.

Follow-up candidates: pip/yarn/bun configuration redaction, AI event decoders,
CLI argument parsing, and filesystem scanning over bounded mock directory trees.
Actual permissions, symlinks, OS schedulers and HTTP upload behavior remain covered
by unit/integration tests; native fuzzing of pure parsers cannot validate them.

## Running and triage

Ordinary `go test ./...` runs the seed corpus and checked-in reproductions. Active
mutation requires `-fuzz`; the workflow runs each target separately and caps both
time and worker count. Run one target locally, for example:

```sh
go test ./internal/detector/rules -run '^$' -fuzz '^FuzzGlobMatch$' -fuzztime 30s -parallel 2
```

Run all targets with `make fuzz`, or `FUZZ_TIME=2m make fuzz` for a longer
campaign. The script discovers targets in the five listed packages and fails if
a package has no targets or cannot compile. Adding a fuzz target in these packages
automatically includes it; a new package must be added to the script and workflow.

PR jobs use 15 seconds per target. Scheduled and manual jobs use two minutes per
target. Jobs have a hard timeout, and failure artifacts retain logs and
`testdata/fuzz` inputs. New failures must be reproduced using the command printed
by Go. Decide whether the implementation or the asserted property is wrong; fix
that cause and commit the minimized reproducer. Never suppress panics or delete
failing inputs merely to make the campaign pass.

Seed with small valid examples, truncated documents, invalid UTF-8, escaping,
empty collections and boundary cases. Keep valid structured seeds so targets do
not spend the entire campaign rejecting syntax errors. Do not place production
rules, user files, tokens or environment-dependent values in a corpus.

## References

- [Go fuzzing guidance](https://go.dev/doc/security/fuzz/): coverage-guided mutation, deterministic targets, bounded campaigns and minimized regressions.
- [Go JSON fuzz tests](https://github.com/golang/go/blob/master/src/encoding/json/fuzz_test.go): representative structured seeds and decode/encode round trips.
- [BurntSushi/toml fuzz tests](https://github.com/BurntSushi/toml/blob/master/fuzz_test.go): exercise malformed input and error handling as well as successful decoding.

These inform the testing approach; target implementations are specific to DMG.

## Initial findings

The first glob campaign minimized a failure to pattern `**` and path `\n`.
The regex translation did not let globstars cross newline characters in Unix
filenames. Expanding the seed set to literal Unicode also exposed byte-by-byte
quoting that changed `é` into different characters. Both matching bugs are fixed;
the newline reproducer and Unicode seeds remain regression coverage.

A Node parser campaign also exposed an overly strict test comparison: nil and
empty normalized package lists have the same logical inventory. The oracle now
compares their elements, and the minimized input remains as a seed. This was a
test-oracle correction, not a package-parser defect.

## Local validation (2026-09-21)

Each target completed a 30-second, two-worker campaign after its final changes.
The counts below include corpus replay and generated inputs; they are not a
coverage percentage or a guarantee that no bugs remain.

| Target | Executions |
|---|---:|
| `FuzzCanonicalHashJSON` | 778,179 |
| `FuzzGlobMatch` | 313,285 |
| `FuzzNPMRCSecrets` | 369,680 |
| `FuzzNodeLockfiles` | 482,047 |
| `FuzzParseSource` | 195,104 |
| `FuzzPythonMetadata` | 387,271 |
| `FuzzRuleScreening` | 195,626 |
| `FuzzRuleSetPrepare` | 390,802 |
| `FuzzStateTransitions` | 482,086 |

The full race suite, 45 smoke checks, lint, vet, dependency-drift check and
Linux/amd64, macOS/arm64 and Windows/amd64 builds passed. Actionlint validated
the workflow. The runner was also checked against successful, failed, missing-target
and compilation-failure commands to verify that failures cannot produce a green job.
Gosec reported 23 findings outside the changed production file; it was run with
the repository’s non-blocking policy.
