#!/usr/bin/env bash
#
# End-to-end harness for the npmrc + pip config audits.
#
# Runs ~70 scenarios covering: discovery across all four scopes for each
# tool, credential redaction, env-var interactions (NPM_CONFIG_USERCONFIG,
# PIP_CONFIG_FILE incl. /dev/null disable, VIRTUAL_ENV), every pip-001..
# pip-024 finding rule, file-mode escalations, severity ordering, and
# edge cases (missing files, unreadable files, garbage content, symlinks).
#
# Usage:
#   tests/test_rc_audit.sh                                     # uses ./stepsecurity-dev-machine-guard
#   BINARY=/path/to/binary tests/test_rc_audit.sh              # explicit binary
#
# The harness mutates a small set of well-known config paths under
# $HOME (~/.npmrc, ~/.config/pip/pip.conf, ~/.netrc, ~/.pip/pip.conf).
# Anything that already exists is backed up to a tempdir on entry and
# restored on exit (including abort via Ctrl-C). The backup/restore is
# idempotent and bulletproof against double-runs.
#
# Tests that would require root (writing /etc/pip.conf for the global-
# scope scenario) are skipped automatically when passwordless sudo is
# unavailable.
#
# Requirements:
#   - jq                  (assertion plumbing)
#   - git                 (1-2 scenarios; auto-skipped if absent)
#   - npm and/or pip      (optional; absent-tool scenarios are still
#                          exercised with PATH=/empty)

set -uo pipefail

#==============================================================================
# Configuration
#==============================================================================

BINARY="${BINARY:-./stepsecurity-dev-machine-guard}"
RESULTS_DIR="${RESULTS_DIR:-/tmp/rc-audit-results}"
TEST_SEARCH_DIR="$(mktemp -d -t rc-test-search.XXXXXX)"

# Files we mutate. They get backed up under $BACKUP_DIR if present, and
# the originals are restored on exit. Sudo-managed paths (/etc/pip.conf,
# /etc/npmrc) are handled in the sudo-gated scenarios only.
USER_FILES=(
    "$HOME/.npmrc"
    "$HOME/.netrc"
    "$HOME/.config/pip/pip.conf"
    "$HOME/.pip/pip.conf"
)
BACKUP_DIR="$(mktemp -d -t rc-test-backup.XXXXXX)"

mkdir -p "$RESULTS_DIR"

# Detect optional tooling so we can gate sudo-required and tool-specific scenarios.
HAVE_SUDO=0
if sudo -n true 2>/dev/null; then HAVE_SUDO=1; fi
HAVE_NPM=$(command -v npm >/dev/null 2>&1 && echo 1 || echo 0)
if command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1; then HAVE_PIP=1; else HAVE_PIP=0; fi
HAVE_GIT=$(command -v git >/dev/null 2>&1 && echo 1 || echo 0)
HAVE_JQ=$(command -v jq >/dev/null 2>&1 && echo 1 || echo 0)

if [ "$HAVE_JQ" != "1" ]; then
    echo "ERROR: jq is required for assertions. Install jq and re-run." >&2
    exit 2
fi

#==============================================================================
# Test framework  (matches tests/test_smoke_go.sh conventions)
#==============================================================================

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  ${GREEN}PASS${RESET}  %s\n" "$1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "  ${RED}FAIL${RESET}  %s\n" "$1"
    if [ -n "${2:-}" ]; then
        printf "        %s\n" "$2"
    fi
}

skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    printf "  ${YELLOW}SKIP${RESET}  %s   (%s)\n" "$1" "$2"
}

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        pass "$label"
    else
        fail "$label" "expected=$expected  actual=$actual"
    fi
}

assert_match() {
    local label="$1" pattern="$2" actual="$3"
    if grep -qE "$pattern" <<<"$actual"; then
        pass "$label"
    else
        fail "$label" "pattern=$pattern  actual=$actual"
    fi
}

assert_no_match_in_file() {
    local label="$1" pattern="$2" file="$3"
    if grep -qE "$pattern" "$file" 2>/dev/null; then
        fail "$label" "pattern '$pattern' was present in $file"
    else
        pass "$label"
    fi
}

section() {
    printf "\n${BOLD}── %s${RESET}\n" "$1"
}

#==============================================================================
# Backup / restore  (so we never destroy a developer's real config)
#==============================================================================

backup_user_state() {
    for f in "${USER_FILES[@]}"; do
        if [ -e "$f" ]; then
            local rel="${f#$HOME/}"
            mkdir -p "$BACKUP_DIR/$(dirname "$rel")"
            cp -p "$f" "$BACKUP_DIR/$rel"
        fi
    done
}

restore_user_state() {
    # Remove anything the harness wrote.
    for f in "${USER_FILES[@]}"; do
        rm -f "$f"
    done
    # Restore originals.
    if [ -d "$BACKUP_DIR" ]; then
        for f in "${USER_FILES[@]}"; do
            local rel="${f#$HOME/}"
            if [ -e "$BACKUP_DIR/$rel" ]; then
                mkdir -p "$(dirname "$f")"
                cp -p "$BACKUP_DIR/$rel" "$f"
            fi
        done
    fi
    rm -rf "$BACKUP_DIR" "$TEST_SEARCH_DIR"
}

# Restore on any exit path — normal, error, signal.
trap 'restore_user_state' EXIT INT TERM

backup_user_state

#==============================================================================
# Helpers
#==============================================================================

# Wipe + recreate per-scenario state (does not touch the backup).
reset_state() {
    rm -f "${USER_FILES[@]}" 2>/dev/null
    rm -rf "$HOME/.config/pip" "$HOME/.pip" "$TEST_SEARCH_DIR"/* 2>/dev/null
    mkdir -p "$TEST_SEARCH_DIR" "$HOME/.config/pip"
}

# Run --npmrc, capture pretty + JSON output to $RESULTS_DIR/<id>.{out,json}
run_npmrc() {
    local id="$1"
    "$BINARY" --npmrc --color=never --search-dirs "$TEST_SEARCH_DIR" 2>/dev/null > "$RESULTS_DIR/$id.out"
    "$BINARY" --npmrc --json --search-dirs "$TEST_SEARCH_DIR" 2>/dev/null > "$RESULTS_DIR/$id.json"
}

# Run --pipconfig with optional env vars: run_pip P3 PIP_CONFIG_FILE=/foo
run_pip() {
    local id="$1"; shift
    env "$@" "$BINARY" --pipconfig --color=never --search-dirs "$TEST_SEARCH_DIR" 2>/dev/null > "$RESULTS_DIR/$id.out"
    env "$@" "$BINARY" --pipconfig --json --search-dirs "$TEST_SEARCH_DIR" 2>/dev/null > "$RESULTS_DIR/$id.json"
}

# Path-suffix filter for the user-scope pip.conf — pip discovery often
# reports both ~/.config/pip/pip.conf and ~/.pip/pip.conf under the
# "user" layer; tests target the former.
USER_PIP='.files[] | select(.path | endswith(".config/pip/pip.conf"))'

#==============================================================================
# 0. Binary check
#==============================================================================

section "Binary check"

if [ -x "$BINARY" ]; then
    pass "Binary exists and is executable: $BINARY"
else
    fail "Binary exists and is executable" "BINARY=$BINARY not found or not executable. Build first or set BINARY=..."
    exit 1
fi

#==============================================================================
# NPMRC scenarios
#==============================================================================

section "NPMRC scenarios"

# N1: clean slate
reset_state
run_npmrc N1
assert_eq "N1  no existing files"          "0"    "$(jq '[.files[] | select(.exists)] | length' "$RESULTS_DIR/N1.json")"
if [ "$HAVE_NPM" = "1" ]; then
    assert_eq "N1  npm_available=true"     "true" "$(jq -r '.npm_available' "$RESULTS_DIR/N1.json")"
fi

# N2: hardcoded + env-ref tokens, plus normal config
reset_state
cat > "$HOME/.npmrc" <<'NPMEOF'
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=npm_HARDCODED_TOKEN_LASTFOUR
//npm.example.com/:_authToken=${COMPANY_TOKEN}
strict-ssl=true
NPMEOF
run_npmrc N2
assert_eq    "N2  user file exists"          "true" "$(jq -r '.files[] | select(.scope=="user") | .exists' "$RESULTS_DIR/N2.json")"
HARDCODED=$(jq -r '.files[] | select(.scope=="user") | .entries[] | select(.is_auth and (.is_env_ref|not)) | .display_value' "$RESULTS_DIR/N2.json" | head -1)
assert_match "N2  hardcoded token redacted to ***" '^\*\*\*' "$HARDCODED"
ENVREF=$(jq -r '.files[] | select(.scope=="user") | .entries[] | select(.is_env_ref) | .display_value' "$RESULTS_DIR/N2.json" | head -1)
assert_match "N2  env-ref preserved verbatim"      'COMPANY_TOKEN' "$ENVREF"
assert_no_match_in_file "N2  no plaintext token in JSON output" "HARDCODED_TOKEN" "$RESULTS_DIR/N2.json"

# N3: ca[]= multi-line array
reset_state
cat > "$HOME/.npmrc" <<'NPMEOF'
ca[]=cert-1
ca[]=cert-2
NPMEOF
run_npmrc N3
assert_eq    "N3  two ca[] entries flagged is_array=true" "2" "$(jq '.files[] | select(.scope=="user") | [.entries[] | select(.is_array)] | length' "$RESULTS_DIR/N3.json")"

# N4: git-tracked project file
if [ "$HAVE_GIT" = "1" ]; then
    reset_state
    mkdir -p "$TEST_SEARCH_DIR/proj-tracked"
    (cd "$TEST_SEARCH_DIR/proj-tracked" && git init -q)
    echo 'save-exact=true' > "$TEST_SEARCH_DIR/proj-tracked/.npmrc"
    (cd "$TEST_SEARCH_DIR/proj-tracked" && git add .npmrc && git -c user.email=t@t -c user.name=t commit -q -m init >/dev/null)
    run_npmrc N4
    assert_eq "N4  git_tracked=true" "true" "$(jq -r '.files[] | select(.path | endswith("/proj-tracked/.npmrc")) | .git_tracked' "$RESULTS_DIR/N4.json")"
    assert_eq "N4  in_git_repo=true" "true" "$(jq -r '.files[] | select(.path | endswith("/proj-tracked/.npmrc")) | .in_git_repo' "$RESULTS_DIR/N4.json")"
else
    skip "N4  git-tracked project file" "git not installed"
fi

# N5: project .npmrc in non-git dir
reset_state
mkdir -p "$TEST_SEARCH_DIR/proj-untracked"
echo 'save-exact=true' > "$TEST_SEARCH_DIR/proj-untracked/.npmrc"
run_npmrc N5
assert_eq "N5  non-git project: in_git_repo=false" "false" "$(jq -r '.files[] | select(.path | endswith("/proj-untracked/.npmrc")) | .in_git_repo // false' "$RESULTS_DIR/N5.json")"

# N6: NPM_CONFIG_USERCONFIG override
reset_state
CUSTOM_NPM="$(mktemp -d -t custom-npm.XXXXXX)"
echo 'audit=false' > "$CUSTOM_NPM/myrc"
NPM_CONFIG_USERCONFIG="$CUSTOM_NPM/myrc" "$BINARY" --npmrc --json --search-dirs "$TEST_SEARCH_DIR" 2>/dev/null > "$RESULTS_DIR/N6.json"
assert_eq "N6  user-scope path == NPM_CONFIG_USERCONFIG" "$CUSTOM_NPM/myrc" "$(jq -r '.files[] | select(.scope=="user") | .path' "$RESULTS_DIR/N6.json")"
rm -rf "$CUSTOM_NPM"

# N7: npm not on PATH (truly hidden via empty PATH)
reset_state
echo 'registry=https://registry.npmjs.org/' > "$HOME/.npmrc"
PATH=/empty "$BINARY" --npmrc --json --search-dirs "$TEST_SEARCH_DIR" 2>/dev/null > "$RESULTS_DIR/N7.json"
assert_eq "N7  npm_available=false when PATH hides npm" "false" "$(jq -r '.npm_available' "$RESULTS_DIR/N7.json")"
assert_eq "N7  user file still discovered"              "true"  "$(jq -r '.files[] | select(.scope=="user") | .exists' "$RESULTS_DIR/N7.json")"
assert_eq "N7  no effective view when npm absent"       "false" "$(jq 'has("effective")' "$RESULTS_DIR/N7.json")"

# N8: empty .npmrc
reset_state
: > "$HOME/.npmrc"
run_npmrc N8
assert_eq "N8  empty user file: 0 entries" "0" "$(jq '.files[] | select(.scope=="user") | (.entries // []) | length' "$RESULTS_DIR/N8.json")"

# N9: --npmrc --json output shape
reset_state
"$BINARY" --npmrc --json --search-dirs "$TEST_SEARCH_DIR" 2>/dev/null > "$RESULTS_DIR/N9.json"
assert_eq "N9  --npmrc --json has npm_available key"     "true"  "$(jq 'has("npm_available")' "$RESULTS_DIR/N9.json")"
assert_eq "N9  --npmrc --json scoped to audit only"      "false" "$(jq 'has("ide_installations")' "$RESULTS_DIR/N9.json")"

#==============================================================================
# PIP scenarios
#==============================================================================

section "PIP scenarios"

# Helper: assert a finding fired with a given severity.
assert_severity() {
    local id="$1" findid="$2" want_sev="$3" desc="$4"
    local got
    got=$(jq -r --arg id "$findid" '[.findings[]? | select(.id==$id) | .severity] | first // ""' "$RESULTS_DIR/$id.json")
    assert_eq "$id  $desc" "$want_sev" "$got"
}

# Helper: assert a count of findings with the given ID.
assert_finding_count() {
    local id="$1" findid="$2" wantcount="$3" desc="$4"
    local got
    got=$(jq --arg id "$findid" '[.findings[]? | select(.id==$id)] | length' "$RESULTS_DIR/$id.json")
    assert_eq "$id  $desc" "$wantcount" "$got"
}

# P1: clean slate
reset_state
run_pip P1
NETRC_ONLY=$(jq '[.findings[]? | select(.id|startswith("pip-")) | select(.id != "pip-netrc-perms" and .id != "pip-netrc-present")] | length == 0' "$RESULTS_DIR/P1.json")
assert_eq "P1  no findings (or netrc-only)" "true" "$NETRC_ONLY"

# P2: global /etc/pip.conf — requires sudo
if [ "$HAVE_SUDO" = "1" ]; then
    reset_state
    sudo tee /etc/pip.conf >/dev/null <<'PIPEOF'
[global]
audit-level = moderate
PIPEOF
    run_pip P2
    assert_eq "P2  global file discovered" "true" "$(jq -r '[.files[] | select(.layer=="global" and .exists)] | length > 0' "$RESULTS_DIR/P2.json")"
    sudo rm -f /etc/pip.conf
else
    skip "P2  global /etc/pip.conf discovery" "passwordless sudo unavailable"
fi

# P3: hardcoded creds in extra-index-url
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
extra-index-url = https://__token__:secret_value_xyz_LASTFOUR@my-private.example.com/simple
PIPEOF
chmod 0644 "$HOME/.config/pip/pip.conf"
run_pip P3
assert_severity P3 "pip-001" "CRITICAL" "pip-001 is CRITICAL on hardcoded creds"
assert_severity P3 "pip-005" "HIGH"     "pip-005 is HIGH (extra-index-url presence)"
assert_severity P3 "pip-022" "HIGH"     "pip-022 is HIGH (creds + group/other readable)"
assert_no_match_in_file "P3  no plaintext secret anywhere in JSON" "secret_value_xyz" "$RESULTS_DIR/P3.json"

# P4: index-url with http://
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
index-url = http://internal.example.com/simple
PIPEOF
run_pip P4
assert_severity P4 "pip-006" "HIGH" "pip-006 fires for http:// index-url"

# P5: extra-index-url with http://
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
extra-index-url = http://other.example.com/simple
PIPEOF
run_pip P5
assert_severity P5 "pip-002" "CRITICAL" "pip-002 fires for http:// extra-index-url"
assert_severity P5 "pip-005" "HIGH"     "pip-005 also fires"

# P6: trusted-host with two values
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
trusted-host =
    a.example.com
    b.example.com
PIPEOF
run_pip P6
assert_finding_count P6 "pip-007" "2" "pip-007 fires once per trusted host"

# P7: build-integrity dial-downs
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
no-build-isolation = true
cache-dir = /tmp/pipcache

[install]
no-binary = :all:
PIPEOF
run_pip P7
assert_severity P7 "pip-011" "MEDIUM" "pip-011 no-build-isolation"
assert_severity P7 "pip-012" "MEDIUM" "pip-012 no-binary=:all:"
assert_severity P7 "pip-013" "MEDIUM" "pip-013 cache-dir under /tmp"

# P8: positive controls
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[install]
require-hashes = true
only-binary = :all:
PIPEOF
run_pip P8
assert_severity P8 "pip-023" "INFO" "pip-023 require-hashes (positive)"
assert_severity P8 "pip-024" "INFO" "pip-024 only-binary=:all: (positive)"

# P9: proxy with embedded creds
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
proxy = http://proxyuser:proxypass@proxy.example.com:8080
PIPEOF
run_pip P9
assert_severity P9 "pip-003" "CRITICAL" "pip-003 proxy creds"

# P10: cert + client-cert
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
cert = /etc/ssl/certs/custom-ca.crt
client-cert = /home/user/client.pem
PIPEOF
run_pip P10
assert_severity P10 "pip-009" "MEDIUM" "pip-009 custom CA"
assert_severity P10 "pip-010" "MEDIUM" "pip-010 client-cert"

# P11: low-severity informational
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
keyring-provider = disabled
no-cache-dir = true
pre = true
PIPEOF
run_pip P11
assert_severity P11 "pip-016" "LOW" "pip-016 keyring-disabled"
assert_severity P11 "pip-017" "LOW" "pip-017 no-cache-dir"
assert_severity P11 "pip-018" "LOW" "pip-018 pre"

# P12: legacy ~/.pip/pip.conf in use
reset_state
mkdir -p "$HOME/.pip"
cat > "$HOME/.pip/pip.conf" <<'PIPEOF'
[global]
index-url = https://pypi.org/simple
PIPEOF
run_pip P12
assert_severity P12 "pip-019" "LOW" "pip-019 fires by path suffix even when pip-debug labels it 'user'"

# P13: PIP_CONFIG_FILE redirect
reset_state
echo '[global]' > /tmp/redirect.conf
echo 'audit = false' >> /tmp/redirect.conf
run_pip P13 PIP_CONFIG_FILE=/tmp/redirect.conf
assert_severity P13 "pip-020" "MEDIUM" "pip-020 PIP_CONFIG_FILE redirect"
rm -f /tmp/redirect.conf

# P14: PIP_CONFIG_FILE=/dev/null disables config-file load
reset_state
run_pip P14 PIP_CONFIG_FILE=/dev/null
assert_severity P14 "pip-021" "MEDIUM" "pip-021 PIP_CONFIG_FILE=/dev/null"

# P15: VIRTUAL_ENV picked up as site scope
reset_state
TEST_VENV="$(mktemp -d -t test-venv.XXXXXX)"
cat > "$TEST_VENV/pip.conf" <<'PIPEOF'
[global]
require-hashes = true
PIPEOF
run_pip P15 VIRTUAL_ENV="$TEST_VENV"
assert_eq "P15  VIRTUAL_ENV pip.conf surfaces under site scope" "1" "$(jq -r '[.files[] | select(.layer=="site" and .exists)] | length' "$RESULTS_DIR/P15.json")"
rm -rf "$TEST_VENV"

# P16: severity ordering — critical first
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
extra-index-url = https://__token__:s3cr3t_LASTFOUR@host.example.com/simple
trusted-host = host.example.com
no-build-isolation = true

[install]
require-hashes = true
PIPEOF
run_pip P16
FIRST_SEV=$(jq -r '.findings[0].severity' "$RESULTS_DIR/P16.json")
LAST_SEV=$(jq -r '.findings[-1].severity' "$RESULTS_DIR/P16.json")
assert_eq "P16  first finding is CRITICAL" "CRITICAL" "$FIRST_SEV"
assert_eq "P16  last finding is INFO"      "INFO"     "$LAST_SEV"

# P17: file mode 0666 with creds → HIGH escalation
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
extra-index-url = https://__token__:another_secret_LASTFOUR@host.example.com/simple
PIPEOF
chmod 0666 "$HOME/.config/pip/pip.conf"
run_pip P17
assert_severity P17 "pip-022" "HIGH" "pip-022 HIGH on creds+0666"

# P18: ~/.netrc 0644 — pip-netrc-perms MEDIUM
reset_state
echo 'machine pypi.org login user password p' > "$HOME/.netrc"
chmod 0644 "$HOME/.netrc"
run_pip P18
assert_severity P18 "pip-netrc-perms" "MEDIUM" "pip-netrc-perms MEDIUM at 0644"

# P19: ~/.netrc 0600 — pip-netrc-present INFO
reset_state
echo 'machine pypi.org login user password p' > "$HOME/.netrc"
chmod 0600 "$HOME/.netrc"
run_pip P19
assert_severity P19 "pip-netrc-present" "INFO" "pip-netrc-present INFO at 0600"

# P20: pip not on PATH — file-only audit, findings still fire
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
extra-index-url = http://no-pip.example.com/simple
PIPEOF
PATH=/empty "$BINARY" --pipconfig --json --search-dirs "$TEST_SEARCH_DIR" 2>/dev/null > "$RESULTS_DIR/P20.json"
assert_eq "P20  pip_available=false when PATH hides pip" "false" "$(jq -r '.pip_available' "$RESULTS_DIR/P20.json")"
assert_eq "P20  pip-002 still fires when pip absent"     "1"     "$(jq '[.findings[]? | select(.id=="pip-002")] | length' "$RESULTS_DIR/P20.json")"

#==============================================================================
# Cross-cutting
#==============================================================================

section "Cross-cutting"

reset_state
"$BINARY" --pretty --color=never --search-dirs "$TEST_SEARCH_DIR" 2>/dev/null > "$RESULTS_DIR/X1.out"
assert_match "X1  --pretty has NPM CONFIG AUDIT block" "NPM CONFIG AUDIT" "$(cat "$RESULTS_DIR/X1.out")"
assert_match "X1  --pretty has PIP CONFIG AUDIT block" "PIP CONFIG AUDIT" "$(cat "$RESULTS_DIR/X1.out")"

"$BINARY" --json --search-dirs "$TEST_SEARCH_DIR" 2>/dev/null > "$RESULTS_DIR/X2.json"
assert_eq "X2  --json has npmrc_audit"                       "true" "$(jq 'has("npmrc_audit")' "$RESULTS_DIR/X2.json")"
assert_eq "X2  --json has pip_audit"                         "true" "$(jq 'has("pip_audit")' "$RESULTS_DIR/X2.json")"
assert_eq "X2  --json still has ide_installations (no regression)" "true" "$(jq 'has("ide_installations")' "$RESULTS_DIR/X2.json")"

"$BINARY" --pipconfig --json --search-dirs "$TEST_SEARCH_DIR" 2>/dev/null > "$RESULTS_DIR/X3.json"
assert_eq "X3  --pipconfig --json has pip_available"             "true"  "$(jq 'has("pip_available")' "$RESULTS_DIR/X3.json")"
assert_eq "X3  --pipconfig --json scoped (no ide_installations)" "false" "$(jq 'has("ide_installations")' "$RESULTS_DIR/X3.json")"

#==============================================================================
# Edge cases
#==============================================================================

section "Edge cases"

# E1: pip.conf with mode 000 (unreadable)
reset_state
cat > "$HOME/.config/pip/pip.conf" <<'PIPEOF'
[global]
audit = false
PIPEOF
chmod 000 "$HOME/.config/pip/pip.conf"
run_pip E1
chmod 0644 "$HOME/.config/pip/pip.conf"
assert_eq    "E1  exists=true even when unreadable" "true"  "$(jq -r "$USER_PIP | .exists"   "$RESULTS_DIR/E1.json")"
assert_eq    "E1  readable=false when mode 000"     "false" "$(jq -r "$USER_PIP | .readable" "$RESULTS_DIR/E1.json")"
assert_match "E1  parse_error mentions 'read'"      "read"  "$(jq -r "$USER_PIP | .parse_error // \"\"" "$RESULTS_DIR/E1.json")"

# E2: garbage bytes — verify run completes with valid JSON
reset_state
printf '\x00\x01\x02 garbage \xff\nrandom-key=value\n[realsection]\nkey=val\n' > "$HOME/.config/pip/pip.conf"
run_pip E2
if jq empty "$RESULTS_DIR/E2.json" 2>/dev/null; then
    pass "E2  run completes with valid JSON on garbage input"
else
    fail "E2  run completes with valid JSON on garbage input" "JSON parse failed"
fi

# E3: pip.conf path is a directory, not a file
reset_state
mkdir -p "$HOME/.config/pip/pip.conf"
run_pip E3
assert_match "E3  parse_error says directory" "directory" "$(jq -r "$USER_PIP | .parse_error // \"\"" "$RESULTS_DIR/E3.json")"
rmdir "$HOME/.config/pip/pip.conf" 2>/dev/null

# E4: pip.conf is a symlink to a real file
reset_state
LINK_TARGET="$(mktemp -t real-pipconf.XXXXXX)"
cat > "$LINK_TARGET" <<'PIPEOF'
[global]
audit-level = moderate
PIPEOF
ln -sf "$LINK_TARGET" "$HOME/.config/pip/pip.conf"
run_pip E4
assert_eq "E4  symlinked file: exists=true"           "true" "$(jq -r "$USER_PIP | .exists" "$RESULTS_DIR/E4.json")"
assert_eq "E4  symlinked file: readable=true"         "true" "$(jq -r "$USER_PIP | .readable" "$RESULTS_DIR/E4.json")"
assert_eq "E4  parsed entries from symlink target"    "1"    "$(jq "$USER_PIP | (.sections // []) | [.[].entries[]] | length" "$RESULTS_DIR/E4.json")"
rm -f "$LINK_TARGET"

#==============================================================================
# Summary
#==============================================================================

printf "\n${BOLD}Summary:${RESET}  ${GREEN}PASS=%d${RESET}  ${RED}FAIL=%d${RESET}  ${YELLOW}SKIP=%d${RESET}\n" "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
exit "$FAIL_COUNT"
