#!/bin/bash
#
# Smoke tests for the Go binary (stepsecurity-dev-machine-guard)
# Adapted from tests/test_smoke.sh
#
# Usage: bash tests/test_smoke_go.sh
#

set -uo pipefail

BINARY="./stepsecurity-dev-machine-guard"

#==============================================================================
# Test framework
#==============================================================================

PASS_COUNT=0
FAIL_COUNT=0
GREEN='\033[0;32m'
RED='\033[0;31m'
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

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        pass "$label"
    else
        fail "$label" "expected=$expected actual=$actual"
    fi
}

assert_contains() {
    local label="$1" haystack="$2" needle="$3"
    # Here-string instead of `echo "$h" | grep`: under `set -o pipefail`, a
    # large haystack triggers SIGPIPE on echo when grep -q exits early after
    # the first match, which propagates as exit 141 and falsely fails the
    # check.
    if grep -q "$needle" <<<"$haystack"; then
        pass "$label"
    else
        fail "$label" "output does not contain: $needle"
    fi
}

section() {
    printf "\n${BOLD}── %s${RESET}\n" "$1"
}

#==============================================================================
# 0. Binary check
#==============================================================================

section "Binary check"

if [ -f "$BINARY" ] && [ -x "$BINARY" ]; then
    pass "Binary exists and is executable"
else
    fail "Binary exists and is executable"
    printf "\n  Build the binary first: make build\n\n"
    exit 1
fi

#==============================================================================
# 1. CLI basics
#==============================================================================

section "CLI basics"

HELP_RC=0
HELP_OUTPUT=$("$BINARY" --help 2>&1) || HELP_RC=$?
assert_eq "--help exits 0" "0" "$HELP_RC"
assert_contains "--help shows usage" "$HELP_OUTPUT" "Usage:"

VERSION_RC=0
VERSION_OUTPUT=$("$BINARY" --version 2>&1) || VERSION_RC=$?
assert_eq "--version exits 0" "0" "$VERSION_RC"
assert_contains "--version prints version string" "$VERSION_OUTPUT" "StepSecurity Dev Machine Guard v"

#==============================================================================
# 2. Pretty output (default)
#==============================================================================

section "Pretty output (default)"

PRETTY_OUTPUT=$("$BINARY" --pretty --color=never 2>&1 || true)
assert_contains "Runs successfully (produces output)" "$PRETTY_OUTPUT" "StepSecurity"
assert_contains "Output contains DEVICE header" "$PRETTY_OUTPUT" "DEVICE"
assert_contains "Output contains AI AGENTS header" "$PRETTY_OUTPUT" "AI AGENTS"
assert_contains "Output contains SUMMARY header" "$PRETTY_OUTPUT" "SUMMARY"

#==============================================================================
# 3. JSON output
#==============================================================================

section "JSON output"

JSON_OUTPUT=$("$BINARY" --json 2>/dev/null || true)

# Validate well-formed JSON
if echo "$JSON_OUTPUT" | python3 -m json.tool >/dev/null 2>&1; then
    pass "Output is valid JSON"
else
    fail "Output is valid JSON"
fi

# Top-level keys
for key in agent_version device ai_agents_and_tools ide_installations ide_extensions mcp_configs summary; do
    if echo "$JSON_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '$key' in d" 2>/dev/null; then
        pass "JSON has top-level key: $key"
    else
        fail "JSON has top-level key: $key"
    fi
done

# Scan metadata fields
for key in scan_timestamp scan_timestamp_iso agent_version; do
    if echo "$JSON_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '$key' in d" 2>/dev/null; then
        pass "JSON has scan metadata field: $key"
    else
        fail "JSON has scan metadata field: $key"
    fi
done

# device object fields
for key in hostname os_version serial_number platform user_identity; do
    if echo "$JSON_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '$key' in d['device']" 2>/dev/null; then
        pass "device has field: $key"
    else
        fail "device has field: $key"
    fi
done

# summary has numeric count fields
SUMMARY_CHECK=$(echo "$JSON_OUTPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
s = d['summary']
counts = ['ai_agents_and_tools_count', 'ide_installations_count', 'ide_extensions_count', 'mcp_configs_count', 'node_projects_count']
for c in counts:
    assert c in s, f'missing {c}'
    assert isinstance(s[c], int), f'{c} is not int'
print('ok')
" 2>&1)
assert_eq "summary has numeric count fields" "ok" "$SUMMARY_CHECK"

#==============================================================================
# 4. HTML output
#==============================================================================

section "HTML output"

HTML_TMP="/tmp/test-dmg-go-report-$$.html"
"$BINARY" --html "$HTML_TMP" >/dev/null 2>&1 || true

if [ -f "$HTML_TMP" ] && [ -s "$HTML_TMP" ]; then
    pass "HTML file exists and is non-empty"
else
    fail "HTML file exists and is non-empty"
fi

HTML_CONTENT=""
if [ -f "$HTML_TMP" ]; then
    HTML_CONTENT=$(cat "$HTML_TMP")
fi
assert_contains "HTML contains <html tag" "$HTML_CONTENT" "<html"
assert_contains "HTML contains </html> tag" "$HTML_CONTENT" "</html>"

rm -f "$HTML_TMP"
pass "Cleaned up temp HTML file"

#==============================================================================
# 5. Flag combinations
#==============================================================================

section "Flag combinations"

VERBOSE_OUT=$("$BINARY" --pretty --verbose --color=never 2>&1 || true)
if [ -n "$VERBOSE_OUT" ]; then
    pass "--verbose runs and produces output"
else
    fail "--verbose runs and produces output"
fi

JSON_VERBOSE_OUT=$("$BINARY" --json --verbose 2>/dev/null || true)
if echo "$JSON_VERBOSE_OUT" | python3 -m json.tool >/dev/null 2>&1; then
    pass "--json --verbose produces valid JSON"
else
    fail "--json --verbose produces valid JSON"
fi

COLOR_JSON_OUT=$("$BINARY" --color=never --json 2>/dev/null || true)
if echo "$COLOR_JSON_OUT" | python3 -m json.tool >/dev/null 2>&1; then
    pass "--color=never --json produces valid JSON"
else
    fail "--color=never --json produces valid JSON"
fi

# Invalid flag must exit non-zero
BOGUS_RC=0
"$BINARY" --bogus-flag >/dev/null 2>&1 || BOGUS_RC=$?
if [ "$BOGUS_RC" -ne 0 ]; then
    pass "Invalid flag exits non-zero"
else
    fail "Invalid flag exits non-zero" "exit code was 0"
fi

BOGUS_ERR=$("$BINARY" --bogus-flag 2>&1 || true)
assert_contains "Invalid flag shows error" "$BOGUS_ERR" "unknown option"

#==============================================================================
# 6. JSON schema validation
#==============================================================================

section "JSON schema validation"

# ai_tools items have name and type
AI_SCHEMA=$(echo "$JSON_OUTPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d['ai_agents_and_tools']
if len(items) == 0:
    print('ok_empty')
else:
    for i, item in enumerate(items):
        assert 'name' in item, f'ai_tools[{i}] missing name'
        assert 'type' in item, f'ai_tools[{i}] missing type'
    print('ok')
" 2>&1)
if [ "$AI_SCHEMA" = "ok" ] || [ "$AI_SCHEMA" = "ok_empty" ]; then
    pass "ai_agents_and_tools items have name and type"
else
    fail "ai_agents_and_tools items have name and type" "$AI_SCHEMA"
fi

# ide_installations items have ide_type and version
IDE_SCHEMA=$(echo "$JSON_OUTPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d['ide_installations']
if len(items) == 0:
    print('ok_empty')
else:
    for i, item in enumerate(items):
        assert 'ide_type' in item, f'ide_installations[{i}] missing ide_type'
        assert 'version' in item, f'ide_installations[{i}] missing version'
    print('ok')
" 2>&1)
if [ "$IDE_SCHEMA" = "ok" ] || [ "$IDE_SCHEMA" = "ok_empty" ]; then
    pass "ide_installations items have ide_type and version"
else
    fail "ide_installations items have ide_type and version" "$IDE_SCHEMA"
fi

# ide_extensions items have name, publisher, and ide_type
EXT_SCHEMA=$(echo "$JSON_OUTPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d['ide_extensions']
if len(items) == 0:
    print('ok_empty')
else:
    for i, item in enumerate(items):
        assert 'name' in item, f'ide_extensions[{i}] missing name'
        assert 'publisher' in item, f'ide_extensions[{i}] missing publisher'
        assert 'ide_type' in item, f'ide_extensions[{i}] missing ide_type'
    print('ok')
" 2>&1)
if [ "$EXT_SCHEMA" = "ok" ] || [ "$EXT_SCHEMA" = "ok_empty" ]; then
    pass "ide_extensions items have name, publisher, and ide_type"
else
    fail "ide_extensions items have name, publisher, and ide_type" "$EXT_SCHEMA"
fi

# mcp_configs items have config_source, config_path, and vendor
MCP_SCHEMA=$(echo "$JSON_OUTPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d['mcp_configs']
if len(items) == 0:
    print('ok_empty')
else:
    for i, item in enumerate(items):
        assert 'config_source' in item, f'mcp_configs[{i}] missing config_source'
        assert 'config_path' in item, f'mcp_configs[{i}] missing config_path'
        assert 'vendor' in item, f'mcp_configs[{i}] missing vendor'
    print('ok')
" 2>&1)
if [ "$MCP_SCHEMA" = "ok" ] || [ "$MCP_SCHEMA" = "ok_empty" ]; then
    pass "mcp_configs items have config_source, config_path, and vendor"
else
    fail "mcp_configs items have config_source, config_path, and vendor" "$MCP_SCHEMA"
fi

#==============================================================================
# 7. Search dirs
#==============================================================================

section "Search dirs"

SEARCH_RC=0
SEARCH_OUT=$("$BINARY" --search-dirs /tmp --json 2>/dev/null || true)
if echo "$SEARCH_OUT" | python3 -m json.tool >/dev/null 2>&1; then
    pass "--search-dirs /tmp --json produces valid JSON"
else
    fail "--search-dirs /tmp --json produces valid JSON"
fi

# Missing dir arg
SEARCH_ERR_RC=0
"$BINARY" --search-dirs 2>/dev/null || SEARCH_ERR_RC=$?
if [ "$SEARCH_ERR_RC" -ne 0 ]; then
    pass "--search-dirs without arg exits non-zero"
else
    fail "--search-dirs without arg exits non-zero"
fi

#==============================================================================
# 8. Configure command
#==============================================================================

section "Configure command"

# configure should be a recognized command (not "Unknown option")
assert_contains "--help mentions configure" "$HELP_OUTPUT" "configure"

# configure with empty stdin should not crash (sends EOF immediately)
CONFIGURE_RC=0
echo "" | "$BINARY" configure >/dev/null 2>&1 || CONFIGURE_RC=$?
assert_eq "configure exits 0 with empty input" "0" "$CONFIGURE_RC"

# Config file should be created
CONFIG_PATH="$HOME/.stepsecurity/config.json"
if [ -f "$CONFIG_PATH" ]; then
    pass "configure creates config file"
else
    fail "configure creates config file"
fi

#==============================================================================
# Summary
#==============================================================================

printf "\n${BOLD}══════════════════════════════════════${RESET}\n"
printf "  Total: %d   ${GREEN}Passed: %d${RESET}   ${RED}Failed: %d${RESET}\n" \
    $((PASS_COUNT + FAIL_COUNT)) "$PASS_COUNT" "$FAIL_COUNT"
printf "${BOLD}══════════════════════════════════════${RESET}\n\n"

[ "$FAIL_COUNT" -eq 0 ]
