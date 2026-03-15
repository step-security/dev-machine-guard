#!/bin/bash
#
# StepSecurity Dev Machine Guard
# https://github.com/step-security/dev-machine-guard
#
# Open-source tool to scan macOS developer environments for:
#   - IDE installations and extensions
#   - AI coding agents and CLI tools
#   - MCP (Model Context Protocol) server configurations
#   - Node.js packages (optional)
#
# Community mode: Outputs results locally (pretty/JSON/HTML). No backend required.
# Enterprise mode: Sends scan data to StepSecurity backend for centralized visibility.
#
# Usage: stepsecurity-dev-machine-guard.sh [COMMAND] [OPTIONS]
#
# Commands (enterprise only):
#   install              Install launchd for periodic scanning
#   uninstall            Remove launchd configuration
#   send-telemetry       Send scan data to StepSecurity backend
#
# Output formats (community mode):
#   --pretty             Pretty terminal output (default)
#   --json               JSON output to stdout
#   --html FILE          HTML report saved to FILE
#
# Options:
#   --enable-npm-scan    Enable Node.js package scanning
#   --disable-npm-scan   Disable Node.js package scanning
#   --search-dir DIR     Add DIR to search paths (repeatable, appends to SEARCH_DIRS)
#   --verbose            Show progress messages
#   --color=WHEN         auto | always | never (default: auto)
#   -v, --version        Show version
#   -h, --help           Show help
#
# Learn more: https://stepsecurity.io
#

set -euo pipefail

#==============================================================================
# SECTION 2: VERSION AND CLI DEFAULTS
#==============================================================================

AGENT_VERSION="1.8.1"

# Output configuration (set by CLI flags)
OUTPUT_FORMAT="pretty"  # pretty | json | html
HTML_OUTPUT_FILE=""
COLOR_MODE="auto"       # auto | always | never
QUIET=true              # Suppress progress messages by default in community mode
ENABLE_NODE_PACKAGE_SCAN="auto"  # auto | true | false

# Directories to search for projects and extensions (space-separated)
# Default: user's home directory. Customize as needed, e.g.:
#   SEARCH_DIRS="$HOME /Volumes/code"                          # home + encrypted partition
#   SEARCH_DIRS="/Volumes/code"                                # only encrypted partition
#   SEARCH_DIRS="$HOME /Volumes/code /opt/work $HOME/project"  # multiple locations
SEARCH_DIRS="\$HOME"

#==============================================================================
# STEPSECURITY ENTERPRISE CONFIGURATION
# Community users: leave these unchanged. They are only used in enterprise mode.
# Enterprise users: these values are set by the StepSecurity backend when
# generating the installation script from your dashboard.
# Learn more: https://docs.stepsecurity.io/developer-mdm/installation-script
#==============================================================================

CUSTOMER_ID="{{CUSTOMER_ID}}"
API_ENDPOINT="{{API_ENDPOINT}}"
API_KEY="{{API_KEY}}"
SCAN_FREQUENCY_HOURS="{{SCAN_FREQUENCY_HOURS}}"

# Feature flags
ENABLE_NODE_PACKAGE_SCAN_ENTERPRISE=true

# Tool availability checks
JQ_AVAILABLE=false
command -v jq &>/dev/null && JQ_AVAILABLE=true
PERL_AVAILABLE=false
command -v perl &>/dev/null && PERL_AVAILABLE=true
CURL_AVAILABLE=false
command -v curl &>/dev/null && CURL_AVAILABLE=true

# Log directory (for launchd output)
LOG_DIR="/var/log/stepsecurity"

# Set process priority to run in background (nice value 19 = lowest priority)
renice -n 19 $$ > /dev/null 2>&1

#==============================================================================
# MODE DETECTION
#==============================================================================

is_enterprise_mode() {
    if [ -n "$API_KEY" ] && [[ "$API_KEY" != *"{{"* ]]; then
        return 0
    fi
    return 1
}

#==============================================================================
# COLOR & OUTPUT UTILITIES
#==============================================================================

# ANSI color variables (set by setup_colors)
BOLD=""
DIM=""
PURPLE=""
GREEN=""
RED=""
CYAN=""
YELLOW=""
RESET=""

setup_colors() {
    if [ "$COLOR_MODE" = "never" ]; then
        return
    fi

    if [ "$COLOR_MODE" = "auto" ]; then
        # Only use colors if stderr is a terminal
        if [ ! -t 2 ]; then
            return
        fi
    fi

    BOLD='\033[1m'
    DIM='\033[2m'
    PURPLE='\033[0;35m'
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    CYAN='\033[0;36m'
    YELLOW='\033[0;33m'
    RESET='\033[0m'
}

# Print progress message to stderr (suppressed in quiet mode)
print_progress() {
    if [ "$QUIET" = true ]; then
        return
    fi
    printf "${DIM}[scanning]${RESET} %s\n" "$*" >&2
}

# Print error message to stderr (never suppressed)
print_error() {
    printf "${RED}[error]${RESET} %s\n" "$*" >&2
}

# Count objects in a JSON array using awk (no jq dependency)
count_json_array_items() {
    local json_array="$1"
    if [ "$json_array" = "[]" ]; then
        echo "0"
        return
    fi
    # Count by matching opening braces at the top level
    echo "$json_array" | awk '{
        depth=0; count=0
        for(i=1;i<=length($0);i++){
            c=substr($0,i,1)
            if(c=="{") { if(depth==0) count++; depth++ }
            else if(c=="}") depth--
        }
        print count
    }'
}

# Aliases for enterprise mode compatibility
print_info() {
    print_progress "$@"
}

print_success() {
    print_progress "$@"
}

#==============================================================================
# CORE UTILITIES
#==============================================================================

# Maximum size limits
MAX_LOG_SIZE_BYTES=$((10 * 1024 * 1024))  # 10MB limit
MAX_PACKAGE_OUTPUT_SIZE_BYTES=$((50 * 1024 * 1024))  # 50MB limit for package manager output
MAX_NODE_PROJECTS_SIZE_BYTES=$((500 * 1024 * 1024))  # 500MB limit for node projects data (stay under server warning threshold)

# Simple JSON string escape - only handles quotes, backslashes, and control chars
json_string_escape() {
    local string="$1"
    # Escape backslashes and quotes
    string="${string//\\/\\\\}"
    string="${string//\"/\\\"}"
    # Remove control characters
    string="$(echo "$string" | tr -d '\000-\037')"
    echo "$string"
}

# Escape HTML special characters to prevent injection
html_escape() {
    local string="$1"
    string="${string//&/&amp;}"
    string="${string//</&lt;}"
    string="${string//>/&gt;}"
    string="${string//\"/&quot;}"
    echo "$string"
}

# Get current time in milliseconds (macOS compatible)
# macOS date doesn't support %N, so we use seconds * 1000
get_timestamp_ms() {
    echo "$(($(date +%s) * 1000))"
}

# Safely read a file with size checking to prevent memory allocation errors
# Parameters: $1 = file path, $2 = max size in bytes (optional, defaults to 50MB)
# Returns: file contents (truncated if needed) or error message
safe_read_file() {
    local file_path="$1"
    local max_size="${2:-$MAX_PACKAGE_OUTPUT_SIZE_BYTES}"

    if [ ! -f "$file_path" ]; then
        echo ""
        return 1
    fi

    # Get file size using stat (macOS compatible)
    local file_size=$(stat -f%z "$file_path" 2>/dev/null || echo "0")

    # Check if file is too large
    if [ "$file_size" -gt "$max_size" ]; then
        print_error "Output file exceeds maximum size (${file_size} bytes > ${max_size} bytes), truncating"
        # Read only the last N bytes to get the most recent output
        tail -c "$max_size" "$file_path" 2>/dev/null || echo ""
        return 2
    fi

    # File is within limits, read it normally
    cat "$file_path" 2>/dev/null || echo ""
    return 0
}

# Base64 encode function (using built-in base64 command)
# DEPRECATED: This function causes xrealloc errors with large strings due to bash variable expansion
# Use: base64 < file | tr -d '\n' instead of base64_encode "$(cat file)"
base64_encode() {
    echo -n "$1" | base64
}

#==============================================================================
# INSTANCE LOCKING
#==============================================================================

# Lock file location (depends on user privileges)
get_lock_file_path() {
    if [ "$(id -u)" -eq 0 ]; then
        # Running as root - use system location
        echo "/var/run/stepsecurity-agent.lock"
    else
        # Running as regular user - use user home
        local user_lock_dir="$HOME/.stepsecurity"
        mkdir -p "$user_lock_dir" 2>/dev/null
        echo "$user_lock_dir/agent.lock"
    fi
}

# Acquire exclusive lock to prevent multiple instances
acquire_lock() {
    local lock_file=$(get_lock_file_path)

    # Check if lock file exists
    if [ -f "$lock_file" ]; then
        local existing_pid=$(cat "$lock_file" 2>/dev/null)

        # Validate if the process is still running
        if [ -n "$existing_pid" ] && kill -0 "$existing_pid" 2>/dev/null; then
            # Check if it's actually our script (not just any process with that PID)
            local process_name=$(ps -p "$existing_pid" -o comm= 2>/dev/null)
            if echo "$process_name" | grep -q "bash"; then
                print_error "Another instance is already running (PID: $existing_pid)"
                print_progress "If this is incorrect, remove the lock file: $lock_file"
                return 1
            else
                # PID exists but not our script - remove stale lock
                print_progress "Removing stale lock file (PID $existing_pid is not this script)"
                rm -f "$lock_file"
            fi
        else
            # Process doesn't exist - remove stale lock
            print_progress "Removing stale lock file (process $existing_pid not running)"
            rm -f "$lock_file"
        fi
    fi

    # Create lock file with current PID
    echo $$ > "$lock_file"

    # Verify we successfully wrote our PID
    local written_pid=$(cat "$lock_file" 2>/dev/null)
    if [ "$written_pid" != "$$" ]; then
        print_error "Failed to acquire lock (race condition detected)"
        return 1
    fi

    print_progress "Lock acquired (PID: $$)"
    return 0
}

# Release the lock file
release_lock() {
    local lock_file=$(get_lock_file_path)

    if [ -f "$lock_file" ]; then
        local lock_pid=$(cat "$lock_file" 2>/dev/null)
        # Only remove if it's our lock
        if [ "$lock_pid" = "$$" ]; then
            rm -f "$lock_file"
            print_progress "Lock released (PID: $$)"
        fi
    fi
}

# Cleanup handler for script exit
cleanup_on_exit() {
    release_lock
}

# Register cleanup handler
trap cleanup_on_exit EXIT INT TERM QUIT HUP

#==============================================================================
# DEVICE IDENTITY
#==============================================================================

get_device_id() {
    # Use hardware serial number as device ID
    local serial=$(get_serial_number)
    echo "$serial"
}

get_serial_number() {
    # Get hardware serial number from IOKit
    local serial=$(ioreg -l | grep IOPlatformSerialNumber | awk '{print $4}' | tr -d '"' 2>/dev/null)

    # Fallback if ioreg fails
    if [ -z "$serial" ]; then
        serial=$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}' 2>/dev/null)
    fi

    # If still empty, use "unknown"
    if [ -z "$serial" ]; then
        serial="unknown"
    fi

    echo "$serial"
}

get_os_version() {
    # Get macOS version (e.g., "14.1.1" or "26.0.1" for macOS Sequoia)
    local os_version=$(sw_vers -productVersion 2>/dev/null)

    if [ -z "$os_version" ]; then
        os_version="unknown"
    fi

    echo "$os_version"
}

get_developer_identity() {
    local username=$1

    # List of environment variables to check (in order of preference)
    local env_vars=("USER_EMAIL" "DEVELOPER_EMAIL" "STEPSEC_DEVELOPER_EMAIL")

    # Try each environment variable in order
    for var_name in "${env_vars[@]}"; do
        local var_value="${!var_name:-}"
        if [ -n "$var_value" ]; then
            echo "$var_value"
            return
        fi
    done
    # Fallback to username only
    echo "${username}"
}

#==============================================================================
# USER DIRECTORY DETECTION
#==============================================================================

# Get the currently logged-in user and their home directory
get_logged_in_user_info() {
    # Get the logged-in user from console
    local logged_in_user=$(stat -f%Su /dev/console 2>/dev/null)

    # Check if no user is logged in or if it's a system user
    if [ -z "$logged_in_user" ] || [ "$logged_in_user" = "root" ] || [ "$logged_in_user" = "_windowserver" ]; then
        echo ""  # No user logged in
        echo ""  # No home directory
        return 1
    fi

    # Get home directory using dscl
    local user_home=$(dscl . -read /Users/$logged_in_user NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')

    # Verify the home directory exists
    if [ -z "$user_home" ] || [ ! -d "$user_home" ]; then
        print_error "Home directory not found for user: $logged_in_user"
        echo "$logged_in_user"  # Return username
        echo ""  # No home directory
        return 1
    fi

    echo "$logged_in_user"
    echo "$user_home"
    return 0
}

# Execute command in the context of the logged-in user if running as root
# Usage: run_as_logged_in_user <username> <command> [args...]
# The command output can be redirected by the caller (redirection happens in parent shell)
run_as_logged_in_user() {
    local logged_in_user=$1
    shift
    local command="$*"

    if [ "$(id -u)" -eq 0 ] && [ -n "$logged_in_user" ]; then
        # Running as root - execute as the logged-in user
        # Use login shell (-l) to source profile files and get complete PATH

        # Get user's configured login shell
        local user_shell=$(dscl . -read /Users/$logged_in_user UserShell 2>/dev/null | awk '{print $2}')

        # Fallback to /bin/bash if shell detection fails
        if [ -z "$user_shell" ] || [ ! -x "$user_shell" ]; then
            user_shell="/bin/bash"
        fi

        # Execute as logged-in user with their login shell
        # The -l flag makes it a login shell, which sources profile files (.bash_profile, .zprofile, etc.)
        # This ensures the user's PATH includes developer tools (npm, pnpm, yarn, etc.)
        sudo -H -u "$logged_in_user" "$user_shell" -l -c "$command"
    else
        # Not running as root - execute directly
        bash -c "$command"
    fi
}

# Run a command with a timeout (macOS doesn't have GNU timeout)
# Usage: run_with_timeout <seconds> <command>
# Returns: command exit code, or 124 if timed out
run_with_timeout() {
    local timeout_seconds=$1
    shift
    local command="$*"

    # Run command in background
    bash -c "$command" &
    local cmd_pid=$!

    # Wait for command or timeout
    local count=0
    while kill -0 "$cmd_pid" 2>/dev/null; do
        if [ "$count" -ge "$timeout_seconds" ]; then
            kill -9 "$cmd_pid" 2>/dev/null
            wait "$cmd_pid" 2>/dev/null
            return 124
        fi
        sleep 1
        count=$((count + 1))
    done

    wait "$cmd_pid"
    return $?
}

# Execute command in the context of the logged-in user with a timeout
# Usage: run_as_logged_in_user_with_timeout <seconds> <username> <command> [args...]
run_as_logged_in_user_with_timeout() {
    local timeout_seconds=$1
    shift
    local logged_in_user=$1
    shift
    local command="$*"

    if [ "$(id -u)" -eq 0 ] && [ -n "$logged_in_user" ]; then
        local user_shell=$(dscl . -read /Users/$logged_in_user UserShell 2>/dev/null | awk '{print $2}')
        if [ -z "$user_shell" ] || [ ! -x "$user_shell" ]; then
            user_shell="/bin/bash"
        fi

        # Run as user in background with timeout
        sudo -H -u "$logged_in_user" "$user_shell" -l -c "$command" &
        local cmd_pid=$!

        local count=0
        while kill -0 "$cmd_pid" 2>/dev/null; do
            if [ "$count" -ge "$timeout_seconds" ]; then
                kill -9 "$cmd_pid" 2>/dev/null
                wait "$cmd_pid" 2>/dev/null
                return 124
            fi
            sleep 1
            count=$((count + 1))
        done

        wait "$cmd_pid"
        return $?
    else
        run_with_timeout "$timeout_seconds" "$command"
        return $?
    fi
}

get_user_directory() {
    local user_info=$(get_logged_in_user_info)
    local logged_in_user=$(echo "$user_info" | sed -n '1p')
    local user_home=$(echo "$user_info" | sed -n '2p')

    if [ -z "$logged_in_user" ] || [ -z "$user_home" ]; then
        # No user logged in
        print_progress "No user currently logged in to console"
        echo ""  # Return empty string
        return 1
    fi

    print_progress "Detected logged-in user: $logged_in_user"
    print_progress "  Home directory: $user_home"

    # Return only the logged-in user's home directory
    echo "$user_home"
    return 0
}

resolve_search_directories() {
    local user_home="$1"
    local resolved_dirs=()

    for dir in $SEARCH_DIRS; do
        # Resolve $HOME to the actual user home directory
        local resolved="${dir/\$HOME/$user_home}"
        if [ -d "$resolved" ]; then
            resolved_dirs+=("$resolved")
        else
            print_progress "Warning: Search directory not found, skipping: $resolved"
        fi
    done

    if [ ${#resolved_dirs[@]} -eq 0 ]; then
        print_progress "Warning: No valid search directories found, falling back to: $user_home"
        echo "$user_home"
        return
    fi

    printf '%s\n' "${resolved_dirs[@]}"
}

#==============================================================================
# LAUNCHD MANAGEMENT
#==============================================================================

get_script_path() {
    # Get the absolute path of this script
    local script_path="$0"

    # If it's a relative path, convert to absolute
    if [[ ! "$script_path" = /* ]]; then
        script_path="$(cd "$(dirname "$script_path")" && pwd)/$(basename "$script_path")"
    fi

    # Resolve symlinks
    if command -v readlink &> /dev/null; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS doesn't have readlink -f, use a different approach
            while [ -L "$script_path" ]; do
                local target=$(readlink "$script_path")
                if [[ "$target" = /* ]]; then
                    script_path="$target"
                else
                    script_path="$(cd "$(dirname "$script_path")" && pwd)/$(basename "$target")"
                fi
            done
        else
            script_path=$(readlink -f "$script_path" 2>/dev/null || echo "$script_path")
        fi
    fi

    echo "$script_path"
}

is_launchd_configured() {
    local current_user="$1"
    local plist_path

    if [ "$(id -u)" -eq 0 ]; then
        # Root - check LaunchDaemons
        plist_path="/Library/LaunchDaemons/com.stepsecurity.agent.plist"
    else
        # Regular user - check LaunchAgents
        plist_path="$HOME/Library/LaunchAgents/com.stepsecurity.agent.plist"
    fi

    # Check if plist file exists
    if [ ! -f "$plist_path" ]; then
        return 1
    fi

    # Check if it's loaded in launchd
    if launchctl list | grep -q "com.stepsecurity.agent"; then
        return 0
    else
        return 1
    fi
}

configure_launchd() {
    local script_path=$(get_script_path)
    local plist_path
    local interval_seconds=$((SCAN_FREQUENCY_HOURS * 3600))

    print_progress "Configuring launchd for periodic execution..."
    print_progress "  Script: ${script_path}"
    print_progress "  Interval: Every ${SCAN_FREQUENCY_HOURS} hours (${interval_seconds} seconds)"

    if [ "$(id -u)" -eq 0 ]; then
        # Running as root - use LaunchDaemon
        plist_path="/Library/LaunchDaemons/com.stepsecurity.agent.plist"
        print_progress "  Type: LaunchDaemon (system-wide)"

        # Create log directory
        mkdir -p "$LOG_DIR"
        chmod 755 "$LOG_DIR"

        # Create the plist file
        cat > "$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.stepsecurity.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${script_path}</string>
        <string>send-telemetry</string>
    </array>
    <key>StartInterval</key>
    <integer>${interval_seconds}</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/agent.error.log</string>
</dict>
</plist>
EOF
        chmod 644 "$plist_path"

        # Load the plist
        if launchctl load "$plist_path" 2>/dev/null; then
            print_progress "launchd configuration completed successfully"
            print_progress "  Plist: ${plist_path}"
            print_progress "  Logs: ${LOG_DIR}/agent.log"
            print_progress "  Errors: ${LOG_DIR}/agent.error.log"
            return 0
        else
            print_error "Failed to load launchd configuration"
            return 1
        fi
    else
        # Running as regular user - use LaunchAgent
        plist_path="$HOME/Library/LaunchAgents/com.stepsecurity.agent.plist"
        print_progress "  Type: LaunchAgent (user-specific)"

        # Create LaunchAgents directory if it doesn't exist
        mkdir -p "$HOME/Library/LaunchAgents"

        # Create log directory in user's home
        local user_log_dir="$HOME/.stepsecurity"
        mkdir -p "$user_log_dir"

        # Create the plist file
        cat > "$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.stepsecurity.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${script_path}</string>
        <string>send-telemetry</string>
    </array>
    <key>StartInterval</key>
    <integer>${interval_seconds}</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>${user_log_dir}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>${user_log_dir}/agent.error.log</string>
</dict>
</plist>
EOF

        # Load the plist
        if launchctl load "$plist_path" 2>/dev/null; then
            print_progress "launchd configuration completed successfully"
            print_progress "  Plist: ${plist_path}"
            print_progress "  Logs: ${user_log_dir}/agent.log"
            print_progress "  Errors: ${user_log_dir}/agent.error.log"
            return 0
        else
            print_error "Failed to load launchd configuration"
            return 1
        fi
    fi
}

uninstall_launchd() {
    local plist_path

    if [ "$(id -u)" -eq 0 ]; then
        plist_path="/Library/LaunchDaemons/com.stepsecurity.agent.plist"
        print_progress "Removing LaunchDaemon configuration..."
    else
        plist_path="$HOME/Library/LaunchAgents/com.stepsecurity.agent.plist"
        print_progress "Removing LaunchAgent configuration..."
    fi

    # Unload the plist if it's loaded
    if launchctl list | grep -q "com.stepsecurity.agent"; then
        if launchctl unload "$plist_path" 2>/dev/null; then
            print_progress "Unloaded launchd agent"
        else
            print_error "Failed to unload launchd agent"
        fi
    fi

    # Remove the plist file
    if [ -f "$plist_path" ]; then
        rm "$plist_path"
        print_progress "Removed plist file: ${plist_path}"
    else
        print_progress "Plist file not found: ${plist_path}"
    fi

    print_progress "launchd configuration removed successfully"
    print_progress "The agent will no longer run automatically"
}

#==============================================================================
# IDE DETECTION
#==============================================================================

detect_ide_installations() {
    local logged_in_user=$1
    print_progress "Detecting IDE and AI desktop app installations..."

    local ide_installations=""
    local first=true

    # Define IDEs/apps to detect: format is "app_name|ide_type|vendor|app_path|binary_path_for_version|version_command"
    local apps=(
        "Visual Studio Code|vscode|Microsoft|/Applications/Visual Studio Code.app|Contents/Resources/app/bin/code|--version"
        "Cursor|cursor|Cursor|/Applications/Cursor.app|Contents/Resources/app/bin/cursor|--version"
        "Windsurf|windsurf|Codeium|/Applications/Windsurf.app|Contents/MacOS/Windsurf|--version"
        "Antigravity|antigravity|Google|/Applications/Antigravity.app|Contents/MacOS/Antigravity|--version"
        "Zed|zed|Zed|/Applications/Zed.app|Contents/MacOS/zed||"
        "Claude|claude_desktop|Anthropic|/Applications/Claude.app|||"
        "Microsoft Copilot|microsoft_copilot_desktop|Microsoft|/Applications/Copilot.app|||"
    )

    for app_def in "${apps[@]}"; do
        IFS='|' read -r app_name ide_type vendor app_path binary_path version_command <<< "$app_def"

        if [ -d "$app_path" ]; then
            local version="unknown"

            # Try to get version from binary if specified
            if [ -n "$binary_path" ] && [ -x "$app_path/$binary_path" ] && [ -n "$version_command" ]; then
                version=$(run_as_logged_in_user_with_timeout 10 "$logged_in_user" "\"$app_path/$binary_path\" $version_command 2>/dev/null | head -1" || echo "unknown")
            fi

            # Fallback: try to get version from Info.plist
            if [ "$version" = "unknown" ]; then
                local plist_file="$app_path/Contents/Info.plist"
                if [ -f "$plist_file" ]; then
                    version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$plist_file" 2>/dev/null || echo "unknown")
                fi
            fi

            # Clean up version string
            version=$(echo "$version" | tr -d '\n\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            [ -z "$version" ] && version="unknown"

            print_progress "  Found: ${app_name} (${vendor}) v${version} at ${app_path}"

            [ "$first" = false ] && ide_installations="${ide_installations},"
            first=false

            # Escape strings for JSON
            local escaped_ide_type=$(json_string_escape "$ide_type")
            local escaped_version=$(json_string_escape "$version")
            local escaped_install_path=$(json_string_escape "$app_path")
            local escaped_vendor=$(json_string_escape "$vendor")

            ide_installations="${ide_installations}{\"ide_type\":\"${escaped_ide_type}\",\"version\":\"${escaped_version}\",\"install_path\":\"${escaped_install_path}\",\"vendor\":\"${escaped_vendor}\",\"is_installed\":true}"
        fi
    done

    if [ "$first" = true ]; then
        print_progress "  No IDEs or AI desktop apps found"
    fi

    echo "[${ide_installations}]"
}

#==============================================================================
# AI CLI TOOLS DETECTION
#==============================================================================

# Detect standalone AI CLI tools from all major vendors
# This function checks for AI coding assistants installed as command-line tools
detect_ai_cli_tools() {
    local logged_in_user=$1
    print_progress "Detecting AI CLI tools..."

    # Get user's home directory for config dir expansion
    local user_home=$(run_as_logged_in_user "$logged_in_user" "echo ~" 2>/dev/null || echo "$HOME")

    local ai_cli_tools=""
    local first=true
    local count=0

    # Define CLI tools to detect: format is "tool_name|vendor|binary_names|config_dirs"
    # binary_names and config_dirs are comma-separated lists
    local tools=(
        "claude-code|Anthropic|claude,~/.claude/local/claude,~/.local/bin/claude|~/.claude"
        "codex|OpenAI|codex|~/.codex"
        "gemini-cli|Google|gemini|~/.gemini"
        "amazon-q-cli|Amazon|kiro-cli,kiro,q|~/.q,~/.kiro,~/.aws/q"
        "github-copilot-cli|Microsoft|copilot,gh-copilot|~/.config/github-copilot"
        "microsoft-ai-shell|Microsoft|aish,ai|~/.aish"
        "aider|OpenSource|aider|~/.aider"
        "opencode|OpenSource|opencode,~/.opencode/bin/opencode|~/.config/opencode"
    )

    for tool_def in "${tools[@]}"; do
        IFS='|' read -r tool_name vendor binary_names config_dirs <<< "$tool_def"

        # Try to find the binary
        local binary_path=""
        local version="unknown"
        local found=false

        # Split binary names by comma and check each
        IFS=',' read -ra BINARY_ARRAY <<< "$binary_names"
        for binary_name in "${BINARY_ARRAY[@]}"; do
            # Check in user's PATH (run in user context)
            local check_result=$(run_as_logged_in_user_with_timeout 10 "$logged_in_user" "command -v $binary_name 2>/dev/null" || echo "")

            if [ -n "$check_result" ]; then
                binary_path="$check_result"
                found=true

                # Get version - different commands for different tools
                case "$tool_name" in
                    claude-code)
                        version=$(run_as_logged_in_user_with_timeout 10 "$logged_in_user" "$binary_name --version 2>/dev/null | head -1" || echo "unknown")
                        ;;
                    amazon-q-cli)
                        # Verify it's actually Amazon Q and not another 'q' command
                        local verify=$(run_as_logged_in_user_with_timeout 10 "$logged_in_user" "$binary_name --version 2>/dev/null | grep -i 'amazon\\|kiro\\|q developer'" || echo "")
                        if [ -n "$verify" ]; then
                            version=$(run_as_logged_in_user_with_timeout 10 "$logged_in_user" "$binary_name --version 2>/dev/null | head -1" || echo "unknown")
                        else
                            # Not Amazon Q CLI, skip
                            found=false
                            continue
                        fi
                        ;;
                    github-copilot-cli)
                        # The binary is just 'copilot', not 'gh-copilot'
                        version=$(run_as_logged_in_user_with_timeout 10 "$logged_in_user" "$binary_name --version 2>/dev/null | head -1" || echo "unknown")
                        ;;
                    opencode)
                        version=$(run_as_logged_in_user_with_timeout 10 "$logged_in_user" "$binary_name -v 2>/dev/null | head -1" || echo "unknown")
                        ;;
                    *)
                        # Generic version check
                        version=$(run_as_logged_in_user_with_timeout 10 "$logged_in_user" "$binary_name --version 2>/dev/null | head -1" || echo "unknown")
                        ;;
                esac

                break  # Found the binary, stop checking other names
            fi
        done

        if [ "$found" = true ]; then
            # Check for config directory
            local config_dir=""
            IFS=',' read -ra CONFIG_ARRAY <<< "$config_dirs"
            for config_candidate in "${CONFIG_ARRAY[@]}"; do
                # Expand ~ to home directory
                local expanded_config="${config_candidate/#\~/$user_home}"
                if [ -d "$expanded_config" ]; then
                    config_dir="$expanded_config"
                    break
                fi
            done

            # Clean up version string (remove extra whitespace, newlines)
            version=$(echo "$version" | tr -d '\n\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

            print_progress "  Found: ${tool_name} (${vendor}) v${version} at ${binary_path}"

            [ "$first" = false ] && ai_cli_tools="${ai_cli_tools},"
            first=false
            count=$((count + 1))

            # Escape strings for JSON
            local escaped_tool_name=$(json_string_escape "$tool_name")
            local escaped_vendor=$(json_string_escape "$vendor")
            local escaped_binary_path=$(json_string_escape "$binary_path")
            local escaped_version=$(json_string_escape "$version")
            local escaped_config_dir=$(json_string_escape "$config_dir")

            ai_cli_tools="${ai_cli_tools}{\"name\":\"${escaped_tool_name}\",\"vendor\":\"${escaped_vendor}\",\"type\":\"cli_tool\",\"version\":\"${escaped_version}\",\"binary_path\":\"${escaped_binary_path}\",\"config_dir\":\"${escaped_config_dir}\"}"
        fi
    done

    if [ "$count" -eq 0 ]; then
        print_progress "  No AI CLI tools found"
    else
        print_progress "  Found ${count} AI CLI tool(s)"
    fi

    echo "[${ai_cli_tools}]"
}

#==============================================================================
# GENERAL-PURPOSE AI AGENTS DETECTION
#==============================================================================

# Detect general-purpose AI agents (not just coding-focused)
# These agents can automate desktop tasks, browse the web, etc.
detect_general_ai_agents() {
    local user_home=$1
    print_progress "Detecting general-purpose AI agents..."

    local ai_agents=""
    local first=true
    local count=0

    # Define agents to detect: format is "agent_name|vendor|detection_paths|binary_names"
    # detection_paths can be directories or files; binary_names for version extraction
    local agents=(
        "openclaw|OpenSource|$user_home/.openclaw|openclaw"
        "clawdbot|OpenSource|$user_home/.clawdbot|clawdbot"
        "moltbot|OpenSource|$user_home/.moltbot|moltbot"
        "moldbot|OpenSource|$user_home/.moldbot|moldbot"
        "gpt-engineer|OpenSource|$user_home/.gpt-engineer|gpt-engineer"
    )

    for agent_def in "${agents[@]}"; do
        IFS='|' read -r agent_name vendor detection_paths binary_names <<< "$agent_def"

        local found=false
        local install_path=""
        local version="unknown"

        # Check detection paths (directories or files)
        IFS=',' read -ra PATH_ARRAY <<< "$detection_paths"
        for path in "${PATH_ARRAY[@]}"; do
            if [ -d "$path" ] || [ -f "$path" ]; then
                found=true
                install_path="$path"
                break
            fi
        done

        # If not found by detection paths, check if binary exists in PATH
        if [ "$found" = false ]; then
            IFS=',' read -ra BINARY_ARRAY <<< "$binary_names"
            for binary_name in "${BINARY_ARRAY[@]}"; do
                local binary_check=$(command -v "$binary_name" 2>/dev/null || echo "")
                if [ -n "$binary_check" ]; then
                    found=true
                    install_path="$binary_check"
                    break
                fi
            done
        fi

        # If found, try to get version from binary
        if [ "$found" = true ]; then
            IFS=',' read -ra BINARY_ARRAY <<< "$binary_names"
            for binary_name in "${BINARY_ARRAY[@]}"; do
                local binary_check=$(command -v "$binary_name" 2>/dev/null || echo "")
                if [ -n "$binary_check" ]; then
                    version=$(run_with_timeout 10 "$binary_name --version 2>/dev/null | head -1" || echo "unknown")
                    version=$(echo "$version" | tr -d '\n\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                    break
                fi
            done

            print_progress "  Found: ${agent_name} (${vendor}) at ${install_path}"

            [ "$first" = false ] && ai_agents="${ai_agents},"
            first=false
            count=$((count + 1))

            # Escape strings for JSON
            local escaped_agent_name=$(json_string_escape "$agent_name")
            local escaped_vendor=$(json_string_escape "$vendor")
            local escaped_install_path=$(json_string_escape "$install_path")
            local escaped_version=$(json_string_escape "$version")

            ai_agents="${ai_agents}{\"name\":\"${escaped_agent_name}\",\"vendor\":\"${escaped_vendor}\",\"type\":\"general_agent\",\"version\":\"${escaped_version}\",\"install_path\":\"${escaped_install_path}\"}"
        fi
    done

    # Check for Claude Cowork (special case - it's a mode within Claude Desktop)
    # Cowork was introduced in Claude Desktop 0.7.0 (early 2026)
    local claude_desktop_path="/Applications/Claude.app"
    if [ -d "$claude_desktop_path" ]; then
        # Check if version supports Cowork (v0.7.0+)
        local claude_version=""
        local plist_file="$claude_desktop_path/Contents/Info.plist"
        if [ -f "$plist_file" ]; then
            claude_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$plist_file" 2>/dev/null || echo "unknown")

            # Simple version check: if version starts with "0.7" or higher, or "1." or higher
            if [[ "$claude_version" =~ ^0\.[7-9] ]] || [[ "$claude_version" =~ ^[1-9]\. ]]; then
                print_progress "  Found: claude-cowork (Anthropic) - mode within Claude Desktop v${claude_version}"

                [ "$first" = false ] && ai_agents="${ai_agents},"
                first=false
                count=$((count + 1))

                ai_agents="${ai_agents}{\"name\":\"claude-cowork\",\"vendor\":\"Anthropic\",\"type\":\"general_agent\",\"version\":\"${claude_version}\",\"install_path\":\"${claude_desktop_path}\"}"
            fi
        fi
    fi

    if [ "$count" -eq 0 ]; then
        print_progress "  No general-purpose AI agents found"
    else
        print_progress "  Found ${count} general-purpose AI agent(s)"
    fi

    echo "[${ai_agents}]"
}

#==============================================================================
# AI FRAMEWORKS DETECTION
#==============================================================================

# Detect AI frameworks and runtimes (for running local LLMs)
detect_ai_frameworks() {
    local logged_in_user=$1
    print_progress "Detecting AI frameworks and runtimes..."

    local ai_frameworks=""
    local first=true
    local count=0

    # Define frameworks to detect: format is "framework_name|binary_name|process_name"
    local frameworks=(
        "ollama|ollama|ollama"
        "localai|local-ai|local-ai"
        "lm-studio|lm-studio|lm-studio"
        "text-generation-webui|textgen|textgen"
    )

    for framework_def in "${frameworks[@]}"; do
        IFS='|' read -r framework_name binary_name process_name <<< "$framework_def"

        # Check if binary exists
        local binary_path=$(run_as_logged_in_user_with_timeout 10 "$logged_in_user" "command -v $binary_name 2>/dev/null" || echo "")

        if [ -n "$binary_path" ]; then
            # Get version
            local version=$(run_as_logged_in_user_with_timeout 10 "$logged_in_user" "$binary_name --version 2>/dev/null | head -1" || echo "unknown")
            version=$(echo "$version" | tr -d '\n\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

            # Check if process is running
            local is_running=false
            if pgrep -x "$process_name" > /dev/null 2>&1; then
                is_running=true
            fi

            print_progress "  Found: ${framework_name} v${version} at ${binary_path} (running: ${is_running})"

            [ "$first" = false ] && ai_frameworks="${ai_frameworks},"
            first=false
            count=$((count + 1))

            # Escape strings for JSON
            local escaped_framework_name=$(json_string_escape "$framework_name")
            local escaped_binary_path=$(json_string_escape "$binary_path")
            local escaped_version=$(json_string_escape "$version")

            ai_frameworks="${ai_frameworks}{\"name\":\"${escaped_framework_name}\",\"vendor\":\"Unknown\",\"type\":\"framework\",\"version\":\"${escaped_version}\",\"binary_path\":\"${escaped_binary_path}\",\"is_running\":${is_running}}"
        fi
    done

    # Check for LM Studio as an application (it's primarily a GUI app)
    local lm_studio_app="/Applications/LM Studio.app"
    if [ -d "$lm_studio_app" ]; then
        local version="unknown"
        local plist_file="$lm_studio_app/Contents/Info.plist"
        if [ -f "$plist_file" ]; then
            version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$plist_file" 2>/dev/null || echo "unknown")
        fi

        # Check if running
        local is_running=false
        if pgrep -f "LM Studio" > /dev/null 2>&1; then
            is_running=true
        fi

        print_progress "  Found: lm-studio v${version} at ${lm_studio_app} (running: ${is_running})"

        [ "$first" = false ] && ai_frameworks="${ai_frameworks},"
        first=false
        count=$((count + 1))

        ai_frameworks="${ai_frameworks}{\"name\":\"lm-studio\",\"vendor\":\"LM Studio\",\"type\":\"framework\",\"version\":\"${version}\",\"binary_path\":\"${lm_studio_app}\",\"is_running\":${is_running}}"
    fi

    if [ "$count" -eq 0 ]; then
        print_progress "  No AI frameworks found"
    else
        print_progress "  Found ${count} AI framework(s)"
    fi

    echo "[${ai_frameworks}]"
}

#==============================================================================
# MCP CONFIG COLLECTION
#==============================================================================

# Collect MCP (Model Context Protocol) configuration files
# These configs tell AI agents which external tools/servers they can connect to
# IMPORTANT: We do NOT parse these files - just read and base64 encode them
# Backend will do all parsing safely in Go
collect_mcp_configs() {
    local user_home=$1
    print_progress "Collecting MCP configuration files..."

    local mcp_configs=""
    local first=true
    local count=0
    local jq_filter='
      def extract: map_values(
        {command, args, serverUrl, url}
        | with_entries(select(.value != null))
      );
      if .mcpServers then {mcpServers: (.mcpServers | extract)}
      elif .context_servers then {context_servers: (.context_servers | extract)}
      elif .projects then {mcpServers: ([.projects[].mcpServers // {} | to_entries[]] | from_entries | extract)}
      else {} end
    '
    # Define MCP config sources: format is "source_name|config_path|vendor"
    local config_sources=(
        "claude_desktop|$user_home/Library/Application Support/Claude/claude_desktop_config.json|Anthropic"
        "claude_code|$user_home/.claude/settings.json|Anthropic"
        "claude_code|$user_home/.claude.json|Anthropic"
        "cursor|$user_home/.cursor/mcp.json|Cursor"
        "windsurf|$user_home/.codeium/windsurf/mcp_config.json|Codeium"
        "antigravity|$user_home/.gemini/antigravity/mcp_config.json|Google"
        "zed|$user_home/.config/zed/settings.json|Zed"
        "open_interpreter|$user_home/.config/open-interpreter/config.yaml|OpenSource"
        "codex|$user_home/.codex/config.toml|OpenAI"
    )

    for config_def in "${config_sources[@]}"; do
        IFS='|' read -r source_name config_path vendor <<< "$config_def"

        # Check if config file exists
        if [ -f "$config_path" ]; then
            # Read file and filter out fields we don't need before encoding
            # Use safe_read_file to handle large files
            local config_content
            config_content=$(safe_read_file "$config_path" 2>/dev/null || echo "")

            if [ -n "$config_content" ]; then
                # For JSON configs, strip fields we don't need (env vars, headers, etc.)
                # before encoding. Falls back to raw content for non-JSON formats (TOML, YAML).
                # Zed settings.json is JSONC (allows // comments), so comments are stripped upfront.
                local filtered_content
                if [ "$JQ_AVAILABLE" = true ] && [[ "$config_path" == *.json ]]; then
                    local json_input="$config_content"
                    # Zed uses JSONC (allows // and /* */ comments); strip them before parsing
                    if [ "$source_name" = "zed" ] && [ "$PERL_AVAILABLE" = true ]; then
                        json_input=$(echo "$config_content" | perl -0777 -pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g')
                    fi
                    if filtered_content=$(echo "$json_input" | jq -c "$jq_filter" 2>/dev/null) && [ -n "$filtered_content" ]; then
                        config_content="$filtered_content"
                    fi
                fi

                print_progress "  Found: ${source_name} config (${vendor})"

                [ "$first" = false ] && mcp_configs="${mcp_configs},"
                first=false
                count=$((count + 1))

                # Escape strings for JSON
                local escaped_source_name=$(json_string_escape "$source_name")
                local escaped_config_path=$(json_string_escape "$config_path")
                local escaped_vendor=$(json_string_escape "$vendor")

                if is_enterprise_mode; then
                    # Enterprise mode: base64 encode for upload
                    local config_content_base64
                    config_content_base64=$(echo -n "$config_content" | base64 | tr -d '\n')
                    mcp_configs="${mcp_configs}{\"config_source\":\"${escaped_source_name}\",\"config_path\":\"${escaped_config_path}\",\"vendor\":\"${escaped_vendor}\",\"config_content_base64\":\"${config_content_base64}\"}"
                else
                    # Community mode: only show source, path, vendor (no content for privacy)
                    mcp_configs="${mcp_configs}{\"config_source\":\"${escaped_source_name}\",\"config_path\":\"${escaped_config_path}\",\"vendor\":\"${escaped_vendor}\"}"
                fi
            else
                print_progress "  Skipping ${source_name}: empty or unreadable config"
            fi
        fi
    done

    if [ "$count" -eq 0 ]; then
        print_progress "  No MCP config files found"
    else
        print_progress "  Found ${count} MCP config file(s)"
    fi

    echo "[${mcp_configs}]"
}

#==============================================================================
# IDE EXTENSION COLLECTION
#==============================================================================

# Load obsolete extensions from .obsolete file
# Parameters: $1 = extensions directory
load_obsolete_extensions() {
    local ext_dir=$1
    local obsolete_file="$ext_dir/.obsolete"

    if [ -f "$obsolete_file" ]; then
        # Read the .obsolete file and return its content
        cat "$obsolete_file" 2>/dev/null || echo "{}"
    else
        echo "{}"
    fi
}

# Check if an extension is marked as obsolete
# Parameters: $1 = extension dirname, $2 = obsolete JSON content
is_extension_obsolete() {
    local dirname=$1
    local obsolete_json=$2

    # Check if the extension dirname appears in the obsolete JSON
    # The obsolete file format is: {"publisher.name-version":true,...}
    if echo "$obsolete_json" | grep -q "\"$dirname\":true"; then
        return 0  # Is obsolete
    else
        return 1  # Not obsolete
    fi
}

# Generic function to collect extensions from an IDE
# Parameters: $1 = IDE name, $2 = extensions directory, $3 = ide_type, $4 = username
collect_ide_extensions() {
    local ide_name=$1
    local ext_dir=$2
    local ide_type=$3
    local username=$4

    if [ ! -d "$ext_dir" ]; then
        echo "[]"
        echo "0"  # Count
        return
    fi

    print_progress "  Scanning ${ide_name} extensions for user ${username}..."

    # Load obsolete extensions from .obsolete file
    local obsolete_json=$(load_obsolete_extensions "$ext_dir")

    local extensions=""
    local first=true
    local count=0

    for dir in "$ext_dir"/*; do
        if [ ! -d "$dir" ]; then
            continue
        fi

        local dirname=$(basename "$dir")

        # Skip special files/directories
        if [ "$dirname" = "extensions.json" ] || [ "$dirname" = ".obsolete" ]; then
            continue
        fi

        # Skip obsolete/uninstalled extensions
        if is_extension_obsolete "$dirname" "$obsolete_json"; then
            continue
        fi

        # Parse: publisher.name-version or publisher.name-version-platform
        local publisher="${dirname%%.*}"
        local rest="${dirname#*.}"

        # Remove platform suffix if present (e.g., -darwin-arm64, -universal)
        rest="${rest%-darwin-*}"
        rest="${rest%-universal}"

        local version="${rest##*-}"
        local name="${rest%-*}"

        # Basic validation
        if [ -n "$publisher" ] && [ -n "$name" ] && [ -n "$version" ]; then
            # Get install date from directory modification time
            local install_date=$(stat -f %m "$dir" 2>/dev/null || echo "0")

            [ "$first" = false ] && extensions="${extensions},"
            first=false
            extensions="${extensions}{\"id\":\"${publisher}.${name}\",\"name\":\"${name}\",\"version\":\"${version}\",\"publisher\":\"${publisher}\",\"install_date\":${install_date},\"ide_type\":\"${ide_type}\"}"
            count=$((count + 1))
        fi
    done

    echo "[${extensions}]"
    echo "$count"  # Return count on second line
}

# Collect all IDE extensions for a specific user home directory
collect_user_extensions() {
    local user_home=$1
    local username=$(basename "$user_home")

    print_progress "Scanning extensions for user: ${username} (${user_home})"

    local all_extensions=""
    local total_count=0
    local first=true

    # Collect VSCode extensions
    local vscode_ext_dir="$user_home/.vscode/extensions"
    if [ -d "$vscode_ext_dir" ]; then
        local vscode_result=$(collect_ide_extensions "VSCode" "$vscode_ext_dir" "vscode" "$username")
        local vscode_extensions=$(echo "$vscode_result" | head -1)
        local vscode_count=$(echo "$vscode_result" | tail -1)

        if [ "$vscode_count" != "0" ] && [ "$vscode_extensions" != "[]" ]; then
            # Remove the surrounding brackets to merge arrays later
            vscode_extensions="${vscode_extensions#[}"
            vscode_extensions="${vscode_extensions%]}"
            all_extensions="${vscode_extensions}"
            total_count=$((total_count + vscode_count))
            first=false
        fi
    fi

    # Collect Cursor extensions
    local cursor_ext_dir="$user_home/.cursor/extensions"
    if [ -d "$cursor_ext_dir" ]; then
        local cursor_result=$(collect_ide_extensions "OpenVSX" "$cursor_ext_dir" "openvsx" "$username")
        local cursor_extensions=$(echo "$cursor_result" | head -1)
        local cursor_count=$(echo "$cursor_result" | tail -1)

        if [ "$cursor_count" != "0" ] && [ "$cursor_extensions" != "[]" ]; then
            # Remove the surrounding brackets to merge arrays
            cursor_extensions="${cursor_extensions#[}"
            cursor_extensions="${cursor_extensions%]}"

            if [ "$first" = false ]; then
                all_extensions="${all_extensions},${cursor_extensions}"
            else
                all_extensions="${cursor_extensions}"
            fi
            total_count=$((total_count + cursor_count))
            first=false
        fi
    fi

    if [ "$total_count" -gt 0 ]; then
        print_progress "  Found ${total_count} extensions for user ${username}"
    fi

    echo "[${all_extensions}]"
    echo "$total_count"
}

# Collect extensions from user directory
collect_all_extensions() {
    local user_dir="$1"

    local all_extensions=""
    local total_count=0

    # Handle single user directory
    if [ -n "$user_dir" ]; then
        local user_result=$(collect_user_extensions "$user_dir")
        local user_extensions=$(echo "$user_result" | head -1)
        local user_count=$(echo "$user_result" | tail -1)

        if [ "$user_count" != "0" ] && [ "$user_extensions" != "[]" ]; then
            # Remove the surrounding brackets
            user_extensions="${user_extensions#[}"
            user_extensions="${user_extensions%]}"
            all_extensions="${user_extensions}"
            total_count=$user_count
        fi
    fi

    if [ "$total_count" -gt 0 ]; then
        print_progress "Found total of ${total_count} IDE extensions"
    else
        print_progress "No IDE extensions found"
    fi

    echo "[${all_extensions}]"
    echo "$total_count"
}

#==============================================================================
# SECTION 15: NODE.JS PACKAGE SCANNING
#==============================================================================

# Detect installed package managers and their versions
detect_package_managers() {
    local logged_in_user=$1
    print_progress "Detecting Node.js package managers..."

    local package_managers=""
    local first=true

    # Check for npm (run in user context to access their PATH)
    local npm_check=$(run_as_logged_in_user "$logged_in_user" "command -v npm 2>/dev/null && npm --version 2>/dev/null" || echo "")
    if [ -n "$npm_check" ]; then
        local npm_path=$(echo "$npm_check" | head -1)
        local npm_version=$(echo "$npm_check" | tail -1)
        [ -z "$npm_version" ] && npm_version="unknown"
        print_progress "  Found: npm v${npm_version} at ${npm_path}"

        [ "$first" = false ] && package_managers="${package_managers},"
        first=false
        package_managers="${package_managers}{\"name\":\"npm\",\"version\":\"${npm_version}\",\"is_global\":true,\"binary_path\":\"${npm_path}\"}"
    fi

    # Check for yarn (run in user context to access their PATH)
    local yarn_check=$(run_as_logged_in_user "$logged_in_user" "command -v yarn 2>/dev/null && yarn --version 2>/dev/null" || echo "")
    if [ -n "$yarn_check" ]; then
        local yarn_path=$(echo "$yarn_check" | head -1)
        local yarn_version=$(echo "$yarn_check" | tail -1)
        [ -z "$yarn_version" ] && yarn_version="unknown"
        print_progress "  Found: yarn v${yarn_version} at ${yarn_path}"

        [ "$first" = false ] && package_managers="${package_managers},"
        first=false
        package_managers="${package_managers}{\"name\":\"yarn\",\"version\":\"${yarn_version}\",\"is_global\":true,\"binary_path\":\"${yarn_path}\"}"
    fi

    # Check for pnpm (run in user context to access their PATH)
    local pnpm_check=$(run_as_logged_in_user "$logged_in_user" "command -v pnpm 2>/dev/null && pnpm --version 2>/dev/null" || echo "")
    if [ -n "$pnpm_check" ]; then
        local pnpm_path=$(echo "$pnpm_check" | head -1)
        local pnpm_version=$(echo "$pnpm_check" | tail -1)
        [ -z "$pnpm_version" ] && pnpm_version="unknown"
        print_progress "  Found: pnpm v${pnpm_version} at ${pnpm_path}"

        [ "$first" = false ] && package_managers="${package_managers},"
        first=false
        package_managers="${package_managers}{\"name\":\"pnpm\",\"version\":\"${pnpm_version}\",\"is_global\":true,\"binary_path\":\"${pnpm_path}\"}"
    fi

    # Check for bun (run in user context to access their PATH)
    local bun_check=$(run_as_logged_in_user "$logged_in_user" "command -v bun 2>/dev/null && bun --version 2>/dev/null" || echo "")
    if [ -n "$bun_check" ]; then
        local bun_path=$(echo "$bun_check" | head -1)
        local bun_version=$(echo "$bun_check" | tail -1)
        [ -z "$bun_version" ] && bun_version="unknown"
        print_progress "  Found: bun v${bun_version} at ${bun_path}"

        [ "$first" = false ] && package_managers="${package_managers},"
        first=false
        package_managers="${package_managers}{\"name\":\"bun\",\"version\":\"${bun_version}\",\"is_global\":true,\"binary_path\":\"${bun_path}\"}"
    fi

    if [ "$first" = true ]; then
        print_progress "  No Node.js package managers found"
    fi

    echo "[${package_managers}]"
}

# Scan globally installed packages - sends RAW output to backend for parsing
scan_global_packages() {
    local logged_in_user=$1
    print_progress "Scanning globally installed packages..."

    # Write results to temp file to avoid bash variable accumulation limit (~1GB in bash 3.2)
    local global_projects_file=$(mktemp)
    local first=true
    local count=0

    # Scan npm global packages (including all transitive dependencies)
    # Check in user context (not root context) since npm is in user's PATH
    print_progress "  Checking npm global packages..."

    local npm_version=$(run_as_logged_in_user "$logged_in_user" "npm --version 2>/dev/null" || echo "unknown")
    local npm_prefix=$(run_as_logged_in_user "$logged_in_user" "npm config get prefix 2>/dev/null" || echo "")

    if [ -n "$npm_prefix" ]; then
        local start_time=$(get_timestamp_ms)
        local raw_stdout=""
        local raw_stderr=""
        local error_msg=""
        local exit_code=0

        # Create temp files for capturing stdout and stderr separately
        local stdout_file=$(mktemp)
        local stderr_file=$(mktemp)

        # Get globally installed packages in JSON format with limited depth to prevent memory issues
        # Using --depth=3 to limit dependency tree depth while still capturing most packages
        # Wrap in subshell with error handling to prevent script exit
        (
            set +e  # Disable exit on error for this subshell
            run_as_logged_in_user "$logged_in_user" "npm list -g --json --depth=3 2>&1" > "$stdout_file" 2> "$stderr_file"
            echo $? > "${stdout_file}.exitcode"
        ) || {
            # If the subshell itself fails catastrophically, log it
            echo "npm global scan failed catastrophically (possible memory error)" > "$stderr_file"
            echo 255 > "${stdout_file}.exitcode"
        }

        # Read exit code
        if [ -f "${stdout_file}.exitcode" ]; then
            exit_code=$(cat "${stdout_file}.exitcode" 2>/dev/null || echo "1")
            rm -f "${stdout_file}.exitcode"
        else
            exit_code=1
        fi

        if [ $exit_code -eq 255 ]; then
            error_msg="npm list -g command failed catastrophically (possible memory error)"
        elif [ $exit_code -ne 0 ]; then
            error_msg="npm list -g command failed with exit code $exit_code"
        fi

        # Base64 encode stdout and stderr directly from files to avoid bash variable expansion
        # This prevents xrealloc errors when dealing with large output (integer underflow issue)
        local encoded_stdout=$(safe_read_file "$stdout_file" 2>/dev/null | base64 | tr -d '\n' || echo "")
        local encoded_stderr=$(safe_read_file "$stderr_file" 2>/dev/null | base64 | tr -d '\n' || echo "")

        # Clean up temp files
        rm -f "$stdout_file" "$stderr_file"

        local end_time=$(get_timestamp_ms)
        local duration=$((end_time - start_time))

        # Escape strings for JSON
        local escaped_prefix=$(json_string_escape "$npm_prefix")
        local escaped_error=$(json_string_escape "$error_msg")

        [ "$first" = false ] && printf '%s' "," >> "$global_projects_file"
        first=false
        count=$((count + 1))

        printf '%s' "{\"project_path\":\"${escaped_prefix}\",\"package_manager\":\"npm\",\"package_manager_version\":\"${npm_version}\",\"working_directory\":\"${escaped_prefix}\",\"raw_stdout_base64\":\"${encoded_stdout}\",\"raw_stderr_base64\":\"${encoded_stderr}\",\"error\":\"${escaped_error}\",\"exit_code\":${exit_code},\"scan_duration_ms\":${duration}}" >> "$global_projects_file"
    fi

    # Scan yarn global packages (Yarn Classic)
    # Check in user context (not root context) since yarn is in user's PATH
    print_progress "  Checking yarn global packages..."

    local yarn_version=$(run_as_logged_in_user "$logged_in_user" "yarn --version 2>/dev/null" || echo "unknown")
    # Get yarn global directory
    local yarn_global_dir=$(run_as_logged_in_user "$logged_in_user" "yarn global dir 2>/dev/null" || echo "")

    if [ -n "$yarn_global_dir" ]; then
        local start_time=$(get_timestamp_ms)
        local raw_stdout=""
        local raw_stderr=""
        local error_msg=""
        local exit_code=0

        # Create temp files for capturing stdout and stderr separately
        local stdout_file=$(mktemp)
        local stderr_file=$(mktemp)

        # Get globally installed packages
        # Note: yarn global list --json doesn't output tree structure, only progress events
        # Use list command in the global directory to get proper JSON tree output
        # Use --depth=0 to get only direct global packages (not transitive dependencies)
        # Wrap in subshell with error handling
        (
            set +e  # Disable exit on error for this subshell
            run_as_logged_in_user "$logged_in_user" "cd '$yarn_global_dir' && yarn list --json --depth=0 2>&1" > "$stdout_file" 2> "$stderr_file"
            echo $? > "${stdout_file}.exitcode"
        ) || {
            echo "yarn global scan failed catastrophically (possible memory error)" > "$stderr_file"
            echo 255 > "${stdout_file}.exitcode"
        }

        # Read exit code
        if [ -f "${stdout_file}.exitcode" ]; then
            exit_code=$(cat "${stdout_file}.exitcode" 2>/dev/null || echo "1")
            rm -f "${stdout_file}.exitcode"
        else
            exit_code=1
        fi

        if [ $exit_code -eq 255 ]; then
            error_msg="yarn global list command failed catastrophically (possible memory error)"
        elif [ $exit_code -ne 0 ]; then
            error_msg="yarn global list command failed with exit code $exit_code"
        fi

        # Base64 encode stdout and stderr directly from files to avoid bash variable expansion
        # This prevents xrealloc errors when dealing with large output (integer underflow issue)
        local encoded_stdout=$(safe_read_file "$stdout_file" 2>/dev/null | base64 | tr -d '\n' || echo "")
        local encoded_stderr=$(safe_read_file "$stderr_file" 2>/dev/null | base64 | tr -d '\n' || echo "")

        # Clean up temp files
        rm -f "$stdout_file" "$stderr_file"

        local end_time=$(get_timestamp_ms)
        local duration=$((end_time - start_time))

        # Escape strings for JSON
        local escaped_global_dir=$(json_string_escape "$yarn_global_dir")
        local escaped_error=$(json_string_escape "$error_msg")

        [ "$first" = false ] && printf '%s' "," >> "$global_projects_file"
        first=false
        count=$((count + 1))

        printf '%s' "{\"project_path\":\"${escaped_global_dir}\",\"package_manager\":\"yarn\",\"package_manager_version\":\"${yarn_version}\",\"working_directory\":\"${escaped_global_dir}\",\"raw_stdout_base64\":\"${encoded_stdout}\",\"raw_stderr_base64\":\"${encoded_stderr}\",\"error\":\"${escaped_error}\",\"exit_code\":${exit_code},\"scan_duration_ms\":${duration}}" >> "$global_projects_file"
    fi

    # Scan pnpm global packages
    # Check in user context (not root context) since pnpm is in user's PATH
    print_progress "  Checking pnpm global packages..."

    local pnpm_version=$(run_as_logged_in_user "$logged_in_user" "pnpm --version 2>/dev/null" || echo "unknown")
    # Get pnpm global directory
    local pnpm_global_dir=$(run_as_logged_in_user "$logged_in_user" "pnpm root -g 2>/dev/null" || echo "")

    if [ -n "$pnpm_global_dir" ]; then
        # pnpm root -g returns the node_modules path, we want the parent
        pnpm_global_dir=$(dirname "$pnpm_global_dir" 2>/dev/null || echo "$pnpm_global_dir")

        local start_time=$(get_timestamp_ms)
        local raw_stdout=""
        local raw_stderr=""
        local error_msg=""
        local exit_code=0

        # Create temp files for capturing stdout and stderr separately
        local stdout_file=$(mktemp)
        local stderr_file=$(mktemp)

        # Get globally installed packages with limited depth to prevent memory issues
        # Wrap in subshell with error handling
        (
            set +e  # Disable exit on error for this subshell
            run_as_logged_in_user "$logged_in_user" "pnpm list -g --json --depth=3 2>&1" > "$stdout_file" 2> "$stderr_file"
            echo $? > "${stdout_file}.exitcode"
        ) || {
            echo "pnpm global scan failed catastrophically (possible memory error)" > "$stderr_file"
            echo 255 > "${stdout_file}.exitcode"
        }

        # Read exit code
        if [ -f "${stdout_file}.exitcode" ]; then
            exit_code=$(cat "${stdout_file}.exitcode" 2>/dev/null || echo "1")
            rm -f "${stdout_file}.exitcode"
        else
            exit_code=1
        fi

        if [ $exit_code -eq 255 ]; then
            error_msg="pnpm list -g command failed catastrophically (possible memory error)"
        elif [ $exit_code -ne 0 ]; then
            error_msg="pnpm list -g command failed with exit code $exit_code"
        fi

        # Base64 encode stdout and stderr directly from files to avoid bash variable expansion
        # This prevents xrealloc errors when dealing with large output (integer underflow issue)
        local encoded_stdout=$(safe_read_file "$stdout_file" 2>/dev/null | base64 | tr -d '\n' || echo "")
        local encoded_stderr=$(safe_read_file "$stderr_file" 2>/dev/null | base64 | tr -d '\n' || echo "")

        # Clean up temp files
        rm -f "$stdout_file" "$stderr_file"

        local end_time=$(get_timestamp_ms)
        local duration=$((end_time - start_time))

        # Escape strings for JSON
        local escaped_global_dir=$(json_string_escape "$pnpm_global_dir")
        local escaped_error=$(json_string_escape "$error_msg")

        [ "$first" = false ] && printf '%s' "," >> "$global_projects_file"
        first=false
        count=$((count + 1))

        printf '%s' "{\"project_path\":\"${escaped_global_dir}\",\"package_manager\":\"pnpm\",\"package_manager_version\":\"${pnpm_version}\",\"working_directory\":\"${escaped_global_dir}\",\"raw_stdout_base64\":\"${encoded_stdout}\",\"raw_stderr_base64\":\"${encoded_stderr}\",\"error\":\"${escaped_error}\",\"exit_code\":${exit_code},\"scan_duration_ms\":${duration}}" >> "$global_projects_file"
    fi

    # Note: Bun doesn't have a traditional global install mechanism like npm/yarn/pnpm
    # Bun installs global packages to a single location and they're just executables
    # We can add support for this later if needed

    if [ "$count" -eq 0 ]; then
        print_progress "  No globally installed packages found"
    else
        print_progress "  Found ${count} global package location(s)"
    fi

    echo "$global_projects_file"
    echo "$count"
}

# Detect which package manager a project uses
detect_project_package_manager() {
    local project_dir=$1

    # Check if path is inside bun's internal directories
    # These are bun's cache and should be tagged as "bun" even without lockfiles
    if [[ "$project_dir" == *"/.bun/install/"* ]]; then
        echo "bun"
        return
    fi

    # Check for lock files (in order of preference - most specific first)
    # Check bun.lock or bun.lockb first, as bun may create package-lock.json for compatibility
    if [ -f "$project_dir/bun.lock" ] || [ -f "$project_dir/bun.lockb" ]; then
        echo "bun"
    elif [ -f "$project_dir/pnpm-lock.yaml" ]; then
        echo "pnpm"
    elif [ -f "$project_dir/yarn.lock" ]; then
        # Determine if it's Yarn Classic or Berry
        if [ -f "$project_dir/.yarnrc.yml" ] || [ -d "$project_dir/.yarn/releases" ]; then
            echo "yarn-berry"
        else
            echo "yarn"
        fi
    elif [ -f "$project_dir/package-lock.json" ]; then
        echo "npm"
    else
        # Default to npm if no lock file found
        echo "npm"
    fi
}

# Get package manager version
get_package_manager_version() {
    local package_manager=$1
    local logged_in_user=$2

    case "$package_manager" in
        npm)
            run_as_logged_in_user "$logged_in_user" "npm --version 2>/dev/null" || echo "unknown"
            ;;
        yarn|yarn-berry)
            run_as_logged_in_user "$logged_in_user" "yarn --version 2>/dev/null" || echo "unknown"
            ;;
        pnpm)
            run_as_logged_in_user "$logged_in_user" "pnpm --version 2>/dev/null" || echo "unknown"
            ;;
        bun)
            run_as_logged_in_user "$logged_in_user" "bun --version 2>/dev/null" || echo "unknown"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# List packages for a project - sends RAW output to backend for parsing
# This function is designed to be resilient - errors from one project should not stop the entire scan
list_project_packages_raw() {
    local project_dir=$1
    local package_manager=$2
    local logged_in_user=$3
    local start_time=$(get_timestamp_ms)

    local raw_stdout=""
    local raw_stderr=""
    local error_msg=""
    local exit_code=0

    # Change to project directory
    if ! cd "$project_dir" 2>/dev/null; then
        error_msg="Failed to change to directory"
        echo "{\"project_path\":\"$(json_string_escape "$project_dir")\",\"package_manager\":\"$package_manager\",\"working_directory\":\"$(pwd)\",\"raw_stdout_base64\":\"\",\"raw_stderr_base64\":\"\",\"error\":\"$(json_string_escape "$error_msg")\",\"exit_code\":1,\"scan_duration_ms\":0}"
        return 0  # Return success to continue processing other projects
    fi

    local current_dir=$(pwd)

    # Check if node_modules exists for package managers that require it
    # Note: yarn-berry can use PnP (no node_modules), so we don't check for it
    case "$package_manager" in
        npm|yarn|pnpm|bun)
            if [ ! -d "node_modules" ]; then
                # Return empty string to signal skip
                echo ""
                return
            fi
            ;;
        yarn-berry)
            # yarn-berry can use PnP or node_modules, so don't check
            ;;
    esac

    # Create temp files for capturing stdout and stderr separately
    local stdout_file=$(mktemp)
    local stderr_file=$(mktemp)

    # Run the appropriate command based on package manager
    # Capture STDOUT and STDERR separately
    # Commands run in the context of the logged-in user when script is run as root
    # Note: We don't check 'command -v' in root context because package managers
    # are in the user's PATH, not root's PATH. We let the command fail gracefully.
    # Use limited depth to prevent memory allocation errors from large dependency trees
    # Wrap in subshell to prevent script exit on command failure
    (
        set +e  # Disable exit on error for this subshell
        case "$package_manager" in
            npm)
                # Limit depth to 3 levels to prevent excessive memory usage
                run_as_logged_in_user "$logged_in_user" "command -v npm >/dev/null 2>&1 && npm ls --json --depth=3 2>&1 || echo 'npm command failed'" > "$stdout_file" 2> "$stderr_file"
                echo $? > "${stdout_file}.exitcode"
                ;;
            yarn)
                run_as_logged_in_user "$logged_in_user" "command -v yarn >/dev/null 2>&1 && yarn list --json 2>&1 || echo 'yarn command failed'" > "$stdout_file" 2> "$stderr_file"
                echo $? > "${stdout_file}.exitcode"
                ;;
            yarn-berry)
                run_as_logged_in_user "$logged_in_user" "command -v yarn >/dev/null 2>&1 && yarn info --all --json 2>&1 || echo 'yarn command failed'" > "$stdout_file" 2> "$stderr_file"
                echo $? > "${stdout_file}.exitcode"
                ;;
            pnpm)
                # Limit depth to 3 levels to prevent excessive memory usage
                run_as_logged_in_user "$logged_in_user" "command -v pnpm >/dev/null 2>&1 && pnpm ls --json --depth=3 2>&1 || echo 'pnpm command failed'" > "$stdout_file" 2> "$stderr_file"
                echo $? > "${stdout_file}.exitcode"
                ;;
            bun)
                run_as_logged_in_user "$logged_in_user" "command -v bun >/dev/null 2>&1 && bun pm ls --all 2>&1 || echo 'bun command failed'" > "$stdout_file" 2> "$stderr_file"
                echo $? > "${stdout_file}.exitcode"
                ;;
            *)
                echo "Unknown package manager: $package_manager" > "$stderr_file"
                echo 1 > "${stdout_file}.exitcode"
                ;;
        esac
    ) || {
        # If the subshell itself fails catastrophically (e.g., xrealloc error), log it
        echo "Command execution failed catastrophically (possible memory error)" > "$stderr_file"
        echo 255 > "${stdout_file}.exitcode"
    }

    # Read the exit code from file
    if [ -f "${stdout_file}.exitcode" ]; then
        exit_code=$(cat "${stdout_file}.exitcode" 2>/dev/null || echo "1")
        rm -f "${stdout_file}.exitcode"
    else
        exit_code=1
        error_msg="Failed to capture exit code"
    fi

    # Interpret exit codes
    if [ $exit_code -eq 127 ]; then
        error_msg="Package manager command not found"
    elif [ $exit_code -eq 255 ]; then
        error_msg="Command execution failed catastrophically (possible memory error)"
    elif [ $exit_code -ne 0 ]; then
        error_msg="${package_manager} command failed with exit code $exit_code"
    fi

    # Base64 encode stdout and stderr directly from files to avoid bash variable expansion
    # This prevents xrealloc errors when dealing with large output (integer underflow issue)
    local encoded_stdout=$(safe_read_file "$stdout_file" 2>/dev/null | base64 | tr -d '\n' || echo "")
    local encoded_stderr=$(safe_read_file "$stderr_file" 2>/dev/null | base64 | tr -d '\n' || echo "")

    # Clean up temp files
    rm -f "$stdout_file" "$stderr_file"

    local end_time=$(get_timestamp_ms)
    local duration=$((end_time - start_time))

    # Escape strings for JSON - backend will parse the raw output
    local escaped_project_path=$(json_string_escape "$project_dir")
    local escaped_working_dir=$(json_string_escape "$current_dir")
    local escaped_error=$(json_string_escape "$error_msg")

    echo "{\"project_path\":\"${escaped_project_path}\",\"package_manager\":\"${package_manager}\",\"working_directory\":\"${escaped_working_dir}\",\"raw_stdout_base64\":\"${encoded_stdout}\",\"raw_stderr_base64\":\"${encoded_stderr}\",\"error\":\"${escaped_error}\",\"exit_code\":${exit_code},\"scan_duration_ms\":${duration}}"
}

# Check if a path is inside node_modules of any project we've seen
is_inside_node_modules() {
    local check_path=$1
    shift
    local processed_projects=("$@")

    for project in "${processed_projects[@]}"; do
        # Check if this path is inside the node_modules of a processed project
        local node_modules_path="${project}/node_modules"
        if [[ "$check_path" == "$node_modules_path"* ]]; then
            return 0  # true - is inside node_modules
        fi
    done

    return 1  # false - not inside node_modules
}

# Check if a directory is a global package directory
# These directories are handled separately by scan_global_packages()
# and should be skipped during project scanning to avoid overwriting is_global flag
is_global_package_directory() {
    local check_path=$1
    local logged_in_user=$2

    # Check yarn global directory
    if command -v yarn &> /dev/null; then
        local yarn_global_dir=$(run_as_logged_in_user "$logged_in_user" "yarn global dir 2>/dev/null" || echo "")
        if [ -n "$yarn_global_dir" ] && [[ "$check_path" == "$yarn_global_dir"* ]]; then
            return 0  # true - is yarn global directory
        fi
    fi

    # Check npm global prefix
    if command -v npm &> /dev/null; then
        local npm_prefix=$(run_as_logged_in_user "$logged_in_user" "npm config get prefix 2>/dev/null" || echo "")
        if [ -n "$npm_prefix" ] && [[ "$check_path" == "$npm_prefix"* ]]; then
            return 0  # true - is npm global directory
        fi
    fi

    # Check pnpm global directory
    if command -v pnpm &> /dev/null; then
        local pnpm_global_dir=$(run_as_logged_in_user "$logged_in_user" "pnpm root -g 2>/dev/null" || echo "")
        if [ -n "$pnpm_global_dir" ]; then
            # pnpm root -g returns the node_modules path, we want the parent
            pnpm_global_dir=$(dirname "$pnpm_global_dir" 2>/dev/null || echo "$pnpm_global_dir")
            if [[ "$check_path" == "$pnpm_global_dir"* ]]; then
                return 0  # true - is pnpm global directory
            fi
        fi
    fi

    return 1  # false - not a global package directory
}

# Scan for Node.js projects - this is the main function that can be disabled
scan_node_projects() {
    local search_dir="$1"
    local logged_in_user="$2"
    local start_time=$(get_timestamp_ms)

    print_progress "Searching for Node.js projects..."

    # Write results to temp file to avoid bash variable accumulation limit (~1GB in bash 3.2)
    local projects_file=$(mktemp)
    local first=true
    local project_count=0
    local cumulative_size=0

    # Track project directories we've already processed
    # This is an array of exact paths, not for prefix matching
    declare -a processed_project_paths
    local processed_count=0

    if [ -n "$search_dir" ]; then
        print_progress "  Searching in: ${search_dir}"

        # Find package.json files, excluding node_modules
        # The grep -v handles most node_modules filtering
        while IFS= read -r package_json_file; do
            local project_dir=$(dirname "$package_json_file")

            # Additional check: Skip if this path is inside node_modules of a project we've already processed
            # This handles nested node_modules cases that grep -v might miss
            # Only check if we have processed at least one project (avoids empty array issues with set -u)
            if [ $processed_count -gt 0 ] && is_inside_node_modules "$project_dir" "${processed_project_paths[@]}"; then
                continue
            fi

            # Skip if we've already processed this exact directory
            # Use a simple approach: check if project_dir is in our array
            local already_processed=false
            if [ $processed_count -gt 0 ]; then
                for processed_path in "${processed_project_paths[@]}"; do
                    if [ "$project_dir" = "$processed_path" ]; then
                        already_processed=true
                        break
                    fi
                done
            fi

            if [ "$already_processed" = true ]; then
                continue
            fi

            # Skip if package.json doesn't exist (shouldn't happen but be safe)
            if [ ! -f "$package_json_file" ]; then
                continue
            fi

            # Skip global package directories - they're handled separately by scan_global_packages()
            # to avoid overwriting is_global=true with is_global=false
            if is_global_package_directory "$project_dir" "$logged_in_user"; then
                print_progress "    Skipping global package directory: ${project_dir}"
                continue
            fi

            print_progress "    Found project: ${project_dir}"

            # Add to processed paths BEFORE processing
            # This prevents concurrent issues and marks node_modules as off-limits
            processed_project_paths+=("$project_dir")
            processed_count=$((processed_count + 1))

            project_count=$((project_count + 1))

            # Detect package manager
            local package_manager=$(detect_project_package_manager "$project_dir")
            print_progress "      Package manager: ${package_manager}"

            # Get package manager version
            local pm_version=$(get_package_manager_version "$package_manager" "$logged_in_user")

            # Get raw package listing - NO PARSING in bash
            # Wrap in error handling to prevent script exit if this project fails
            local project_result=""
            if ! project_result=$(list_project_packages_raw "$project_dir" "$package_manager" "$logged_in_user" 2>&1); then
                print_error "      Failed to scan project (continuing with next project)"
                # Don't count this as a processed project
                project_count=$((project_count - 1))
                continue
            fi

            # Skip if no node_modules (empty result means packages not installed)
            if [ -z "$project_result" ]; then
                print_progress "      Skipping (no node_modules directory)"
                # Don't count this as a processed project
                project_count=$((project_count - 1))
                continue
            fi

            # Add package manager version to the result
            # Simple string manipulation to inject the version
            project_result="${project_result%\}},\"package_manager_version\":\"${pm_version}\"}"

            # Check cumulative size limit before adding
            local result_size=${#project_result}
            if [ $((cumulative_size + result_size)) -gt $MAX_NODE_PROJECTS_SIZE_BYTES ]; then
                print_progress "    Reached data size limit (${cumulative_size} bytes collected, limit: ${MAX_NODE_PROJECTS_SIZE_BYTES} bytes)"
                print_progress "    Skipping remaining projects (prioritized by most recently modified)"
                project_count=$((project_count - 1))
                break
            fi
            cumulative_size=$((cumulative_size + result_size))

            # Add to projects file
            [ "$first" = false ] && printf '%s' "," >> "$projects_file"
            first=false
            printf '%s' "${project_result}" >> "$projects_file"

            # Limit number of projects to avoid excessive data
            if [ $project_count -ge 1000 ]; then
                print_progress "    Reached maximum of 1000 projects, stopping search"
                break
            fi

        done < <(find "$search_dir" -name "package.json" -type f 2>/dev/null \
            | grep -v "/node_modules/" \
            | while IFS= read -r f; do stat -f "%m %N" "$f" 2>/dev/null; done \
            | sort -rn \
            | cut -d' ' -f2- 2>/dev/null)
    fi

    local end_time=$(get_timestamp_ms)
    local total_duration=$((end_time - start_time))

    print_progress "Found ${project_count} Node.js projects"
    print_progress "  Scan duration: ${total_duration}ms"

    # Return results (file path instead of content to avoid bash variable limit)
    echo "$projects_file"
    echo "$project_count"
    echo "$total_duration"
}

#==============================================================================
# SECTION 16: OUTPUT FORMATTERS
#==============================================================================

# Extract packages from a scan results temp file for community mode display.
# Reads flat JSON entries from the file, decodes raw_stdout_base64, and extracts
# package names and versions grouped by folder path.
# Arguments: $1 = scan temp file path
# Output: lines in format "FOLDER_START:<path>:<pkg_manager>" then "pkg@ver" lines then "FOLDER_END"
extract_packages_from_scan_file() {
    local scan_file="$1"
    if [ -z "$scan_file" ] || [ ! -f "$scan_file" ]; then
        return
    fi
    local content
    content=$(cat "$scan_file" 2>/dev/null)
    if [ -z "$content" ]; then
        return
    fi

    # Entries are flat JSON (base64 means no nested braces) separated by commas
    echo "[$content]" | grep -o '{[^}]*}' | while IFS= read -r entry; do
        local project_path pkg_manager raw_b64
        project_path=$(echo "$entry" | sed 's/.*"project_path":"\([^"]*\)".*/\1/')
        pkg_manager=$(echo "$entry" | sed 's/.*"package_manager":"\([^"]*\)".*/\1/')
        raw_b64=$(echo "$entry" | sed 's/.*"raw_stdout_base64":"\([^"]*\)".*/\1/')

        if [ -z "$raw_b64" ] || [ "$raw_b64" = "$entry" ]; then
            continue
        fi

        local decoded
        decoded=$(echo "$raw_b64" | base64 -d 2>/dev/null || echo "")
        if [ -z "$decoded" ]; then
            continue
        fi

        # Strip whitespace for single-line pattern matching
        local stripped
        stripped=$(echo "$decoded" | tr -d '\n\r' | sed 's/  */ /g')

        local packages=""

        # npm/pnpm JSON format: "pkg-name": { "version": "x.y.z"
        packages=$(echo "$stripped" | grep -oE '"[@a-zA-Z0-9/_.-]+": *\{ *"version": *"[^"]*"' 2>/dev/null | while IFS= read -r match; do
            local pkg ver
            pkg=$(echo "$match" | sed 's/" *: *{.*//' | sed 's/^"//')
            ver=$(echo "$match" | sed 's/.*"version": *"//' | sed 's/"$//')
            if [ "$pkg" != "dependencies" ] && [ "$pkg" != "devDependencies" ] && [ "$pkg" != "peerDependencies" ]; then
                echo "${pkg}@${ver}"
            fi
        done | sort -u)

        # yarn JSON format: "name":"pkg@ver" in trees
        if [ -z "$packages" ]; then
            packages=$(echo "$stripped" | grep -oE '"name": *"[^"]+@[^"]*"' 2>/dev/null | sed 's/"name": *"//;s/"$//' | sort -u)
        fi

        # bun text format: ├── pkg@ver or └── pkg@ver
        if [ -z "$packages" ]; then
            packages=$(echo "$decoded" | grep -oE '[├└]── [^ ]+@[^ ]+' 2>/dev/null | sed 's/[├└]── //' | sort -u)
        fi

        if [ -n "$packages" ]; then
            echo "FOLDER_START:${project_path}:${pkg_manager}"
            echo "$packages"
            echo "FOLDER_END"
        fi
    done
}

format_pretty_output() {
    local scan_timestamp="$1"
    local hostname="$2"
    local serial_number="$3"
    local os_version="$4"
    local developer_identity="$5"
    local ide_installations="$6"
    local ai_tools="$7"
    local ide_extensions="$8"
    local ide_count="$9"
    local ai_tools_count="${10}"
    local ext_count="${11}"
    local mcp_configs="${12}"
    local node_package_managers="${13}"
    local node_projects_count="${14}"
    local node_global_packages_file="${15}"
    local node_projects_file="${16}"

    # Use colors for stdout only if stdout is a terminal (or color=always)
    local use_stdout_colors=false
    if [ "$COLOR_MODE" = "always" ]; then
        use_stdout_colors=true
    elif [ "$COLOR_MODE" = "auto" ] && [ -t 1 ]; then
        use_stdout_colors=true
    fi

    local P="" G="" B="" D="" R="" RD="" Y=""
    if [ "$use_stdout_colors" = true ]; then
        P='\033[0;35m'   # Purple
        G='\033[0;32m'   # Green
        B='\033[1m'      # Bold
        D='\033[2m'      # Dim
        R='\033[0m'      # Reset
        RD='\033[0;31m'  # Red
        Y='\033[0;33m'   # Yellow
    fi

    local scan_time_formatted=$(date -r "$scan_timestamp" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$scan_timestamp")

    local mcp_count=$(count_json_array_items "$mcp_configs")

    # Helper: truncate string to max length with "..." suffix
    truncate_str() {
        local str="$1"
        local max="$2"
        if [ ${#str} -gt $max ]; then
            echo "${str:0:$((max - 3))}..."
        else
            echo "$str"
        fi
    }

    # Banner
    local box_width=58
    local title="StepSecurity Dev Machine Guard v${AGENT_VERSION}"
    local url="https://github.com/step-security/dev-machine-guard"
    local title_pad=$((box_width - 2 - ${#title}))
    local url_pad=$((box_width - 2 - ${#url}))
    printf "\n"
    printf "  ${P}┌$(printf '%0.s─' $(seq 1 $box_width))┐${R}\n"
    printf "  ${P}│${R}  ${B}%s${R}%*s${P}│${R}\n" "$title" "$title_pad" ""
    printf "  ${P}│${R}  ${D}%s${R}%*s${P}│${R}\n" "$url" "$url_pad" ""
    printf "  ${P}└$(printf '%0.s─' $(seq 1 $box_width))┘${R}\n"
    printf "  ${D}Scanned at ${scan_time_formatted}${R}\n"
    printf "\n"

    # DEVICE section
    printf "  ${P}${B}DEVICE${R}\n"
    printf "    %-16s %s\n" "Hostname" "$hostname"
    printf "    %-16s %s\n" "Serial" "$serial_number"
    printf "    %-16s %s\n" "macOS" "$os_version"
    printf "    %-16s %s\n" "User" "$developer_identity"
    printf "\n"

    # SUMMARY section
    printf "  ${P}${B}SUMMARY${R}\n"
    printf "    %-24s ${G}%s${R}\n" "AI Agents and Tools" "$ai_tools_count"
    printf "    %-24s ${G}%s${R}\n" "IDEs & Desktop Apps" "$ide_count"
    printf "    %-24s ${G}%s${R}\n" "IDE Extensions" "$ext_count"
    printf "    %-24s ${G}%s${R}\n" "MCP Servers" "$mcp_count"
    if [ "$node_package_managers" != "[]" ]; then
        printf "    %-24s ${G}%s${R}\n" "Node.js Projects" "$node_projects_count"
    fi
    printf "\n"

    # AI AGENTS AND TOOLS section
    printf "  ${P}${B}AI AGENTS AND TOOLS${R}%*s${G}%s found${R}\n" $((35 - 19)) "" "$ai_tools_count"
    if [ "$ai_tools_count" -gt 0 ]; then
        echo "$ai_tools" | grep -o '{[^}]*}' | while IFS= read -r entry; do
            local name=$(echo "$entry" | sed 's/.*"name":"\([^"]*\)".*/\1/')
            local version=$(echo "$entry" | sed 's/.*"version":"\([^"]*\)".*/\1/')
            local vendor=$(echo "$entry" | sed 's/.*"vendor":"\([^"]*\)".*/\1/')
            local type=$(echo "$entry" | sed 's/.*"type":"\([^"]*\)".*/\1/')
            local type_label=""
            case "$type" in
                cli_tool) type_label="cli" ;;
                general_agent) type_label="agent" ;;
                framework) type_label="framework" ;;
                *) type_label="$type" ;;
            esac
            name=$(truncate_str "$name" 24)
            version=$(truncate_str "$version" 20)
            printf "    %-24s ${D}v%-20s %-12s %s${R}\n" "$name" "$version" "[$type_label]" "$vendor"
        done
    else
        printf "    ${D}None detected${R}\n"
    fi
    printf "\n"

    # IDE & AI DESKTOP APPS section
    printf "  ${P}${B}IDE & AI DESKTOP APPS${R}%*s${G}%s found${R}\n" $((35 - 21)) "" "$ide_count"
    if [ "$ide_count" -gt 0 ]; then
        echo "$ide_installations" | grep -o '{[^}]*}' | while IFS= read -r entry; do
            local ide_type=$(echo "$entry" | sed 's/.*"ide_type":"\([^"]*\)".*/\1/')
            local version=$(echo "$entry" | sed 's/.*"version":"\([^"]*\)".*/\1/')
            local vendor=$(echo "$entry" | sed 's/.*"vendor":"\([^"]*\)".*/\1/')
            local display_name="$ide_type"
            case "$ide_type" in
                vscode) display_name="Visual Studio Code" ;;
                cursor) display_name="Cursor" ;;
                windsurf) display_name="Windsurf" ;;
                antigravity) display_name="Antigravity" ;;
                zed) display_name="Zed" ;;
                claude_desktop) display_name="Claude" ;;
                microsoft_copilot_desktop) display_name="Microsoft Copilot" ;;
            esac
            display_name=$(truncate_str "$display_name" 24)
            version=$(truncate_str "$version" 20)
            printf "    %-24s ${D}v%-20s %s${R}\n" "$display_name" "$version" "$vendor"
        done
    else
        printf "    ${D}None detected${R}\n"
    fi
    printf "\n"

    # MCP SERVERS section
    printf "  ${P}${B}MCP SERVERS${R}%*s${G}%s found${R}\n" $((35 - 11)) "" "$mcp_count"
    if [ "$mcp_count" -gt 0 ]; then
        echo "$mcp_configs" | grep -o '{[^}]*}' | while IFS= read -r entry; do
            local config_source=$(echo "$entry" | sed 's/.*"config_source":"\([^"]*\)".*/\1/')
            local vendor=$(echo "$entry" | sed 's/.*"vendor":"\([^"]*\)".*/\1/')
            printf "    %-24s ${D}%s${R}\n" "$config_source" "$vendor"
        done
    else
        printf "    ${D}None detected${R}\n"
    fi
    printf "\n"

    # IDE EXTENSIONS section
    printf "  ${P}${B}IDE EXTENSIONS${R}%*s${G}%s found${R}\n" $((35 - 14)) "" "$ext_count"
    if [ "$ext_count" -gt 0 ]; then
        local ide_types=$(echo "$ide_extensions" | grep -o '"ide_type":"[^"]*"' | sed 's/"ide_type":"//;s/"//' | sort -u)

        for ide_type in $ide_types; do
            local ide_ext_count=$(echo "$ide_extensions" | grep -o "\"ide_type\":\"${ide_type}\"" | wc -l | tr -d ' ')

            local ide_display="$ide_type"
            case "$ide_type" in
                vscode) ide_display="VSCode" ;;
                openvsx) ide_display="OpenVSX" ;;
                windsurf) ide_display="Windsurf" ;;
            esac

            printf "    ${P}${B}${ide_display}${R}%*s${G}%s found${R}\n" $((33 - ${#ide_display})) "" "$ide_ext_count"

            echo "$ide_extensions" | grep -o '{[^}]*}' | grep "\"ide_type\":\"${ide_type}\"" | while IFS= read -r entry; do
                local ext_id=$(echo "$entry" | sed 's/.*"id":"\([^"]*\)".*/\1/')
                local ext_version=$(echo "$entry" | sed 's/.*"version":"\([^"]*\)".*/\1/')
                local ext_publisher=$(echo "$entry" | sed 's/.*"publisher":"\([^"]*\)".*/\1/')
                ext_id=$(truncate_str "$ext_id" 42)
                ext_version=$(truncate_str "$ext_version" 14)
                printf "      %-42s ${D}v%-14s %s${R}\n" "$ext_id" "$ext_version" "$ext_publisher"
            done
        done
    else
        printf "    ${D}None detected${R}\n"
    fi
    printf "\n"

    # NODE.JS PACKAGES section (only shown if npm scan was enabled)
    if [ "$node_package_managers" != "[]" ]; then
        local pm_count=$(count_json_array_items "$node_package_managers")
        printf "  ${P}${B}NODE.JS PACKAGE MANAGERS${R}%*s${G}%s found${R}\n" $((35 - 23)) "" "$pm_count"
        echo "$node_package_managers" | grep -o '{[^}]*}' | while IFS= read -r entry; do
            local pm_name=$(echo "$entry" | sed 's/.*"name":"\([^"]*\)".*/\1/')
            local pm_version=$(echo "$entry" | sed 's/.*"version":"\([^"]*\)".*/\1/')
            printf "    %-24s ${D}v%s${R}\n" "$pm_name" "$pm_version"
        done
        printf "\n"
        printf "  ${P}${B}NODE.JS PROJECTS${R}%*s${G}%s found${R}\n" $((35 - 16)) "" "$node_projects_count"
        printf "\n"

        # List all npm packages grouped by folder
        printf "  ${P}${B}NODE.JS PACKAGES${R}\n"
        local all_pkg_output=""
        for scan_file in "$node_global_packages_file" "$node_projects_file"; do
            local pkg_output
            pkg_output=$(extract_packages_from_scan_file "$scan_file")
            if [ -n "$pkg_output" ]; then
                [ -n "$all_pkg_output" ] && all_pkg_output="${all_pkg_output}"$'\n'"${pkg_output}" || all_pkg_output="$pkg_output"
            fi
        done

        if [ -n "$all_pkg_output" ]; then
            local current_folder="" current_pm=""
            while IFS= read -r line; do
                if [[ "$line" == FOLDER_START:* ]]; then
                    local rest="${line#FOLDER_START:}"
                    current_folder="${rest%:*}"
                    current_pm="${rest##*:}"
                    printf "\n    ${P}${B}%s${R} ${D}(%s)${R}\n" "$current_folder" "$current_pm"
                elif [ "$line" = "FOLDER_END" ]; then
                    :
                else
                    printf "      %s\n" "$line"
                fi
            done <<< "$all_pkg_output"
        else
            printf "    ${D}No packages found${R}\n"
        fi
        printf "\n"
    fi
}

#==============================================================================
# JSON OUTPUT FORMATTER
#==============================================================================

format_json_output() {
    local scan_timestamp="$1"
    local hostname="$2"
    local serial_number="$3"
    local os_version="$4"
    local developer_identity="$5"
    local ide_installations="$6"
    local ai_tools="$7"
    local ide_extensions="$8"
    local ide_count="$9"
    local ai_tools_count="${10}"
    local ext_count="${11}"
    local mcp_configs="${12}"
    local node_package_managers="${13}"
    local node_projects_count="${14}"
    local node_global_packages_file="${15}"
    local node_projects_file="${16}"

    local scan_iso=$(date -r "$scan_timestamp" -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")

    # Escape strings for JSON
    local escaped_hostname=$(json_string_escape "$hostname")
    local escaped_serial=$(json_string_escape "$serial_number")
    local escaped_os=$(json_string_escape "$os_version")
    local escaped_identity=$(json_string_escape "$developer_identity")

    local mcp_count=$(count_json_array_items "$mcp_configs")

    # Build node_packages JSON array from scan files
    local node_packages_json="[]"
    local all_pkg_output=""
    for scan_file in "$node_global_packages_file" "$node_projects_file"; do
        local pkg_out
        pkg_out=$(extract_packages_from_scan_file "$scan_file")
        if [ -n "$pkg_out" ]; then
            [ -n "$all_pkg_output" ] && all_pkg_output="${all_pkg_output}"$'\n'"${pkg_out}" || all_pkg_output="$pkg_out"
        fi
    done

    if [ -n "$all_pkg_output" ]; then
        local first_folder=true
        local folder_json=""
        local current_folder="" current_pm="" pkg_list=""

        node_packages_json="["
        while IFS= read -r line; do
            if [[ "$line" == FOLDER_START:* ]]; then
                # Emit previous folder if any
                if [ -n "$current_folder" ] && [ -n "$pkg_list" ]; then
                    [ "$first_folder" = false ] && node_packages_json="${node_packages_json},"
                    first_folder=false
                    node_packages_json="${node_packages_json}{\"folder\":\"$(json_string_escape "$current_folder")\",\"package_manager\":\"${current_pm}\",\"packages\":[${pkg_list}]}"
                fi
                local rest="${line#FOLDER_START:}"
                current_folder="${rest%:*}"
                current_pm="${rest##*:}"
                pkg_list=""
            elif [ "$line" = "FOLDER_END" ]; then
                :
            elif [ -n "$line" ]; then
                # Split on last @ to handle scoped packages like @scope/pkg@1.0.0
                local pkg_ver="${line##*@}"
                local pkg_name="${line%@*}"
                [ -n "$pkg_list" ] && pkg_list="${pkg_list},"
                pkg_list="${pkg_list}{\"name\":\"$(json_string_escape "$pkg_name")\",\"version\":\"$(json_string_escape "$pkg_ver")\"}"
            fi
        done <<< "$all_pkg_output"

        # Emit last folder
        if [ -n "$current_folder" ] && [ -n "$pkg_list" ]; then
            [ "$first_folder" = false ] && node_packages_json="${node_packages_json},"
            node_packages_json="${node_packages_json}{\"folder\":\"$(json_string_escape "$current_folder")\",\"package_manager\":\"${current_pm}\",\"packages\":[${pkg_list}]}"
        fi
        node_packages_json="${node_packages_json}]"
    fi

    cat <<EOF
{
  "agent_version": "${AGENT_VERSION}",
  "agent_url": "https://github.com/step-security/dev-machine-guard",
  "scan_timestamp": ${scan_timestamp},
  "scan_timestamp_iso": "${scan_iso}",
  "device": {
    "hostname": "${escaped_hostname}",
    "serial_number": "${escaped_serial}",
    "os_version": "${escaped_os}",
    "platform": "darwin",
    "user_identity": "${escaped_identity}"
  },
  "ai_agents_and_tools": ${ai_tools},
  "ide_installations": ${ide_installations},
  "ide_extensions": ${ide_extensions},
  "mcp_configs": ${mcp_configs},
  "node_package_managers": ${node_package_managers},
  "node_packages": ${node_packages_json},
  "summary": {
    "ai_agents_and_tools_count": ${ai_tools_count},
    "ide_installations_count": ${ide_count},
    "ide_extensions_count": ${ext_count},
    "mcp_configs_count": ${mcp_count},
    "node_projects_count": ${node_projects_count}
  }
}
EOF
}

#==============================================================================
# HTML REPORT GENERATOR
#==============================================================================

generate_html_report() {
    local output_file="$1"
    local scan_timestamp="$2"
    local hostname="$3"
    local serial_number="$4"
    local os_version="$5"
    local developer_identity="$6"
    local ide_installations="$7"
    local ai_tools="$8"
    local ide_extensions="$9"
    local ide_count="${10}"
    local ai_tools_count="${11}"
    local ext_count="${12}"
    local mcp_configs="${13}"
    local node_package_managers="${14}"
    local node_projects_count="${15}"
    local node_global_packages_file="${16}"
    local node_projects_file="${17}"

    local scan_time_formatted=$(date -r "$scan_timestamp" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$scan_timestamp")
    local mcp_count=$(count_json_array_items "$mcp_configs")

    generate_table_rows_ide() {
        local json="$1"
        if [ "$json" = "[]" ]; then
            echo "<tr><td colspan=\"4\" style=\"text-align:center;color:#8a94a6;\">None detected</td></tr>"
            return
        fi
        echo "$json" | grep -o '{[^}]*}' | while IFS= read -r entry; do
            local ide_type=$(echo "$entry" | sed 's/.*"ide_type":"\([^"]*\)".*/\1/')
            local version=$(echo "$entry" | sed 's/.*"version":"\([^"]*\)".*/\1/')
            local vendor=$(echo "$entry" | sed 's/.*"vendor":"\([^"]*\)".*/\1/')
            local install_path=$(echo "$entry" | sed 's/.*"install_path":"\([^"]*\)".*/\1/')
            local display_name="$ide_type"
            case "$ide_type" in
                vscode) display_name="Visual Studio Code" ;;
                cursor) display_name="Cursor" ;;
                windsurf) display_name="Windsurf" ;;
                antigravity) display_name="Antigravity" ;;
                zed) display_name="Zed" ;;
                claude_desktop) display_name="Claude" ;;
                microsoft_copilot_desktop) display_name="Microsoft Copilot" ;;
            esac
            echo "<tr><td>${display_name}</td><td>${version}</td><td>${vendor}</td><td style=\"color:#8a94a6;font-size:0.85em;\">${install_path}</td></tr>"
        done
    }

    generate_table_rows_ai_tools() {
        local json="$1"
        if [ "$json" = "[]" ]; then
            echo "<tr><td colspan=\"4\" style=\"text-align:center;color:#8a94a6;\">None detected</td></tr>"
            return
        fi
        echo "$json" | grep -o '{[^}]*}' | while IFS= read -r entry; do
            local name=$(echo "$entry" | sed 's/.*"name":"\([^"]*\)".*/\1/')
            local version=$(echo "$entry" | sed 's/.*"version":"\([^"]*\)".*/\1/')
            local vendor=$(echo "$entry" | sed 's/.*"vendor":"\([^"]*\)".*/\1/')
            local type=$(echo "$entry" | sed 's/.*"type":"\([^"]*\)".*/\1/')
            local type_label=""
            case "$type" in
                cli_tool) type_label="CLI Tool" ;;
                general_agent) type_label="Agent" ;;
                framework) type_label="Framework" ;;
                *) type_label="$type" ;;
            esac
            echo "<tr><td>${name}</td><td>${version}</td><td><span style=\"background:#f0ebff;color:#7037f5;padding:2px 8px;border-radius:10px;font-size:0.8em;\">${type_label}</span></td><td>${vendor}</td></tr>"
        done
    }

    generate_extension_rows() {
        local json="$1"
        if [ "$json" = "[]" ]; then
            echo "<tr><td colspan=\"4\" style=\"text-align:center;color:#8a94a6;\">None detected</td></tr>"
            return
        fi
        echo "$json" | grep -o '{[^}]*}' | while IFS= read -r entry; do
            local ext_id=$(echo "$entry" | sed 's/.*"id":"\([^"]*\)".*/\1/')
            local ext_version=$(echo "$entry" | sed 's/.*"version":"\([^"]*\)".*/\1/')
            local ext_publisher=$(echo "$entry" | sed 's/.*"publisher":"\([^"]*\)".*/\1/')
            local ext_ide_type=$(echo "$entry" | sed 's/.*"ide_type":"\([^"]*\)".*/\1/')
            local ide_display="$ext_ide_type"
            case "$ext_ide_type" in
                vscode) ide_display="VSCode" ;;
                openvsx) ide_display="OpenVSX" ;;
                windsurf) ide_display="Windsurf" ;;
            esac
            echo "<tr><td>${ext_id}</td><td>${ext_version}</td><td>${ext_publisher}</td><td>${ide_display}</td></tr>"
        done
    }

    generate_mcp_rows() {
        local json="$1"
        if [ "$json" = "[]" ]; then
            echo "<tr><td colspan=\"2\" style=\"text-align:center;color:#8a94a6;\">None detected</td></tr>"
            return
        fi
        echo "$json" | grep -o '{[^}]*}' | while IFS= read -r entry; do
            local config_source=$(echo "$entry" | sed 's/.*"config_source":"\([^"]*\)".*/\1/')
            local vendor=$(echo "$entry" | sed 's/.*"vendor":"\([^"]*\)".*/\1/')
            echo "<tr><td>${config_source}</td><td>${vendor}</td></tr>"
        done
    }

    # HTML-escape user-controlled values
    local h_hostname=$(html_escape "$hostname")
    local h_serial=$(html_escape "$serial_number")
    local h_os=$(html_escape "$os_version")
    local h_identity=$(html_escape "$developer_identity")

    # Generate the table row HTML
    local ide_rows=$(generate_table_rows_ide "$ide_installations")
    local ai_tools_rows=$(generate_table_rows_ai_tools "$ai_tools")
    local extension_rows=$(generate_extension_rows "$ide_extensions")
    local mcp_rows=$(generate_mcp_rows "$mcp_configs")

    # Generate node packages rows from scan files
    local node_pkg_rows=""
    local all_pkg_output=""
    for scan_file in "$node_global_packages_file" "$node_projects_file"; do
        local pkg_out
        pkg_out=$(extract_packages_from_scan_file "$scan_file")
        if [ -n "$pkg_out" ]; then
            [ -n "$all_pkg_output" ] && all_pkg_output="${all_pkg_output}"$'\n'"${pkg_out}" || all_pkg_output="$pkg_out"
        fi
    done

    if [ -n "$all_pkg_output" ]; then
        local current_folder="" current_pm=""
        while IFS= read -r line; do
            if [[ "$line" == FOLDER_START:* ]]; then
                local rest="${line#FOLDER_START:}"
                current_folder="${rest%:*}"
                current_pm="${rest##*:}"
            elif [ "$line" = "FOLDER_END" ]; then
                :
            elif [ -n "$line" ]; then
                # Split on last @ to handle scoped packages like @scope/pkg@1.0.0
                local pkg_ver="${line##*@}"
                local pkg_name="${line%@*}"
                node_pkg_rows="${node_pkg_rows}<tr><td>$(html_escape "$current_folder")</td><td>$(html_escape "$current_pm")</td><td>$(html_escape "$pkg_name")</td><td>$(html_escape "$pkg_ver")</td></tr>"
            fi
        done <<< "$all_pkg_output"
    fi

    if [ -z "$node_pkg_rows" ]; then
        node_pkg_rows="<tr><td colspan=\"4\" style=\"text-align:center;color:#8a94a6;\">No packages found (use --enable-npm-scan)</td></tr>"
    fi

    # Write the HTML file
    cat > "$output_file" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>StepSecurity Dev Machine Guard Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #faf7fb; color: #193447; line-height: 1.6;
  }
  .header {
    background: linear-gradient(135deg, #7037f5, #9b59f5);
    color: #fff; padding: 32px 0; text-align: center;
  }
  .header h1 { font-size: 1.6em; font-weight: 600; margin-bottom: 4px; }
  .header p { opacity: 0.85; font-size: 0.95em; }
  .container { max-width: 960px; margin: 0 auto; padding: 24px 16px; }
  .summary-cards {
    display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap;
  }
  .card {
    flex: 1; min-width: 140px; background: #fff; border-radius: 10px;
    padding: 18px 16px; text-align: center;
    border: 1px solid #e8e0f0; box-shadow: 0 1px 3px rgba(112,55,245,0.06);
  }
  .card .number { font-size: 2em; font-weight: 700; color: #7037f5; }
  .card .label { font-size: 0.82em; color: #8a94a6; margin-top: 2px; }
  .device-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 8px 32px;
    background: #fff; border-radius: 10px; padding: 20px 24px;
    margin-bottom: 28px; border: 1px solid #e8e0f0;
  }
  .device-grid .field { display: flex; gap: 12px; padding: 6px 0; }
  .device-grid .field-label { color: #8a94a6; min-width: 90px; font-size: 0.9em; }
  .device-grid .field-value { font-weight: 500; }
  .section { margin-bottom: 28px; }
  .section h2 {
    font-size: 1.1em; color: #7037f5; margin-bottom: 12px;
    padding-bottom: 6px; border-bottom: 2px solid #f0ebff;
  }
  .section h2 .count {
    float: right; background: #f0ebff; color: #7037f5;
    padding: 2px 10px; border-radius: 10px; font-size: 0.85em;
  }
  table {
    width: 100%; border-collapse: collapse; background: #fff;
    border-radius: 10px; overflow: hidden; border: 1px solid #e8e0f0;
  }
  th {
    background: #f0ebff; color: #7037f5; font-weight: 600;
    text-align: left; padding: 10px 14px; font-size: 0.85em;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  td { padding: 9px 14px; border-top: 1px solid #f0ebff; font-size: 0.92em; }
  tr:hover td { background: #faf7fb; }
  .footer {
    text-align: center; padding: 24px; color: #8a94a6; font-size: 0.85em;
    border-top: 1px solid #e8e0f0; margin-top: 12px;
  }
  .footer a { color: #7037f5; text-decoration: none; }
  .footer a:hover { text-decoration: underline; }
  .scan-meta { text-align: center; color: #8a94a6; font-size: 0.85em; margin-bottom: 20px; }
  @media print {
    body { background: #fff; }
    .header { background: #7037f5; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .card { break-inside: avoid; }
  }
  @media (max-width: 600px) {
    .summary-cards { flex-direction: column; }
    .device-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="header">
  <h1>StepSecurity Dev Machine Guard Report</h1>
  <p>Developer Environment Security Scanner</p>
</div>
<div class="container">
HTMLEOF

    # Now write dynamic content
    cat >> "$output_file" <<EOF
<p class="scan-meta">Scanned at ${scan_time_formatted} &middot; Agent v${AGENT_VERSION}</p>

<div class="summary-cards">
  <div class="card"><div class="number">${ai_tools_count}</div><div class="label">AI Agents and Tools</div></div>
  <div class="card"><div class="number">${ide_count}</div><div class="label">IDEs & Desktop Apps</div></div>
  <div class="card"><div class="number">${ext_count}</div><div class="label">IDE Extensions</div></div>
  <div class="card"><div class="number">${mcp_count}</div><div class="label">MCP Servers</div></div>
  <div class="card"><div class="number">${node_projects_count}</div><div class="label">Node.js Projects</div></div>
EOF

    cat >> "$output_file" <<EOF
</div>

<div class="device-grid">
  <div class="field"><span class="field-label">Hostname</span><span class="field-value">${h_hostname}</span></div>
  <div class="field"><span class="field-label">Serial</span><span class="field-value">${h_serial}</span></div>
  <div class="field"><span class="field-label">macOS</span><span class="field-value">${h_os}</span></div>
  <div class="field"><span class="field-label">User</span><span class="field-value">${h_identity}</span></div>
</div>
EOF

    cat >> "$output_file" <<EOF

<div class="section">
  <h2>AI Agents and Tools <span class="count">${ai_tools_count}</span></h2>
  <table>
    <tr><th>Name</th><th>Version</th><th>Type</th><th>Vendor</th></tr>
    ${ai_tools_rows}
  </table>
</div>

<div class="section">
  <h2>IDE & AI Desktop Apps <span class="count">${ide_count}</span></h2>
  <table>
    <tr><th>Name</th><th>Version</th><th>Vendor</th><th>Path</th></tr>
    ${ide_rows}
  </table>
</div>

<div class="section">
  <h2>MCP Servers <span class="count">${mcp_count}</span></h2>
  <table>
    <tr><th>Source</th><th>Vendor</th></tr>
    ${mcp_rows}
  </table>
</div>

<div class="section">
  <h2>IDE Extensions <span class="count">${ext_count}</span></h2>
  <table>
    <tr><th>Extension ID</th><th>Version</th><th>Publisher</th><th>IDE</th></tr>
    ${extension_rows}
  </table>
</div>

<div class="section">
  <h2>Node.js Packages</h2>
  <table>
    <tr><th>Folder</th><th>Package Manager</th><th>Package</th><th>Version</th></tr>
    ${node_pkg_rows}
  </table>
</div>

</div>
<div class="footer">
  Generated by <a href="https://github.com/step-security/dev-machine-guard">StepSecurity Dev Machine Guard</a> v${AGENT_VERSION}
</div>
</body>
</html>
EOF

    print_progress "HTML report saved to ${output_file}"
}

#==============================================================================
# SECTION 17: TELEMETRY UPLOAD
#==============================================================================

upload_telemetry_to_s3() {
    local device_id=$1
    local payload_file=$2

    print_progress "Requesting upload URL from backend..."

    # Request upload URL
    local upload_url_response
    upload_url_response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "X-Agent-Version: ${AGENT_VERSION}" \
        -d "{\"device_id\":\"${device_id}\"}" \
        "${API_ENDPOINT}/v1/${CUSTOMER_ID}/developer-mdm-agent/telemetry/upload-url" 2>&1)

    if [ $? -ne 0 ]; then
        print_error "Failed to request upload URL"
        return 1
    fi

    # Extract upload_url and s3_key using simple string manipulation
    # This avoids dependency on jq
    local upload_url=$(echo "$upload_url_response" | grep -o '"upload_url":"[^"]*"' | cut -d'"' -f4)
    local s3_key=$(echo "$upload_url_response" | grep -o '"s3_key":"[^"]*"' | cut -d'"' -f4)

    if [ -z "$upload_url" ]; then
        print_error "Failed to parse upload URL from response"
        print_error "Response: ${upload_url_response}"
        return 1
    fi

    # IMPORTANT: unescape JSON \uXXXX sequences commonly used in URLs
    # Use sed instead of bash parameter expansion for macOS compatibility
    # (macOS ships bash 3.2 which has bugs with backslash in ${//} patterns)
    upload_url=$(echo "$upload_url" | sed -e 's/\\u0026/\&/g' -e 's/\\u003d/=/g' -e 's/\\u002f/\//g' -e 's/\\\//\//g')

    print_progress "Uploading telemetry to S3..."

    # Upload to S3 using --upload-file (more reliable than -d for large payloads)
    local upload_response
    upload_response=$(curl -v -w "\n%{http_code}" -X PUT \
        -H "Content-Type: application/json" \
        --upload-file "$payload_file" \
        "${upload_url}" 2>&1)

    local http_code=$(echo "$upload_response" | tail -n 1)

    if [ "$http_code" != "200" ]; then
        print_error "Failed to upload to S3 (HTTP ${http_code})"
        # Get error body - BSD head doesn't support -n -1, use sed instead
        local error_body=$(echo "$upload_response" | sed '$d')
        if [ -n "$error_body" ]; then
            print_error "Error details: ${error_body}"
        fi
        print_error "Payload size: $(stat -f%z "$payload_file" 2>/dev/null || echo 'unknown') bytes"
        print_error "S3 URL starts with: $(echo "$upload_url" | cut -c1-80)..."
        return 1
    fi

    print_progress "Uploaded to S3"

    # Notify backend
    print_progress "Notifying backend of upload..."

    local notify_response
    notify_response=$(curl -w "\n%{http_code}" -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "X-Agent-Version: ${AGENT_VERSION}" \
        -d "{\"s3_key\":\"${s3_key}\",\"device_id\":\"${device_id}\"}" \
        "${API_ENDPOINT}/v1/${CUSTOMER_ID}/developer-mdm-agent/telemetry/process-uploaded" 2>&1)

    http_code=$(echo "$notify_response" | tail -n 1)

    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        print_progress "Backend processing initiated (HTTP ${http_code})"
        return 0
    else
        print_error "Failed to notify backend (HTTP ${http_code})"
        return 1
    fi
}

#==============================================================================
# SECTION 18: EXECUTION LOGGING
#==============================================================================

# Global variables for log capture
EXECUTION_LOGS_OUTPUT=""
EXECUTION_START_TIME=""
EXECUTION_END_TIME=""
OUTPUT_LOG_FILE=""
CAPTURE_LOGS=true
LOGS_FINALIZED=false

# NOTE: MAX_LOG_SIZE_BYTES, MAX_PACKAGE_OUTPUT_SIZE_BYTES, and MAX_NODE_PROJECTS_SIZE_BYTES
# are already defined in Section 7 (Core Utilities). Do NOT redeclare them here.

# capture_execution_logs starts capturing STDOUT and STDERR to a single temp file
capture_execution_logs() {
    # Only capture if enabled
    if [ "$CAPTURE_LOGS" != "true" ]; then
        return 0
    fi

    # Create temp file for log capture
    OUTPUT_LOG_FILE=$(mktemp /tmp/stepsec-output.XXXXXX 2>/dev/null) || {
        print_error "Failed to create temp file for log capture, disabling logging"
        CAPTURE_LOGS=false
        return 1
    }

    EXECUTION_START_TIME=$(date +%s)

    # Save original file descriptors
    exec 3>&1
    exec 4>&2

    # Redirect both STDOUT and STDERR to the same file while still displaying
    # This captures everything printed to the console
    exec 1> >(tee -a "$OUTPUT_LOG_FILE" >&3)
    exec 2> >(tee -a "$OUTPUT_LOG_FILE" >&4)

    return 0
}

# finalize_execution_logs stops log capture and base64 encodes the log
finalize_execution_logs() {
    # Skip if logs are disabled or already finalized (idempotent)
    if [ "$CAPTURE_LOGS" != "true" ] || [ "$LOGS_FINALIZED" = "true" ]; then
        return 0
    fi

    # Mark as finalized to prevent double-finalization
    LOGS_FINALIZED=true

    EXECUTION_END_TIME=$(date +%s)

    # Wait for tee processes to flush (small delay)
    sleep 0.5

    # Restore original file descriptors (on separate lines to ensure correct order)
    exec 1>&3
    exec 2>&4
    exec 3>&-
    exec 4>&-

    # Read and encode log file
    if [ -f "$OUTPUT_LOG_FILE" ]; then
        local output_size
        output_size=$(stat -f%z "$OUTPUT_LOG_FILE" 2>/dev/null || echo 0)

        # Truncate if exceeds max size
        if [ "$output_size" -gt "$MAX_LOG_SIZE_BYTES" ]; then
            print_error "Output log exceeds max size (${output_size} bytes), truncating to ${MAX_LOG_SIZE_BYTES} bytes"
            tail -c "$MAX_LOG_SIZE_BYTES" "$OUTPUT_LOG_FILE" > "${OUTPUT_LOG_FILE}.tmp"
            mv "${OUTPUT_LOG_FILE}.tmp" "$OUTPUT_LOG_FILE"
        fi

        # Base64 encode directly from file to avoid bash variable expansion
        # This prevents xrealloc errors with large logs (integer underflow issue)
        EXECUTION_LOGS_OUTPUT=$(base64 < "$OUTPUT_LOG_FILE" | tr -d '\n' || echo "")
        rm -f "$OUTPUT_LOG_FILE"
    fi

    return 0
}

#==============================================================================
# SECTION 19: MAIN ORCHESTRATORS
#==============================================================================

# Progress step helpers — always visible on stderr so users see activity
# These are used in community mode to show what's happening in real time
STEP_START_TIME=""
SPINNER_PID=""

_stop_spinner() {
    if [ -n "$SPINNER_PID" ]; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
        SPINNER_PID=""
    fi
}

step_start() {
    local label="$1"
    STEP_START_TIME=$(date +%s)
    # Skip progress display for JSON output (keep it pipe-friendly)
    if [ "$OUTPUT_FORMAT" = "json" ]; then
        return
    fi
    # Launch animated spinner as a backgrounded subshell with set +e
    (
        set +e
        trap '' EXIT
        spin_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        i=0
        start=$STEP_START_TIME
        while true; do
            elapsed=$(( $(date +%s) - start ))
            char="${spin_chars:$i:1}"
            printf "\r  %s %s... (%ds)\033[K" "$char" "$label" "$elapsed" >&2
            i=$(( (i + 1) % 10 ))
            sleep 0.12 2>/dev/null || sleep 1
        done
    ) &
    SPINNER_PID=$!
}

step_done() {
    local label="$1"
    _stop_spinner
    if [ "$OUTPUT_FORMAT" = "json" ]; then
        return
    fi
    local end_time=$(date +%s)
    local elapsed=$((end_time - STEP_START_TIME))
    printf "\r  ✓ %s (%ds)\033[K\n" "$label" "$elapsed" >&2
}

step_skip() {
    local label="$1"
    _stop_spinner
    if [ "$OUTPUT_FORMAT" = "json" ]; then
        return
    fi
    printf "\r  ○ %s (skipped)\033[K\n" "$label" >&2
}

# Community mode scan orchestrator
run_scan() {
    # Verify macOS
    if [[ "$OSTYPE" != "darwin"* ]]; then
        print_error "This scanner only supports macOS (detected: $OSTYPE)"
        exit 1
    fi

    local scan_total_start=$(date +%s)
    if [ "$OUTPUT_FORMAT" != "json" ]; then
        printf "\n  StepSecurity Dev Machine Guard v${AGENT_VERSION}\n\n" >&2
    fi

    # Get device identity
    step_start "Gathering device information"
    local serial_number=$(get_serial_number)
    local os_version=$(get_os_version)
    local hostname=$(hostname)
    local user_info=$(get_logged_in_user_info)
    local logged_in_user=$(echo "$user_info" | sed -n '1p')
    local user_home=$(echo "$user_info" | sed -n '2p')
    if [ -z "$logged_in_user" ] || [ -z "$user_home" ]; then
        print_error "No user currently logged in to console. Cannot scan."
        exit 1
    fi
    local developer_identity=$(get_developer_identity "$logged_in_user")
    step_done "Gathering device information"

    # Detect IDEs & desktop apps
    step_start "Scanning IDEs & desktop apps"
    local ide_installations=$(detect_ide_installations "$logged_in_user")
    step_done "Scanning IDEs & desktop apps"

    # Detect AI agents and tools
    step_start "Scanning AI agents & CLI tools"
    local ai_cli_tools=$(detect_ai_cli_tools "$logged_in_user")
    local general_ai_agents=$(detect_general_ai_agents "$user_home")
    local ai_frameworks=$(detect_ai_frameworks "$logged_in_user")
    step_done "Scanning AI agents & CLI tools"

    # Merge AI CLI tools, agents, and frameworks into a single "ai_tools" array
    local ai_tools="[]"
    local cli_content=$(echo "$ai_cli_tools" | sed 's/^\[//;s/\]$//')
    local agents_content=$(echo "$general_ai_agents" | sed 's/^\[//;s/\]$//')
    local frameworks_content=$(echo "$ai_frameworks" | sed 's/^\[//;s/\]$//')
    local combined=""
    [ -n "$cli_content" ] && combined="$cli_content"
    [ -n "$agents_content" ] && { [ -n "$combined" ] && combined="${combined},${agents_content}" || combined="$agents_content"; }
    [ -n "$frameworks_content" ] && { [ -n "$combined" ] && combined="${combined},${frameworks_content}" || combined="$frameworks_content"; }
    [ -n "$combined" ] && ai_tools="[${combined}]"

    # Collect MCP configs
    step_start "Scanning MCP server configs"
    local mcp_configs="[]"
    if [ "$JQ_AVAILABLE" = "true" ] && [ "$PERL_AVAILABLE" = "true" ]; then
        mcp_configs=$(collect_mcp_configs "$user_home")
    else
        print_error "Skipping MCP config collection (jq=$JQ_AVAILABLE, perl=$PERL_AVAILABLE)"
    fi
    step_done "Scanning MCP server configs"

    # Resolve search directories
    local search_dirs
    search_dirs=$(resolve_search_directories "$user_home")

    # Collect extensions across all search directories
    step_start "Scanning IDE extensions"
    local ide_extensions="[]"
    local ext_count=0
    while IFS= read -r search_dir; do
        local dir_ext_result=$(collect_all_extensions "$search_dir")
        local dir_extensions=$(echo "$dir_ext_result" | head -1)
        local dir_ext_count=$(echo "$dir_ext_result" | tail -1)
        # Merge JSON arrays
        if [ "$dir_extensions" != "[]" ] && [ -n "$dir_extensions" ]; then
            if [ "$ide_extensions" = "[]" ]; then
                ide_extensions="$dir_extensions"
            else
                local existing_content=$(echo "$ide_extensions" | sed 's/^\[//;s/\]$//')
                local new_content=$(echo "$dir_extensions" | sed 's/^\[//;s/\]$//')
                ide_extensions="[${existing_content},${new_content}]"
            fi
        fi
        ext_count=$((ext_count + dir_ext_count))
    done <<< "$search_dirs"
    step_done "Scanning IDE extensions"

    # Resolve ENABLE_NODE_PACKAGE_SCAN: in community mode, "auto" means "false"
    if [ "$ENABLE_NODE_PACKAGE_SCAN" = "auto" ]; then
        ENABLE_NODE_PACKAGE_SCAN="false"
    fi

    # Run npm scan if enabled
    local node_package_managers="[]"
    local node_global_packages_file=""
    local node_global_packages_count=0
    local node_projects_file=""
    local node_projects_count=0
    local node_scan_duration=0

    if [ "$ENABLE_NODE_PACKAGE_SCAN" = "true" ]; then
        step_start "Detecting Node.js package managers"
        node_package_managers=$(detect_package_managers "$logged_in_user")
        step_done "Detecting Node.js package managers"

        step_start "Scanning global packages"
        local global_scan_result=$(scan_global_packages "$logged_in_user")
        node_global_packages_file=$(echo "$global_scan_result" | sed -n '1p')
        node_global_packages_count=$(echo "$global_scan_result" | sed -n '2p')
        step_done "Scanning global packages"

        step_start "Scanning Node.js projects"
        # Scan across all search directories, merge results
        local combined_projects_file=$(mktemp)
        echo "[]" > "$combined_projects_file"
        local total_node_projects_count=0
        local total_node_scan_duration=0
        while IFS= read -r search_dir; do
            local node_scan_result=$(scan_node_projects "$search_dir" "$logged_in_user")
            local dir_projects_file=$(echo "$node_scan_result" | sed -n '1p')
            local dir_projects_count=$(echo "$node_scan_result" | sed -n '2p')
            local dir_scan_duration=$(echo "$node_scan_result" | sed -n '3p')
            total_node_projects_count=$((total_node_projects_count + dir_projects_count))
            total_node_scan_duration=$((total_node_scan_duration + dir_scan_duration))
            # Merge project files
            if [ -n "$dir_projects_file" ] && [ -f "$dir_projects_file" ]; then
                local existing=$(cat "$combined_projects_file")
                if [ "$existing" = "[]" ]; then
                    cat "$dir_projects_file" > "$combined_projects_file"
                else
                    local existing_content=$(echo "$existing" | sed 's/^\[//;s/\]$//')
                    local new_content=$(cat "$dir_projects_file" | sed 's/^\[//;s/\]$//')
                    if [ -n "$new_content" ]; then
                        echo "[${existing_content},${new_content}]" > "$combined_projects_file"
                    fi
                fi
                rm -f "$dir_projects_file"
            fi
        done <<< "$search_dirs"
        node_projects_file="$combined_projects_file"
        node_projects_count=$total_node_projects_count
        node_scan_duration=$total_node_scan_duration
        step_done "Scanning Node.js projects"
    else
        step_skip "Node.js packages (use --enable-npm-scan)"
    fi

    local scan_total_end=$(date +%s)
    local scan_total_elapsed=$((scan_total_end - scan_total_start))
    if [ "$OUTPUT_FORMAT" != "json" ]; then
        printf "\n  Scan completed in %ds\n\n" "$scan_total_elapsed" >&2
    fi

    # Calculate counts
    local ide_count=$(count_json_array_items "$ide_installations")
    local ai_tools_count=$(count_json_array_items "$ai_tools")

    local scan_timestamp=$(date +%s)

    # Route to output formatter based on OUTPUT_FORMAT
    case "$OUTPUT_FORMAT" in
        json)
            format_json_output "$scan_timestamp" "$hostname" "$serial_number" "$os_version" \
                "$developer_identity" "$ide_installations" "$ai_tools" "$ide_extensions" \
                "$ide_count" "$ai_tools_count" "$ext_count" "$mcp_configs" \
                "$node_package_managers" "$node_projects_count" \
                "$node_global_packages_file" "$node_projects_file"
            ;;
        html)
            generate_html_report "$HTML_OUTPUT_FILE" "$scan_timestamp" "$hostname" "$serial_number" \
                "$os_version" "$developer_identity" "$ide_installations" "$ai_tools" \
                "$ide_extensions" "$ide_count" "$ai_tools_count" "$ext_count" "$mcp_configs" \
                "$node_package_managers" "$node_projects_count" \
                "$node_global_packages_file" "$node_projects_file"
            ;;
        pretty|*)
            format_pretty_output "$scan_timestamp" "$hostname" "$serial_number" "$os_version" \
                "$developer_identity" "$ide_installations" "$ai_tools" "$ide_extensions" \
                "$ide_count" "$ai_tools_count" "$ext_count" "$mcp_configs" \
                "$node_package_managers" "$node_projects_count" \
                "$node_global_packages_file" "$node_projects_file"
            ;;
    esac

    # Clean up temp files
    [ -n "$node_global_packages_file" ] && [ -f "$node_global_packages_file" ] && rm -f "$node_global_packages_file"
    [ -n "$node_projects_file" ] && [ -f "$node_projects_file" ] && rm -f "$node_projects_file"
}

# Enterprise mode telemetry orchestrator
run_telemetry() {
    # Start log capture FIRST (v1.3.0+)
    capture_execution_logs

    # Ensure logs are finalized even on error
    # Must call both finalize_execution_logs AND cleanup_on_exit to release lock
    trap 'finalize_execution_logs; cleanup_on_exit' EXIT

    echo "=========================================="
    echo "StepSecurity Device Agent v${AGENT_VERSION}"
    echo "=========================================="
    echo ""

    # Acquire lock to prevent multiple instances
    if ! acquire_lock; then
        exit 1
    fi

    # Verify macOS
    if [ "$(uname -s)" != "Darwin" ]; then
        print_error "This agent is for macOS only"
        exit 1
    fi

    print_info "Tool availability: curl=${CURL_AVAILABLE}, jq=${JQ_AVAILABLE}, perl=${PERL_AVAILABLE}"

    # Verify curl is available
    if [ "$CURL_AVAILABLE" = false ]; then
        print_error "curl not found (should be pre-installed on macOS)"
        exit 1
    fi

    # Check if configuration has been customized
    if [[ "$CUSTOMER_ID" == *"{{"* ]] || [[ "$API_KEY" == *"{{"* ]] || [[ "$API_ENDPOINT" == *"{{"* ]]; then
        print_error "This script needs to be customized with your customer details"
        print_error "Please download the installation script from your StepSecurity dashboard"
        exit 1
    fi

    # Get device identity
    DEVICE_ID=$(get_device_id)
    SERIAL_NUMBER=$(get_serial_number)
    OS_VERSION=$(get_os_version)

    # Get logged-in user information
    local user_info=$(get_logged_in_user_info)
    local logged_in_user=$(echo "$user_info" | sed -n '1p')
    local user_home=$(echo "$user_info" | sed -n '2p')

    # Check if a user is logged in
    local no_user_logged_in=false
    if [ -z "$logged_in_user" ] || [ -z "$user_home" ]; then
        no_user_logged_in=true
        print_progress "No user currently logged in - skipping data collection"
        print_progress "Device ID (Serial): ${DEVICE_ID}"
        print_progress "OS Version: ${OS_VERSION}"
        echo ""

        # Send telemetry with no_user_logged_in flag
        local hostname=$(hostname)
        local collected_at=$(date +%s)

        # Finalize execution logs before building payload
        finalize_execution_logs

        local payload_file=$(mktemp)
        cat > "$payload_file" <<EOF
{
  "customer_id": "${CUSTOMER_ID}",
  "device_id": "${DEVICE_ID}",
  "serial_number": "${SERIAL_NUMBER}",
  "user_identity": "none",
  "hostname": "${hostname}",
  "platform": "darwin",
  "os_version": "${OS_VERSION}",
  "agent_version": "${AGENT_VERSION}",
  "collected_at": ${collected_at},
  "no_user_logged_in": true,
  "ide_extensions": [],
  "ide_installations": [],
  "node_package_managers": [],
  "node_global_packages": [],
  "node_projects": [],
  "ai_agents": [],
  "mcp_configs": [],
  "execution_logs": {
    "output_base64": "${EXECUTION_LOGS_OUTPUT}",
    "start_time": ${EXECUTION_START_TIME},
    "end_time": ${EXECUTION_END_TIME},
    "exit_code": 0,
    "agent_version": "${AGENT_VERSION}"
  },
  "performance_metrics": {
    "extensions_count": 0,
    "node_packages_scan_ms": 0,
    "node_global_packages_count": 0,
    "node_projects_count": 0
  }
}
EOF

        # Upload telemetry
        if upload_telemetry_to_s3 "$DEVICE_ID" "$payload_file"; then
            rm -f "$payload_file"
            echo ""
            print_progress "Telemetry sent successfully (no user logged in)"
            exit 0
        else
            echo ""
            print_error "Telemetry upload failed"
            exit 1
        fi
    fi

    DEVELOPER_IDENTITY=$(get_developer_identity "$logged_in_user")

    print_progress "Device ID (Serial): ${DEVICE_ID}"
    print_progress "OS Version: ${OS_VERSION}"
    print_progress "Developer: ${DEVELOPER_IDENTITY}"
    print_progress "Running commands as user: ${logged_in_user}"
    echo ""

    # Detect IDE installations and AI desktop apps
    local ide_installations=$(detect_ide_installations "$logged_in_user")
    echo ""

    # Resolve search directories
    local search_dirs
    search_dirs=$(resolve_search_directories "$user_home")
    echo ""

    # Collect all IDE extensions across search directories
    local ide_extensions="[]"
    local ide_extensions_count=0
    while IFS= read -r search_dir; do
        local dir_ext_result=$(collect_all_extensions "$search_dir")
        local dir_extensions=$(echo "$dir_ext_result" | head -1)
        local dir_ext_count=$(echo "$dir_ext_result" | tail -1)
        if [ "$dir_extensions" != "[]" ] && [ -n "$dir_extensions" ]; then
            if [ "$ide_extensions" = "[]" ]; then
                ide_extensions="$dir_extensions"
            else
                local existing_content=$(echo "$ide_extensions" | sed 's/^\[//;s/\]$//')
                local new_content=$(echo "$dir_extensions" | sed 's/^\[//;s/\]$//')
                ide_extensions="[${existing_content},${new_content}]"
            fi
        fi
        ide_extensions_count=$((ide_extensions_count + dir_ext_count))
    done <<< "$search_dirs"
    echo ""

    # AI Agent Detection (v1.6.0+)
    print_progress "Detecting AI agents and tools..."
    echo ""

    # Detect AI CLI tools
    local ai_cli_tools=$(detect_ai_cli_tools "$logged_in_user")
    echo ""

    # Detect general-purpose AI agents
    local general_ai_agents=$(detect_general_ai_agents "$user_home")
    echo ""

    # Detect AI frameworks
    local ai_frameworks=$(detect_ai_frameworks "$logged_in_user")
    echo ""

    # Combine all AI agents into a single array (v1.6.0+)
    local ai_agents="[]"
    if [ "$ai_cli_tools" != "[]" ] || [ "$general_ai_agents" != "[]" ] || [ "$ai_frameworks" != "[]" ]; then
        # Remove brackets and combine, handling empty arrays
        local cli_content=$(echo "$ai_cli_tools" | sed 's/^\[//;s/\]$//')
        local agents_content=$(echo "$general_ai_agents" | sed 's/^\[//;s/\]$//')
        local frameworks_content=$(echo "$ai_frameworks" | sed 's/^\[//;s/\]$//')

        # Combine non-empty arrays with commas
        local combined=""
        [ -n "$cli_content" ] && combined="$cli_content"
        [ -n "$agents_content" ] && { [ -n "$combined" ] && combined="${combined},${agents_content}" || combined="$agents_content"; }
        [ -n "$frameworks_content" ] && { [ -n "$combined" ] && combined="${combined},${frameworks_content}" || combined="$frameworks_content"; }

        ai_agents="[${combined}]"
    fi

    # Collect MCP configuration files (requires jq and perl)
    local mcp_configs="[]"
    if [ "$JQ_AVAILABLE" = "true" ] && [ "$PERL_AVAILABLE" = "true" ]; then
        mcp_configs=$(collect_mcp_configs "$user_home")
    else
        print_error "Skipping MCP config collection (jq=$JQ_AVAILABLE, perl=$PERL_AVAILABLE)"
    fi
    echo ""

    # Resolve ENABLE_NODE_PACKAGE_SCAN: in enterprise mode, "auto" means "true"
    if [ "$ENABLE_NODE_PACKAGE_SCAN" = "auto" ]; then
        ENABLE_NODE_PACKAGE_SCAN="true"
    fi

    # Node.js package scanning (OPTIONAL - can be disabled)
    local node_package_managers="[]"
    local node_global_packages_file=""
    local node_global_packages_count=0
    local node_projects_file=""
    local node_projects_count=0
    local node_scan_duration=0

    if [ "$ENABLE_NODE_PACKAGE_SCAN" = "true" ]; then
        print_progress "Node.js package scanning is ENABLED"

        # Detect package managers
        node_package_managers=$(detect_package_managers "$logged_in_user")
        echo ""

        # Scan for globally installed packages (returns file path)
        local global_scan_result=$(scan_global_packages "$logged_in_user")
        node_global_packages_file=$(echo "$global_scan_result" | sed -n '1p')
        node_global_packages_count=$(echo "$global_scan_result" | sed -n '2p')
        echo ""

        # Scan for Node.js projects across all search directories
        local combined_projects_file=$(mktemp)
        echo "[]" > "$combined_projects_file"
        local total_node_projects_count=0
        local total_node_scan_duration=0
        while IFS= read -r search_dir; do
            local node_scan_result=$(scan_node_projects "$search_dir" "$logged_in_user")
            local dir_projects_file=$(echo "$node_scan_result" | sed -n '1p')
            local dir_projects_count=$(echo "$node_scan_result" | sed -n '2p')
            local dir_scan_duration=$(echo "$node_scan_result" | sed -n '3p')
            total_node_projects_count=$((total_node_projects_count + dir_projects_count))
            total_node_scan_duration=$((total_node_scan_duration + dir_scan_duration))
            if [ -n "$dir_projects_file" ] && [ -f "$dir_projects_file" ]; then
                local existing=$(cat "$combined_projects_file")
                if [ "$existing" = "[]" ]; then
                    cat "$dir_projects_file" > "$combined_projects_file"
                else
                    local existing_content=$(echo "$existing" | sed 's/^\[//;s/\]$//')
                    local new_content=$(cat "$dir_projects_file" | sed 's/^\[//;s/\]$//')
                    if [ -n "$new_content" ]; then
                        echo "[${existing_content},${new_content}]" > "$combined_projects_file"
                    fi
                fi
                rm -f "$dir_projects_file"
            fi
        done <<< "$search_dirs"
        node_projects_file="$combined_projects_file"
        node_projects_count=$total_node_projects_count
        node_scan_duration=$total_node_scan_duration
        echo ""

    else
        print_progress "Node.js package scanning is DISABLED"
        echo ""
    fi

    # Build telemetry payload to temp file (avoids bash variable size limits)
    local hostname=$(hostname)
    local collected_at=$(date +%s)

    # Finalize execution logs before building payload
    finalize_execution_logs

    local payload_file=$(mktemp)

    # Write payload header
    cat > "$payload_file" <<EOF
{
  "customer_id": "${CUSTOMER_ID}",
  "device_id": "${DEVICE_ID}",
  "serial_number": "${SERIAL_NUMBER}",
  "user_identity": "${DEVELOPER_IDENTITY}",
  "hostname": "${hostname}",
  "platform": "darwin",
  "os_version": "${OS_VERSION}",
  "agent_version": "${AGENT_VERSION}",
  "collected_at": ${collected_at},
  "no_user_logged_in": false,
  "available_tools": {
    "jq": ${JQ_AVAILABLE},
    "perl": ${PERL_AVAILABLE},
    "curl": ${CURL_AVAILABLE}
  },
  "ide_extensions": ${ide_extensions},
  "ide_installations": ${ide_installations},
  "node_package_managers": ${node_package_managers},
EOF

    # Stream node_global_packages from temp file
    printf '  "node_global_packages": [' >> "$payload_file"
    if [ -n "$node_global_packages_file" ] && [ -f "$node_global_packages_file" ]; then
        cat "$node_global_packages_file" >> "$payload_file"
        rm -f "$node_global_packages_file"
    fi
    printf '],\n' >> "$payload_file"

    # Stream node_projects from temp file
    printf '  "node_projects": [' >> "$payload_file"
    if [ -n "$node_projects_file" ] && [ -f "$node_projects_file" ]; then
        cat "$node_projects_file" >> "$payload_file"
        rm -f "$node_projects_file"
    fi
    printf '],\n' >> "$payload_file"

    # Write remaining fields
    cat >> "$payload_file" <<EOF
  "ai_agents": ${ai_agents},
  "mcp_configs": ${mcp_configs},
  "execution_logs": {
    "output_base64": "${EXECUTION_LOGS_OUTPUT}",
    "start_time": ${EXECUTION_START_TIME},
    "end_time": ${EXECUTION_END_TIME},
    "exit_code": 0,
    "agent_version": "${AGENT_VERSION}"
  },
  "performance_metrics": {
    "extensions_count": ${ide_extensions_count},
    "node_packages_scan_ms": ${node_scan_duration},
    "node_global_packages_count": ${node_global_packages_count},
    "node_projects_count": ${node_projects_count}
  }
}
EOF

    # Upload telemetry
    if upload_telemetry_to_s3 "$DEVICE_ID" "$payload_file"; then
        rm -f "$payload_file"
        echo ""
        print_progress "Telemetry collection completed successfully"
        exit 0
    else
        echo ""
        print_error "Telemetry upload failed"
        exit 1
    fi
}

#==============================================================================
# SECTION 20: CLI PARSER AND ENTRY POINT
#==============================================================================

show_help() {
    cat >&2 <<EOF
StepSecurity Dev Machine Guard v${AGENT_VERSION}

Scans your macOS developer environment for IDEs, AI tools, extensions,
MCP servers, and security issues. Outputs results locally or sends
telemetry to StepSecurity backend (enterprise mode).

Usage: $(basename "$0") [COMMAND] [OPTIONS]

Commands (enterprise only):
  install              Install launchd for periodic scanning
  uninstall            Remove launchd configuration
  send-telemetry       Send scan data to StepSecurity backend

Output formats (community mode, mutually exclusive):
  --pretty             Pretty terminal output (default)
  --json               JSON output to stdout
  --html FILE          HTML report saved to FILE

Options:
  --search-dir DIR     Add DIR to search paths (repeatable, appends to SEARCH_DIRS)
  --enable-npm-scan    Enable Node.js package scanning
  --disable-npm-scan   Disable Node.js package scanning
  --verbose            Show progress messages (suppressed by default)
  --color=WHEN         Color mode: auto | always | never (default: auto)
  -v, --version        Show version
  -h, --help           Show this help

Examples:
  $(basename "$0")                                  # Pretty terminal output
  $(basename "$0") --json | python3 -m json.tool    # Formatted JSON
  $(basename "$0") --json > scan.json               # JSON to file
  $(basename "$0") --html report.html               # HTML report
  $(basename "$0") --verbose --enable-npm-scan      # Verbose with npm scan
  $(basename "$0") --search-dir /Volumes/code       # Also search /Volumes/code
  $(basename "$0") send-telemetry                   # Enterprise telemetry

https://github.com/step-security/dev-machine-guard
EOF
}

# Parse CLI arguments
ENTERPRISE_COMMAND=""
while [ $# -gt 0 ]; do
    case "$1" in
        install|--install)
            ENTERPRISE_COMMAND="install"
            shift
            ;;
        uninstall|--uninstall)
            ENTERPRISE_COMMAND="uninstall"
            shift
            ;;
        send-telemetry|--send-telemetry)
            ENTERPRISE_COMMAND="send-telemetry"
            shift
            ;;
        --pretty)
            OUTPUT_FORMAT="pretty"
            shift
            ;;
        --json)
            OUTPUT_FORMAT="json"
            shift
            ;;
        --html)
            OUTPUT_FORMAT="html"
            if [ -z "${2:-}" ]; then
                print_error "--html requires a file path argument"
                exit 1
            fi
            HTML_OUTPUT_FILE="$2"
            shift 2
            ;;
        --enable-npm-scan)
            ENABLE_NODE_PACKAGE_SCAN="true"
            shift
            ;;
        --disable-npm-scan)
            ENABLE_NODE_PACKAGE_SCAN="false"
            shift
            ;;
        --color=*)
            COLOR_MODE="${1#--color=}"
            if [[ "$COLOR_MODE" != "auto" && "$COLOR_MODE" != "always" && "$COLOR_MODE" != "never" ]]; then
                print_error "Invalid color mode: $COLOR_MODE (must be auto, always, or never)"
                exit 1
            fi
            shift
            ;;
        --search-dir)
            if [ -z "${2:-}" ]; then
                print_error "--search-dir requires a directory path argument"
                exit 1
            fi
            SEARCH_DIRS="${SEARCH_DIRS} $2"
            shift 2
            ;;
        --verbose)
            QUIET=false
            shift
            ;;
        -v|--version)
            echo "StepSecurity Dev Machine Guard v${AGENT_VERSION}"
            exit 0
            ;;
        -h|--help|help)
            show_help
            exit 0
            ;;
        version)
            echo "StepSecurity Dev Machine Guard v${AGENT_VERSION}"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Run '$(basename "$0") --help' for usage information." >&2
            exit 1
            ;;
    esac
done

# Initialize colors after parsing arguments
setup_colors

# Entry point logic
if [ -n "$ENTERPRISE_COMMAND" ]; then
    # Enterprise command specified - validate config and run
    case "$ENTERPRISE_COMMAND" in
        send-telemetry)
            if ! is_enterprise_mode; then
                print_error "Enterprise configuration not found. Please download the script from your StepSecurity dashboard."
                exit 1
            fi
            run_telemetry
            ;;
        install)
            echo "StepSecurity Dev Machine Guard v${AGENT_VERSION}"
            echo ""

            if ! is_enterprise_mode; then
                print_error "Enterprise configuration not found. Please download the script from your StepSecurity dashboard."
                exit 1
            fi

            if is_launchd_configured "$(whoami)"; then
                print_progress "Existing agent installation detected. Upgrading..."
                uninstall_launchd
                print_progress "Previous installation removed. Installing new version..."
            fi

            if configure_launchd; then
                echo ""
                print_progress "Installation complete!"
                print_progress "The agent will now run automatically every ${SCAN_FREQUENCY_HOURS} hours"
                echo ""
                print_progress "Sending initial telemetry..."
                echo ""
                run_telemetry
            else
                exit 1
            fi
            ;;
        uninstall)
            echo "StepSecurity Dev Machine Guard v${AGENT_VERSION}"
            echo ""

            if ! is_launchd_configured "$(whoami)"; then
                print_progress "Agent is not currently configured for periodic execution"
                exit 0
            fi

            uninstall_launchd
            exit 0
            ;;
    esac
elif [ "$OUTPUT_FORMAT" != "pretty" ] || [ -n "$HTML_OUTPUT_FILE" ]; then
    # Output format flag was explicitly set - community mode
    run_scan
elif is_enterprise_mode; then
    # No args + enterprise config valid - enterprise mode (backward compat)
    run_telemetry
else
    # No args + no enterprise config - community mode (pretty)
    run_scan
fi
