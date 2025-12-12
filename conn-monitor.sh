#!/bin/bash
#
# conn-monitor - Connection flood monitor with automatic blocking
#
# Monitors active connections on ports 80/443 and automatically blocks
# IP addresses or /16 subnets that exceed connection thresholds.
# Uses ipset for efficient Cloudflare IP whitelisting.
#
# Dependencies: ipset, conntrack, iptables, curl, ss
# Install: apt install ipset conntrack iptables
#

VERSION="1.2.0"
CONFIG_FILE="/etc/default/conn-monitor"

# Valid configuration variables
VALID_VARS="THRESHOLD SUBNET_THRESHOLD SERVER_IP STATIC_WHITELIST LOGFILE CF_UPDATE_INTERVAL IP_BLOCK_EXPIRY RANGE_BLOCK_EXPIRY BLOCK_MODE TEMP_BLOCK_DURATION LOG_PREFIX SYSLOG_FILE ABUSEIPDB_ENABLED ABUSEIPDB_KEY ABUSEIPDB_CATEGORIES ABUSEIPDB_RATE_LIMIT ABUSEIPDB_REPORT_RANGES ABUSEIPDB_BLACKLIST_ENABLED ABUSEIPDB_BLACKLIST_CONFIDENCE ABUSEIPDB_BLACKLIST_LIMIT ABUSEIPDB_BLACKLIST_INTERVAL"

# Show help
show_help() {
    cat << EOF
conn-monitor v$VERSION - Connection flood monitor with automatic blocking

Usage: conn-monitor.sh [command]

Commands:
  (none)                Run the monitor (normally via systemd)
  status                Show current configuration and blocked IPs
  unblock <ip>          Unblock an IP address
  unblock <range>/16    Unblock a /16 range (e.g., 45.5.0.0/16)
  config                Show config file and current settings
  config set VAR=value  Set configuration variable(s)
  -h, --help            Show this help message
  -v, --version         Show version

Examples:
  conn-monitor.sh unblock 192.0.2.50
  conn-monitor.sh unblock 45.5.0.0/16
  conn-monitor.sh config set THRESHOLD=50
  conn-monitor.sh config set BLOCK_MODE=temporary TEMP_BLOCK_DURATION=3600
  conn-monitor.sh status

Configuration Variables:
  THRESHOLD             Block IPs exceeding this many connections (default: 100)
  SUBNET_THRESHOLD      Block /16 subnets exceeding this (default: 75)
  SERVER_IP             Your server IP, excluded from monitoring
  STATIC_WHITELIST      Space-separated IP prefixes to never block
  LOGFILE               Log file location (default: /var/log/conn-monitor.log)
  CF_UPDATE_INTERVAL    Seconds between Cloudflare IP updates (default: 86400)

Block Expiry:
  IP_BLOCK_EXPIRY       Seconds until IP blocks expire, 0=permanent (default: 0)
  RANGE_BLOCK_EXPIRY    Seconds until range blocks expire, 0=permanent (default: 0)

Temporary Range Block Mode:
  BLOCK_MODE            "permanent" or "temporary" for /16 ranges (default: permanent)
  TEMP_BLOCK_DURATION   Seconds to hold temp blocks before harvesting (default: 3600)
  LOG_PREFIX            iptables LOG prefix (default: CONN-MONITOR)
  SYSLOG_FILE           Syslog file to parse (default: /var/log/kern.log)

AbuseIPDB Reporting:
  ABUSEIPDB_ENABLED     Enable reporting: yes/no (default: no)
  ABUSEIPDB_KEY         Your API key from abuseipdb.com
  ABUSEIPDB_CATEGORIES  Category codes, comma-separated (default: 4,21)
  ABUSEIPDB_RATE_LIMIT  Min seconds between reports (default: 30)
  ABUSEIPDB_REPORT_RANGES  Report /16 ranges, requires paid tier (default: no)

AbuseIPDB Blacklist (proactive blocking):
  ABUSEIPDB_BLACKLIST_ENABLED    Enable blacklist sync: yes/no (default: no)
  ABUSEIPDB_BLACKLIST_CONFIDENCE Min confidence score 25-100 (default: 75)
  ABUSEIPDB_BLACKLIST_LIMIT      Max IPs to fetch (default: 10000)
  ABUSEIPDB_BLACKLIST_INTERVAL   Seconds between updates (default: 86400)

Config file: $CONFIG_FILE

Service commands:
  systemctl status conn-monitor      Check service status
  systemctl restart conn-monitor     Restart after config changes
  tail -f /var/log/conn-monitor.log  View live logs

More info: https://github.com/anytech/conn-monitor
EOF
    exit 0
}

# Show version
show_version() {
    echo "conn-monitor v$VERSION"
    exit 0
}

# Show current status
show_status() {
    echo "conn-monitor v$VERSION"
    echo ""

    # Load config if exists
    [[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

    echo "Current Configuration:"
    echo "  THRESHOLD=${THRESHOLD:-100}"
    echo "  SUBNET_THRESHOLD=${SUBNET_THRESHOLD:-75}"
    echo "  SERVER_IP=${SERVER_IP:-YOUR_SERVER_IP}"
    echo "  BLOCK_MODE=${BLOCK_MODE:-permanent}"
    echo "  TEMP_BLOCK_DURATION=${TEMP_BLOCK_DURATION:-3600}"
    echo "  IP_BLOCK_EXPIRY=${IP_BLOCK_EXPIRY:-0}"
    echo "  RANGE_BLOCK_EXPIRY=${RANGE_BLOCK_EXPIRY:-0}"
    echo "  ABUSEIPDB_ENABLED=${ABUSEIPDB_ENABLED:-no}"
    echo "  ABUSEIPDB_BLACKLIST_ENABLED=${ABUSEIPDB_BLACKLIST_ENABLED:-no}"
    echo ""

    # Show blacklist count if available
    if ipset list abuseipdb-blacklist &>/dev/null; then
        local bl_count=$(ipset list abuseipdb-blacklist 2>/dev/null | grep -c "^[0-9]")
        echo "AbuseIPDB Blacklist: $bl_count IPs loaded"
        echo ""
    fi

    echo "Blocked IPs (iptables):"
    iptables -L INPUT -n 2>/dev/null | grep DROP | head -20 || echo "  (none or no permission)"
    echo ""

    echo "Service status:"
    systemctl is-active conn-monitor 2>/dev/null || echo "  (not running or not installed)"
    exit 0
}

# Show config info
show_config() {
    echo "conn-monitor v$VERSION"
    echo ""
    echo "Config file: $CONFIG_FILE"

    if [[ -f "$CONFIG_FILE" ]]; then
        echo ""
        echo "Current config:"
        cat "$CONFIG_FILE"
    else
        echo "  (file does not exist - using defaults)"
        echo ""
        echo "To create a config file, run:"
        echo "  conn-monitor.sh config set VARIABLE=value"
        echo ""
        echo "Or manually: sudo nano $CONFIG_FILE"
    fi
    exit 0
}

# Set config values
set_config() {
    shift  # Remove 'config' from args
    shift  # Remove 'set' from args

    if [[ $# -eq 0 ]]; then
        echo "Usage: conn-monitor.sh config set VAR=value [VAR2=value2 ...]"
        echo ""
        echo "Example:"
        echo "  conn-monitor.sh config set THRESHOLD=50 BLOCK_MODE=temporary"
        echo ""
        echo "Run 'conn-monitor.sh --help' to see all available variables."
        exit 1
    fi

    # Check for root
    if [[ $EUID -ne 0 ]]; then
        echo "Error: Setting config requires root. Use: sudo conn-monitor.sh config set ..."
        exit 1
    fi

    # Create config file with header if it doesn't exist
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "# conn-monitor configuration" > "$CONFIG_FILE"
        echo "# Generated by conn-monitor.sh config set" >> "$CONFIG_FILE"
        echo "" >> "$CONFIG_FILE"
    fi

    # Process each VAR=value argument
    for arg in "$@"; do
        if [[ ! "$arg" =~ ^[A-Z_]+= ]]; then
            echo "Error: Invalid format '$arg'. Use VAR=value"
            exit 1
        fi

        local var="${arg%%=*}"
        local value="${arg#*=}"

        # Validate variable name
        if ! echo "$VALID_VARS" | grep -qw "$var"; then
            echo "Error: Unknown variable '$var'"
            echo "Run 'conn-monitor.sh --help' to see valid variables."
            exit 1
        fi

        # Update or add the variable
        if grep -q "^${var}=" "$CONFIG_FILE" 2>/dev/null; then
            # Update existing
            sed -i "s|^${var}=.*|${var}=${value}|" "$CONFIG_FILE"
            echo "Updated: ${var}=${value}"
        elif grep -q "^#.*${var}=" "$CONFIG_FILE" 2>/dev/null; then
            # Uncomment and update
            sed -i "s|^#.*${var}=.*|${var}=${value}|" "$CONFIG_FILE"
            echo "Enabled: ${var}=${value}"
        else
            # Add new
            echo "${var}=${value}" >> "$CONFIG_FILE"
            echo "Added: ${var}=${value}"
        fi
    done

    echo ""
    echo "Config updated. Restart the service to apply:"
    echo "  sudo systemctl restart conn-monitor"
    exit 0
}

# Unblock an IP or range
do_unblock() {
    local target="$1"

    if [[ -z "$target" ]]; then
        echo "Usage: conn-monitor.sh unblock <ip or range>"
        echo ""
        echo "Examples:"
        echo "  conn-monitor.sh unblock 192.0.2.50"
        echo "  conn-monitor.sh unblock 45.5.0.0/16"
        exit 1
    fi

    # Check for root
    if [[ $EUID -ne 0 ]]; then
        echo "Error: Unblocking requires root. Use: sudo conn-monitor.sh unblock $target"
        exit 1
    fi

    # Check if it's a range (contains /16)
    if [[ "$target" == *"/16" ]]; then
        # It's a range - remove both DROP and LOG rules
        if iptables -L INPUT -n | grep -q "$target"; then
            iptables -D INPUT -s "$target" -j DROP 2>/dev/null
            iptables -D INPUT -s "$target" -j LOG 2>/dev/null  # In case temp block
            echo "Unblocked range: $target"
        else
            echo "Range $target is not currently blocked"
            exit 1
        fi
    else
        # It's an IP
        if iptables -L INPUT -n | grep -q " $target "; then
            iptables -D INPUT -s "$target" -j DROP 2>/dev/null
            echo "Unblocked IP: $target"
        else
            echo "IP $target is not currently blocked"
            exit 1
        fi
    fi

    exit 0
}

# Parse arguments
case "${1:-}" in
    -h|--help|help)
        show_help
        ;;
    -v|--version|version)
        show_version
        ;;
    status)
        show_status
        ;;
    unblock)
        do_unblock "$2"
        ;;
    config)
        if [[ "${2:-}" == "set" ]]; then
            set_config "$@"
        else
            show_config
        fi
        ;;
esac

# Load config file if it exists
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

# === CONFIGURATION ===
# All settings can be overridden via environment variables (e.g., in systemd service)

# Block individual IPs exceeding this many connections
THRESHOLD="${THRESHOLD:-100}"

# Block /16 subnets exceeding this many connections
SUBNET_THRESHOLD="${SUBNET_THRESHOLD:-75}"

# Log file location
LOGFILE="${LOGFILE:-/var/log/conn-monitor.log}"

# Your server's IP (excluded from monitoring)
SERVER_IP="${SERVER_IP:-YOUR_SERVER_IP}"

# Static whitelist - IP prefixes that should never be blocked
# Includes: localhost, Google, your management IP
STATIC_WHITELIST="${STATIC_WHITELIST:-127.0.0 10.0.0 192.168}"

# How often to refresh Cloudflare IPs (seconds)
CF_UPDATE_INTERVAL="${CF_UPDATE_INTERVAL:-86400}"

# === BLOCK EXPIRY SETTINGS ===

# IP block expiry (seconds). 0 = permanent (never expires)
IP_BLOCK_EXPIRY="${IP_BLOCK_EXPIRY:-0}"

# Range block expiry (seconds). 0 = permanent (never expires)
# Note: Only applies when BLOCK_MODE="permanent"
RANGE_BLOCK_EXPIRY="${RANGE_BLOCK_EXPIRY:-0}"

# === TEMPORARY RANGE BLOCK SETTINGS ===

# BLOCK_MODE for /16 ranges:
#   "permanent" = block ranges permanently (subject to RANGE_BLOCK_EXPIRY)
#   "temporary" = block range, log IPs, harvest individuals, then release range
BLOCK_MODE="${BLOCK_MODE:-permanent}"

# Duration to hold temporary range blocks (seconds) before harvesting IPs
# Only used when BLOCK_MODE="temporary"
TEMP_BLOCK_DURATION="${TEMP_BLOCK_DURATION:-3600}"

# Prefix for iptables LOG entries (used to identify our log entries in syslog)
LOG_PREFIX="${LOG_PREFIX:-CONN-MONITOR}"

# Syslog file to parse for caught IPs (kern.log or syslog depending on distro)
SYSLOG_FILE="${SYSLOG_FILE:-/var/log/kern.log}"

# === ABUSEIPDB REPORTING ===

# Enable AbuseIPDB reporting (requires API key)
ABUSEIPDB_ENABLED="${ABUSEIPDB_ENABLED:-no}"

# Your AbuseIPDB API key (get from https://www.abuseipdb.com/account/api)
ABUSEIPDB_KEY="${ABUSEIPDB_KEY:-}"

# AbuseIPDB category codes for reports (comma-separated)
# 4 = DDoS Attack, 21 = Web App Attack
# See: https://www.abuseipdb.com/categories
ABUSEIPDB_CATEGORIES="${ABUSEIPDB_CATEGORIES:-4,21}"

# Rate limit: minimum seconds between reports (free tier = 3000/day, ~29s between)
ABUSEIPDB_RATE_LIMIT="${ABUSEIPDB_RATE_LIMIT:-30}"

# Report /16 ranges (requires paid AbuseIPDB tier with subnet reporting)
# Free tier can only report individual IPs
ABUSEIPDB_REPORT_RANGES="${ABUSEIPDB_REPORT_RANGES:-no}"

# === ABUSEIPDB BLACKLIST (proactive blocking) ===

# Enable AbuseIPDB blacklist sync (requires API key)
# Downloads known bad IPs and blocks them proactively
ABUSEIPDB_BLACKLIST_ENABLED="${ABUSEIPDB_BLACKLIST_ENABLED:-no}"

# Minimum confidence score for blacklist IPs (25-100)
# Higher = more confident the IP is malicious (default 75 matches AbuseIPDB)
ABUSEIPDB_BLACKLIST_CONFIDENCE="${ABUSEIPDB_BLACKLIST_CONFIDENCE:-75}"

# Maximum IPs to fetch from blacklist (free tier: 10000 max)
ABUSEIPDB_BLACKLIST_LIMIT="${ABUSEIPDB_BLACKLIST_LIMIT:-10000}"

# How often to refresh the blacklist (seconds) - default 24h
# Free tier allows 10 requests/day, so don't set below 8640 (2.4h)
ABUSEIPDB_BLACKLIST_INTERVAL="${ABUSEIPDB_BLACKLIST_INTERVAL:-86400}"

# === END CONFIGURATION ===

LAST_CF_UPDATE=0
LAST_ABUSEIPDB_REPORT=0
LAST_BLACKLIST_UPDATE=0

# Data structures for tracking blocks with timestamps
# Using temp files as associative arrays (bash 3 compatibility)
BLOCKED_IPS_FILE="/tmp/conn-monitor-blocked-ips.$$"
BLOCKED_RANGES_FILE="/tmp/conn-monitor-blocked-ranges.$$"
TEMP_RANGES_FILE="/tmp/conn-monitor-temp-ranges.$$"
ABUSEIPDB_QUEUE_FILE="/tmp/conn-monitor-abuseipdb-queue.$$"

# Initialize tracking files
> "$BLOCKED_IPS_FILE"
> "$BLOCKED_RANGES_FILE"
> "$TEMP_RANGES_FILE"
> "$ABUSEIPDB_QUEUE_FILE"

# Cleanup on exit
cleanup() {
    rm -f "$BLOCKED_IPS_FILE" "$BLOCKED_RANGES_FILE" "$TEMP_RANGES_FILE" "$ABUSEIPDB_QUEUE_FILE"
}
trap cleanup EXIT

# Queue an IP for AbuseIPDB reporting
queue_abuseipdb_report() {
    local ip=$1
    local count=$2
    local reason=$3
    [[ "$ABUSEIPDB_ENABLED" != "yes" ]] && return
    [[ -z "$ABUSEIPDB_KEY" ]] && return
    echo "$ip|$count|$reason" >> "$ABUSEIPDB_QUEUE_FILE"
}

# Process AbuseIPDB report queue (rate-limited)
process_abuseipdb_queue() {
    [[ "$ABUSEIPDB_ENABLED" != "yes" ]] && return
    [[ -z "$ABUSEIPDB_KEY" ]] && return
    [[ ! -s "$ABUSEIPDB_QUEUE_FILE" ]] && return

    local now=$(date +%s)
    local time_since=$((now - LAST_ABUSEIPDB_REPORT))

    # Rate limit check
    if [[ "$time_since" -lt "$ABUSEIPDB_RATE_LIMIT" ]]; then
        return
    fi

    # Get next IP from queue
    local entry=$(head -1 "$ABUSEIPDB_QUEUE_FILE")
    [[ -z "$entry" ]] && return

    local ip=$(echo "$entry" | cut -d'|' -f1)
    local count=$(echo "$entry" | cut -d'|' -f2)
    local reason=$(echo "$entry" | cut -d'|' -f3)

    # Build comment
    local comment="Blocked by conn-monitor: $count connections ($reason)"

    # Submit report
    local response=$(curl -s --connect-timeout 10 -X POST \
        "https://api.abuseipdb.com/api/v2/report" \
        -H "Key: $ABUSEIPDB_KEY" \
        -H "Accept: application/json" \
        -d "ip=$ip" \
        -d "categories=$ABUSEIPDB_CATEGORIES" \
        --data-urlencode "comment=$comment" 2>/dev/null)

    # Check for success
    if echo "$response" | grep -q '"ipAddress"'; then
        echo "$(date): Reported $ip to AbuseIPDB ($count connections)" >> $LOGFILE
    else
        local error=$(echo "$response" | grep -oE '"message":"[^"]*"' | head -1)
        echo "$(date): AbuseIPDB report failed for $ip: $error" >> $LOGFILE
    fi

    # Remove processed entry from queue
    tail -n +2 "$ABUSEIPDB_QUEUE_FILE" > "$ABUSEIPDB_QUEUE_FILE.tmp"
    mv "$ABUSEIPDB_QUEUE_FILE.tmp" "$ABUSEIPDB_QUEUE_FILE"

    LAST_ABUSEIPDB_REPORT=$now
}

# Track a blocked IP with timestamp
track_blocked_ip() {
    local ip=$1
    local timestamp=$(date +%s)
    echo "$ip $timestamp" >> "$BLOCKED_IPS_FILE"
}

# Track a blocked range with timestamp (permanent mode)
track_blocked_range() {
    local range=$1
    local timestamp=$(date +%s)
    echo "$range $timestamp" >> "$BLOCKED_RANGES_FILE"
}

# Track a temporary range block with timestamp
track_temp_range() {
    local range=$1
    local timestamp=$(date +%s)
    echo "$range $timestamp" >> "$TEMP_RANGES_FILE"
}

# Check if IP is already tracked
is_ip_tracked() {
    local ip=$1
    grep -q "^$ip " "$BLOCKED_IPS_FILE" 2>/dev/null
}

# Check if range is already tracked (permanent)
is_range_tracked() {
    local range=$1
    grep -q "^$range " "$BLOCKED_RANGES_FILE" 2>/dev/null
}

# Check if range is tracked as temporary
is_temp_range_tracked() {
    local range=$1
    grep -q "^$range " "$TEMP_RANGES_FILE" 2>/dev/null
}

# Block a range temporarily with LOG rule to capture individual IPs
block_range_temporary() {
    local range=$1
    local count=$2
    local cidr="$range.0.0/16"

    # Skip if already blocked
    if iptables -C INPUT -s "$cidr" -j DROP 2>/dev/null; then
        return
    fi

    # Add LOG rule first (before DROP) to capture IPs hitting this range
    iptables -I INPUT 1 -s "$cidr" -j LOG --log-prefix "${LOG_PREFIX}-${range}: " --log-level 4
    # Then add DROP rule
    iptables -I INPUT 2 -s "$cidr" -j DROP

    # Kill existing connections
    conntrack -D -s "$cidr" 2>/dev/null

    # Track this temporary block
    track_temp_range "$range"

    # Queue range for AbuseIPDB reporting (paid tier only)
    if [[ "$ABUSEIPDB_REPORT_RANGES" == "yes" ]]; then
        queue_abuseipdb_report "$cidr" "$count" "subnet flood (temp block)"
    fi

    echo "$(date): Temporary block on $cidr ($count connections), logging individual IPs for ${TEMP_BLOCK_DURATION}s" >> $LOGFILE
}

# Block a range permanently (with optional expiry)
block_range_permanent() {
    local range=$1
    local count=$2
    local cidr="$range.0.0/16"

    # Skip if already blocked
    if iptables -C INPUT -s "$cidr" -j DROP 2>/dev/null; then
        return
    fi

    iptables -I INPUT 1 -s "$cidr" -j DROP
    conntrack -D -s "$cidr" 2>/dev/null

    # Track for expiry if enabled
    if [[ "$RANGE_BLOCK_EXPIRY" -gt 0 ]]; then
        track_blocked_range "$range"
    fi

    # Queue range for AbuseIPDB reporting (paid tier only)
    if [[ "$ABUSEIPDB_REPORT_RANGES" == "yes" ]]; then
        queue_abuseipdb_report "$cidr" "$count" "subnet flood"
    fi

    echo "$(date): Blocked subnet $cidr ($count connections)" >> $LOGFILE
}

# Block an individual IP (with optional expiry and AbuseIPDB reporting)
block_ip() {
    local ip=$1
    local count=$2
    local reason="${3:-threshold exceeded}"

    # Skip if already blocked
    if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        return
    fi

    iptables -I INPUT 1 -s "$ip" -j DROP
    conntrack -D -s "$ip" 2>/dev/null

    # Track for expiry if enabled
    if [[ "$IP_BLOCK_EXPIRY" -gt 0 ]]; then
        track_blocked_ip "$ip"
    fi

    # Queue for AbuseIPDB reporting (skip if already on blacklist - no need to re-report)
    if [[ "$reason" != "AbuseIPDB blacklist" ]]; then
        queue_abuseipdb_report "$ip" "$count" "$reason"
    fi

    echo "$(date): Blocked IP $ip ($count connections, $reason)" >> $LOGFILE
}

# Harvest IPs from syslog for a specific range and ban them individually
harvest_ips_from_range() {
    local range=$1
    local cidr="$range.0.0/16"
    local log_tag="${LOG_PREFIX}-${range}:"

    # Parse syslog for IPs that hit this range's LOG rule
    # Extract unique IPs from log entries matching our prefix
    local caught_ips=$(grep "$log_tag" "$SYSLOG_FILE" 2>/dev/null | \
        grep -oE 'SRC=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        cut -d= -f2 | sort -u)

    local ip_count=0
    for ip in $caught_ips; do
        # Skip if already blocked
        if iptables -L INPUT -n | grep -q " $ip "; then
            continue
        fi

        # Skip whitelisted
        if is_cloudflare "$ip" || is_static_whitelisted "$ip"; then
            continue
        fi

        # Ban this individual IP permanently
        iptables -I INPUT 1 -s "$ip" -j DROP
        if [[ "$IP_BLOCK_EXPIRY" -gt 0 ]]; then
            track_blocked_ip "$ip"
        fi

        # Queue for AbuseIPDB reporting
        queue_abuseipdb_report "$ip" "1" "caught from temp block on $cidr"

        ((ip_count++))
    done

    echo "$ip_count"
}

# Release a temporary range block
release_temp_range() {
    local range=$1
    local cidr="$range.0.0/16"

    # Harvest IPs before releasing
    local caught_count=$(harvest_ips_from_range "$range")

    # Remove the LOG rule
    iptables -D INPUT -s "$cidr" -j LOG --log-prefix "${LOG_PREFIX}-${range}: " --log-level 4 2>/dev/null
    # Remove the DROP rule
    iptables -D INPUT -s "$cidr" -j DROP 2>/dev/null

    # Remove from tracking
    grep -v "^$range " "$TEMP_RANGES_FILE" > "$TEMP_RANGES_FILE.tmp" 2>/dev/null
    mv "$TEMP_RANGES_FILE.tmp" "$TEMP_RANGES_FILE" 2>/dev/null

    echo "$(date): Released $cidr, caught and banned $caught_count individual IPs" >> $LOGFILE
}

# Check and process expired temporary range blocks
check_temp_range_expiry() {
    local now=$(date +%s)

    while read -r range timestamp; do
        [[ -z "$range" ]] && continue
        local age=$((now - timestamp))
        if [[ "$age" -ge "$TEMP_BLOCK_DURATION" ]]; then
            release_temp_range "$range"
        fi
    done < "$TEMP_RANGES_FILE"
}

# Check and remove expired IP blocks
check_ip_expiry() {
    [[ "$IP_BLOCK_EXPIRY" -eq 0 ]] && return

    local now=$(date +%s)
    local remaining=""

    while read -r ip timestamp; do
        [[ -z "$ip" ]] && continue
        local age=$((now - timestamp))
        if [[ "$age" -ge "$IP_BLOCK_EXPIRY" ]]; then
            iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
            echo "$(date): Expired IP block removed: $ip (after ${age}s)" >> $LOGFILE
        else
            remaining+="$ip $timestamp"$'\n'
        fi
    done < "$BLOCKED_IPS_FILE"

    echo -n "$remaining" > "$BLOCKED_IPS_FILE"
}

# Check and remove expired range blocks (permanent mode only)
check_range_expiry() {
    [[ "$RANGE_BLOCK_EXPIRY" -eq 0 ]] && return

    local now=$(date +%s)
    local remaining=""

    while read -r range timestamp; do
        [[ -z "$range" ]] && continue
        local age=$((now - timestamp))
        local cidr="$range.0.0/16"
        if [[ "$age" -ge "$RANGE_BLOCK_EXPIRY" ]]; then
            iptables -D INPUT -s "$cidr" -j DROP 2>/dev/null
            echo "$(date): Expired range block removed: $cidr (after ${age}s)" >> $LOGFILE
        else
            remaining+="$range $timestamp"$'\n'
        fi
    done < "$BLOCKED_RANGES_FILE"

    echo -n "$remaining" > "$BLOCKED_RANGES_FILE"
}

init_ipset() {
    if ! ipset list cloudflare &>/dev/null; then
        ipset create cloudflare hash:net
        echo "$(date): Created cloudflare ipset" >> $LOGFILE
    fi
    if ! ipset list abuseipdb-blacklist &>/dev/null; then
        ipset create abuseipdb-blacklist hash:ip maxelem 100000
        echo "$(date): Created abuseipdb-blacklist ipset" >> $LOGFILE
    fi
}

update_cloudflare_ips() {
    local cf_cidrs=$(curl -s --connect-timeout 10 https://www.cloudflare.com/ips-v4)
    if [[ -z "$cf_cidrs" ]]; then
        echo "$(date): Failed to fetch Cloudflare IPs" >> $LOGFILE
        LAST_CF_UPDATE=$(date +%s)
        return
    fi

    ipset flush cloudflare
    for cidr in $cf_cidrs; do
        ipset add cloudflare "$cidr" 2>/dev/null
    done

    echo "$(date): Updated Cloudflare ipset" >> $LOGFILE
    LAST_CF_UPDATE=$(date +%s)
}

update_abuseipdb_blacklist() {
    [[ "$ABUSEIPDB_BLACKLIST_ENABLED" != "yes" ]] && return
    [[ -z "$ABUSEIPDB_KEY" ]] && return

    # Fetch blacklist as plaintext (one IP per line)
    local blacklist=$(curl -s --connect-timeout 30 -G \
        "https://api.abuseipdb.com/api/v2/blacklist" \
        -d "confidenceMinimum=$ABUSEIPDB_BLACKLIST_CONFIDENCE" \
        -d "limit=$ABUSEIPDB_BLACKLIST_LIMIT" \
        -d "plaintext" \
        -H "Key: $ABUSEIPDB_KEY" \
        -H "Accept: text/plain" 2>/dev/null)

    if [[ -z "$blacklist" ]]; then
        echo "$(date): Failed to fetch AbuseIPDB blacklist" >> $LOGFILE
        LAST_BLACKLIST_UPDATE=$(date +%s)
        return
    fi

    # Check for error response (JSON error messages start with {)
    if [[ "$blacklist" == "{"* ]]; then
        local error=$(echo "$blacklist" | grep -oE '"message":"[^"]*"' | head -1)
        echo "$(date): AbuseIPDB blacklist error: $error" >> $LOGFILE
        LAST_BLACKLIST_UPDATE=$(date +%s)
        return
    fi

    # Flush and repopulate the ipset
    ipset flush abuseipdb-blacklist
    local count=0
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        [[ "$ip" == "#"* ]] && continue  # Skip comments
        ipset add abuseipdb-blacklist "$ip" 2>/dev/null && ((count++))
    done <<< "$blacklist"

    echo "$(date): Updated AbuseIPDB blacklist ipset ($count IPs, confidence >= $ABUSEIPDB_BLACKLIST_CONFIDENCE%)" >> $LOGFILE
    LAST_BLACKLIST_UPDATE=$(date +%s)
}

is_blacklisted() {
    local ip=$1
    ipset test abuseipdb-blacklist "$ip" 2>/dev/null
}

is_cloudflare() {
    local ip=$1
    ipset test cloudflare "$ip" 2>/dev/null
}

is_static_whitelisted() {
    local ip=$1
    # Always whitelist the server's own /16 range
    local server_prefix=$(echo "$SERVER_IP" | cut -d. -f1-2)
    if [[ -n "$server_prefix" && "$ip" == "$server_prefix"* ]]; then
        return 0
    fi
    for w in $STATIC_WHITELIST; do
        if [[ "$ip" == "$w"* ]]; then
            return 0
        fi
    done
    return 1
}

# Initialize
init_ipset
update_cloudflare_ips
update_abuseipdb_blacklist

# Main loop
while true; do
    NOW=$(date +%s)
    if (( NOW - LAST_CF_UPDATE > CF_UPDATE_INTERVAL )); then
        update_cloudflare_ips
    fi
    if (( NOW - LAST_BLACKLIST_UPDATE > ABUSEIPDB_BLACKLIST_INTERVAL )); then
        update_abuseipdb_blacklist
    fi

    # Check for expired blocks
    check_ip_expiry
    check_range_expiry
    if [[ "$BLOCK_MODE" == "temporary" ]]; then
        check_temp_range_expiry
    fi

    # Check per /16 subnet on ports 80/443
    ss -tan '( sport = :80 or sport = :443 )' 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        grep -v "$SERVER_IP" | \
        cut -d. -f1-2 | sort | uniq -c | sort -rn | \
    while read count range; do
        if [[ "$count" -gt "$SUBNET_THRESHOLD" && -n "$range" ]]; then
            test_ip="$range.0.1"
            if is_cloudflare "$test_ip" || is_static_whitelisted "$range"; then
                continue
            fi

            # Check if already blocked (either mode)
            if iptables -L INPUT -n | grep -q "$range.0.0/16"; then
                continue
            fi

            # Block based on mode
            if [[ "$BLOCK_MODE" == "temporary" ]]; then
                block_range_temporary "$range" "$count"
            else
                block_range_permanent "$range" "$count"
            fi
        fi
    done

    # Check per IP on ports 80/443
    ss -tan '( sport = :80 or sport = :443 )' 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        grep -v "$SERVER_IP" | \
        sort | uniq -c | sort -rn | \
    while read count ip; do
        [[ -z "$ip" ]] && continue

        # Skip whitelisted
        if is_cloudflare "$ip" || is_static_whitelisted "$ip"; then
            continue
        fi

        # Skip if already blocked
        if iptables -L INPUT -n | grep -q " $ip "; then
            continue
        fi

        # Block if on AbuseIPDB blacklist (proactive blocking)
        if is_blacklisted "$ip"; then
            block_ip "$ip" "$count" "AbuseIPDB blacklist"
            continue
        fi

        # Block if over threshold
        if [[ "$count" -gt "$THRESHOLD" ]]; then
            block_ip "$ip" "$count" "threshold exceeded"
        fi
    done

    # Process AbuseIPDB report queue (rate-limited)
    process_abuseipdb_queue

    sleep 5
done
