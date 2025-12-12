#!/bin/bash
#
# conn-monitor uninstaller
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   exit 1
fi

echo "Uninstalling conn-monitor..."

# Stop and disable service
systemctl stop conn-monitor 2>/dev/null || true
systemctl disable conn-monitor 2>/dev/null || true

# Remove files
rm -f /etc/systemd/system/conn-monitor.service
rm -f /usr/local/bin/conn-monitor.sh

# Reload systemd
systemctl daemon-reload

# Clean up ipset
ipset destroy cloudflare 2>/dev/null || true

echo -e "${GREEN}conn-monitor uninstalled${NC}"
echo ""
echo "Note: iptables rules and /var/log/conn-monitor.log were preserved."
echo "To remove blocked IPs: iptables -F INPUT"
echo "To remove log: rm /var/log/conn-monitor.log"
