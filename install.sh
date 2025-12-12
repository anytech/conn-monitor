#!/bin/bash
#
# conn-monitor installer
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}conn-monitor installer${NC}"
echo "========================"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   exit 1
fi

# Find script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if source files exist
if [[ ! -f "$SCRIPT_DIR/conn-monitor.sh" ]]; then
    echo -e "${RED}Error: conn-monitor.sh not found in $SCRIPT_DIR${NC}"
    exit 1
fi

# Detect server IP
SERVER_IP=$(hostname -I | awk '{print $1}')
echo -e "Detected server IP: ${YELLOW}$SERVER_IP${NC}"
read -p "Is this correct? [Y/n] " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    read -p "Enter your server IP: " SERVER_IP
fi

# Install dependencies
echo ""
echo "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq ipset conntrack iptables iproute2 curl

# Install script
echo "Installing conn-monitor..."
cp "$SCRIPT_DIR/conn-monitor.sh" /usr/local/bin/conn-monitor.sh
chmod +x /usr/local/bin/conn-monitor.sh

# Install systemd service
cp "$SCRIPT_DIR/conn-monitor.service" /etc/systemd/system/conn-monitor.service

# Set server IP in service file
if ! grep -q "Environment=SERVER_IP=" /etc/systemd/system/conn-monitor.service; then
    # Add SERVER_IP after the RestartSec line
    sed -i "/^RestartSec=/a Environment=SERVER_IP=$SERVER_IP" /etc/systemd/system/conn-monitor.service
else
    # Update existing SERVER_IP
    sed -i "s/Environment=SERVER_IP=.*/Environment=SERVER_IP=$SERVER_IP/" /etc/systemd/system/conn-monitor.service
fi

# Enable and start
echo "Enabling service..."
systemctl daemon-reload
systemctl enable conn-monitor
systemctl start conn-monitor

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Commands:"
echo "  systemctl status conn-monitor     - Check status"
echo "  tail -f /var/log/conn-monitor.log - View logs"
echo "  iptables -L INPUT -n | grep DROP  - View blocked IPs"
echo ""
echo "Configuration:"
echo "  Edit /etc/systemd/system/conn-monitor.service to change settings"
echo "  Then run: systemctl daemon-reload && systemctl restart conn-monitor"
echo ""
echo "Or create /etc/default/conn-monitor with your settings and uncomment"
echo "the EnvironmentFile line in the service file."
echo ""
