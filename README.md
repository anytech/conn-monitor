# conn-monitor

Automatic connection flood monitor and blocker for Linux web servers.

Monitors active TCP connections on ports 80/443 and automatically blocks IP addresses or /16 subnets that exceed configurable thresholds. Designed for servers behind Cloudflare with proper whitelisting to prevent false positives.

## Features

- Blocks individual IPs with 100+ concurrent connections
- Blocks /16 subnets with 75+ concurrent connections (catches distributed attacks)
- **Temporary range block mode** - catch individual attackers from a range, then release innocent traffic
- **Configurable block expiry** - auto-expire blocks after a set duration
- Automatic Cloudflare IP whitelisting using ipset (updated daily)
- Static whitelist for trusted IP ranges
- All settings configurable via environment variables or systemd
- Logs all blocks to `/var/log/conn-monitor.log`
- Runs as a systemd service with auto-restart

## Quick Install

**From install script:**
```bash
curl -fsSL https://raw.githubusercontent.com/anytech/conn-monitor/main/install.sh | sudo bash
```

**From source:**
```bash
git clone https://github.com/anytech/conn-monitor.git
cd conn-monitor
sudo ./install.sh
```

## Uninstall

```bash
sudo ./uninstall.sh
```

## Requirements

- Ubuntu/Debian (or any Linux with systemd and apt)
- Root access

Dependencies are installed automatically:
- ipset
- conntrack
- iptables
- iproute2
- curl

## Configuration

All settings can be configured in three ways:

1. **Edit the script directly** - Modify defaults in `/usr/local/bin/conn-monitor.sh`
2. **Environment file** - Create `/etc/default/conn-monitor` with settings
3. **Systemd service** - Uncomment and modify lines in `/etc/systemd/system/conn-monitor.service`

### Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `THRESHOLD` | `100` | Block IPs exceeding this many connections |
| `SUBNET_THRESHOLD` | `75` | Block /16 subnets exceeding this many connections |
| `SERVER_IP` | `YOUR_SERVER_IP` | Your server's IP (excluded from monitoring) |
| `STATIC_WHITELIST` | `127.0.0 10.0.0 192.168` | Space-separated IP prefixes to never block |
| `IP_BLOCK_EXPIRY` | `0` | Seconds until IP blocks expire (0 = permanent) |
| `RANGE_BLOCK_EXPIRY` | `0` | Seconds until range blocks expire (0 = permanent) |
| `BLOCK_MODE` | `permanent` | `permanent` or `temporary` for /16 ranges |
| `TEMP_BLOCK_DURATION` | `3600` | Seconds to hold temporary range blocks |
| `LOGFILE` | `/var/log/conn-monitor.log` | Log file location |
| `CF_UPDATE_INTERVAL` | `86400` | Seconds between Cloudflare IP updates |
| `ABUSEIPDB_ENABLED` | `no` | Enable AbuseIPDB reporting (`yes`/`no`) |
| `ABUSEIPDB_KEY` | *(empty)* | Your AbuseIPDB API key |
| `ABUSEIPDB_CATEGORIES` | `4,21` | Category codes for reports |
| `ABUSEIPDB_RATE_LIMIT` | `30` | Minimum seconds between reports |
| `ABUSEIPDB_REPORT_RANGES` | `no` | Report /16 ranges (requires paid tier) |
| `ABUSEIPDB_BLACKLIST_ENABLED` | `no` | Proactively block IPs from AbuseIPDB blacklist |
| `ABUSEIPDB_BLACKLIST_CONFIDENCE` | `90` | Minimum confidence score (1-100) to block |
| `ABUSEIPDB_BLACKLIST_LIMIT` | `1000` | Max IPs to fetch from blacklist (free tier: 10,000/day) |
| `ABUSEIPDB_BLACKLIST_BLOCK_EXPIRY` | `2592000` | Seconds until blacklist blocks expire (30 days) |

### Example: Using Environment File

Create `/etc/default/conn-monitor`:
```bash
# Enable temporary range blocks with 1-hour capture window
BLOCK_MODE=temporary
TEMP_BLOCK_DURATION=3600

# Auto-expire individual IP blocks after 24 hours
IP_BLOCK_EXPIRY=86400

# Your server's IP
SERVER_IP=203.0.113.50

# Add your management IP to whitelist
STATIC_WHITELIST="127.0.0 10.0.0 192.168 YOUR.MGMT.IP"
```

Then enable in the service file by uncommenting:
```
EnvironmentFile=-/etc/default/conn-monitor
```

### Example: Systemd Service Configuration

Edit `/etc/systemd/system/conn-monitor.service` and uncomment the settings you want:
```ini
[Service]
# ... existing settings ...

# Enable temporary range block mode
Environment=BLOCK_MODE=temporary
Environment=TEMP_BLOCK_DURATION=3600

# Auto-expire IP blocks after 24 hours
Environment=IP_BLOCK_EXPIRY=86400
```

After changes: `sudo systemctl daemon-reload && sudo systemctl restart conn-monitor`

## Block Modes Explained

### Permanent Mode (default)
```
BLOCK_MODE=permanent
```
Traditional behavior - blocked ranges stay blocked until manually removed or expiry (if configured).

### Temporary Range Block Mode
```
BLOCK_MODE=temporary
TEMP_BLOCK_DURATION=3600
```

When a /16 subnet exceeds the threshold:
1. The entire /16 is blocked
2. During the block, individual IPs attempting to connect are caught and blocked permanently
3. Caught IPs are reported to AbuseIPDB in real-time
4. After `TEMP_BLOCK_DURATION` seconds, the range block is lifted
5. If the range exceeds the threshold again, it gets temp-blocked again

**Use case:** Catch attackers from a botnet without permanently blocking entire countries. The range acts as a temporary net - catch the bad IPs, then release innocent traffic.

Data files are stored in `/etc/conn-monitor/` and persist across restarts.

Log output example:
```
Temporary block on 45.5.0.0/16 (150 connections) for 3600s
Blocked IP 45.5.123.45 (caught from temp block on 45.5.0.0/16)
Released temp block on 45.5.0.0/16
```

### Block Expiry

Set non-zero values to auto-expire blocks:
```bash
IP_BLOCK_EXPIRY=86400      # IPs unblocked after 24 hours
RANGE_BLOCK_EXPIRY=86400   # Ranges unblocked after 24 hours (permanent mode only)
```

Log output:
```
Expired IP block removed: 192.0.2.50 (after 86400s)
Expired range block removed: 45.5.0.0/16 (after 86400s)
```

## AbuseIPDB Integration

Optionally report blocked IPs to [AbuseIPDB](https://www.abuseipdb.com/) to contribute to the global threat intelligence database.

### Setup

1. Create a free account at https://www.abuseipdb.com/
2. Get your API key from https://www.abuseipdb.com/account/api
3. Configure the environment variables:

```bash
# In /etc/default/conn-monitor or systemd service
ABUSEIPDB_ENABLED=yes
ABUSEIPDB_KEY=your_api_key_here
```

### Free vs Paid Tiers

- **Free tier**: Reports individual IPs only (3,000 reports/day)
- **Paid tiers**: Can also report /16 ranges with `ABUSEIPDB_REPORT_RANGES=yes`

### Rate Limiting

The free tier allows 3,000 reports per day (~1 every 29 seconds). The default `ABUSEIPDB_RATE_LIMIT=30` ensures you stay within limits. Reports are queued and sent one at a time with rate limiting.

### Category Codes

Default categories are `4,21` (DDoS Attack, Web App Attack). Common categories:
- `4` - DDoS Attack
- `15` - Hacking
- `21` - Web App Attack
- `18` - Brute Force

See all categories: https://www.abuseipdb.com/categories

### Log Output

```
Reported 192.0.2.50 to AbuseIPDB (150 connections)
```

## Usage

Check status:
```bash
systemctl status conn-monitor
```

View logs:
```bash
tail -f /var/log/conn-monitor.log
```

View blocked ranges:
```bash
iptables -L INPUT -n | grep DROP
```

View Cloudflare whitelist:
```bash
ipset list cloudflare
```

## How it works

Every 5 seconds, the script:

1. Checks for expired blocks (IP and range) and removes them
2. Checks for expired temporary range blocks, harvests caught IPs, releases ranges
3. Counts connections per /16 subnet on ports 80/443
4. If a subnet has 75+ connections:
   - Checks if it's Cloudflare (via ipset)
   - Checks if it's in the static whitelist
   - If neither, blocks based on `BLOCK_MODE` (temporary or permanent)
   - Kills existing connections with conntrack
5. Counts connections per individual IP
6. If an IP has 100+ connections:
   - Same whitelist checks
   - Blocks the single IP if not whitelisted

The Cloudflare ipset is refreshed daily from `https://www.cloudflare.com/ips-v4`.

## Thresholds

Default thresholds work well for most servers:

- `SUBNET_THRESHOLD=75` - Distributed attacks rarely have legitimate 75+ connections from one /16
- `THRESHOLD=100` - Single IP attacks are caught at 100 connections

Adjust based on your traffic patterns. Lower = more aggressive blocking.

## Notes

- Block data persists in `/etc/conn-monitor/` and is restored on service restart
- Data files track temporary IPs (`temp-ips.log`), permanent IPs (`perm-ips.log`), blacklist IPs (`blacklist-ips.log`), and ranges
- Works best with servers behind Cloudflare proxy
- For non-Cloudflare setups, adjust the whitelist accordingly

## License

MIT

## Author

Kayne Middleton - [Anytech](https://anytech.ca) - kayne@anytech.ca

Built while defending against a week-long DDoS attack from a 5.76 million device botnet.
