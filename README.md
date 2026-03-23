# Intrusion Detection System

## Overview
Network and host-based intrusion detection system written in Python. Monitors network traffic and system activity for malicious patterns.

## Architecture
┌─────────────────────────────────────────────────────────────────┐
│ IDS Core │
├─────────────────────────────────────────────────────────────────┤
│ │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│ │ Packet │ │ Host │ │ Alert │ │
│ │ Capture │ │ Monitor │ │ Manager │ │
│ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ │
│ │ │ │ │
│ ▼ ▼ ▼ │
│ ┌──────────────────────────────────────────────────────┐ │
│ │ SQLite Database │ │
│ │ - alerts table │ │
│ │ - attacks table │ │
│ └──────────────────────────────────────────────────────┘ │
│ │
│ ┌──────────────────────────────────────────────────────┐ │
│ │ Configuration (JSON) │ │
│ └──────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

text

## Components

### Packet Capture Module
- Raw socket packet capture (requires root/admin)
- IP/TCP/UDP/ICMP protocol parsing
- SYN flood detection
- UDP flood detection
- ICMP flood detection
- Port scan detection
- Configurable thresholds
- Threaded processing

### Host Monitor Module
- File integrity monitoring (SHA-256)
- Critical file tracking
- Suspicious process detection
- Process name pattern matching
- Command line inspection
- Optional psutil integration

### Alert Manager Module
- Queue-based alert processing
- Severity classification
- Console output with color coding
- Log file persistence
- Database storage

### Database Module
- SQLite backend
- Alert storage with timestamps
- Attack statistics
- Historical query support
- Report generation

### Configuration Module
- JSON configuration file
- Runtime modification
- Threshold tuning
- Whitelist management
- Persistent settings

## Detection Methods

### SYN Flood Detection
- Monitors TCP SYN packets
- Threshold: 500 packets per time window
- Alert severity: CRITICAL
- Source tracking per IP

### UDP Flood Detection
- Monitors UDP packet rate
- Threshold: 500 packets per time window
- Alert severity: CRITICAL
- Destination port tracking

### ICMP Flood Detection
- Monitors ICMP echo requests
- Threshold: 200 packets per time window
- Alert severity: HIGH
- Ping flood detection

### Port Scan Detection
- Tracks unique destination ports
- Threshold: 100 ports per time window
- Alert severity: HIGH
- Source IP tracking
- Time window: 10 seconds

### File Integrity Monitoring
- SHA-256 hash comparison
- Monitored files:
  - Windows: hosts, SAM
  - Linux: passwd, shadow, hosts
- Check interval: 60 seconds
- Alert on hash mismatch

### Process Monitoring
- Process name scanning
- Suspicious pattern detection:
  - netcat, ncat, telnet
  - mimikatz, procdump
  - powershell -enc
- Command line inspection
- Check interval: 10 seconds

## Installation

### Prerequisites
- Python 3.6+
- Administrator/root privileges

### Dependencies
colorama>=0.4.6
psutil>=5.9.0

text

### Windows
```cmd
git clone https://github.com/zer0tr4c3exe/IDS.git
cdd IDS
pip install colorama psutil
python ids.py
```
### Linux / macOS
```cmd
git clone https://github.com/zer0tr4c3exe/IDS.git
cdd IDS
pip3 install colorama psutil
sudo python3 ids.py
```
### Configuration
config.json Structure
json
{
    "port_scan_threshold": 100,
    "syn_flood_threshold": 500,
    "udp_flood_threshold": 500,
    "icmp_flood_threshold": 200,
    "time_window": 10,
    "whitelist": ["127.0.0.1"],
    "auto_block": false,
    "db_file": "ids.db",
    "log_file": "ids.log"
}
