# Intrusion Detection System (IDS)

A lightweight, cross-platform network and host-based intrusion detection system written in Python. Detects common network attacks and suspicious system activity with minimal dependencies.

## Features

- **Network Attack Detection**
  - SYN Flood attacks
  - UDP Flood attacks
  - ICMP Flood attacks
  - Port scanning
  - Real-time packet capture

- **Host-Based Detection**
  - File integrity monitoring (critical system files)
  - Suspicious process detection
  - System resource monitoring

- **Management Features**
  - SQLite database for logging
  - Configurable thresholds
  - Export reports
  - Color-coded console output
  - Persistent configuration

## Requirements

- Python 3.6+
- Administrator/root privileges (required for packet capture)
- Optional: psutil (for enhanced process monitoring)

## Installation

### Linux / macOS / Windows

```bash
# Install Python dependencies
pip install colorama psutil

# Clone repository
git clone https://github.com/zer0tr4c3.exe/IDS.git
cd IDS

# Run with sudo (Linux)
sudo python IDS.py
# Windows
python IDS.py
