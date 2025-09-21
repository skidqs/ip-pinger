# Python IP Pinger

A Python tool that pings an IP address or hostname to check if it is online.  
Includes optional async port scanning for TCP, UDP, HTTP, and HTTPS.

## Features
- Check if an IP or hostname is online
- Detailed output: TTL, response time, port status
- Supports TCP, UDP, HTTP, HTTPS port detection
- Works on Windows, Linux, and macOS
- Optional async HTTP/HTTPS scanning using aiohttp

## Requirements
- Python 3.8+
- Optional: `aiohttp` (`pip install aiohttp`)

## Usage
```bash
python pinger.py
