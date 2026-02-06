# Network Scanner - Device & Web Service Discovery

A comprehensive cross-platform Python network scanner that detects all devices on your local network and checks for running web services.

## Features

✅ **Cross-Platform**: Works on Windows, Linux, and macOS  
✅ **Fast Scanning**: Uses parallel processing for quick results  
✅ **ARP Table Parsing**: Quick device discovery from system ARP cache  
✅ **Network Ping Sweep**: Thorough scanning of entire subnet  
✅ **MAC Address Resolution**: Identifies device MAC addresses  
✅ **Vendor Identification**: Recognizes 500+ device manufacturers  
✅ **Web Service Detection**: Scans common HTTP/HTTPS ports  
✅ **Page Title Extraction**: Retrieves web page titles  
✅ **Detailed Reporting**: Saves timestamped results to file  
✅ **No Compilation Required**: Pure Python, no C++ dependencies  

## Requirements

- Python 3.6 or higher
- `requests` library (the only external dependency)

## Installation

### Step 1: Install Python
If you don't have Python installed, download it from [python.org](https://www.python.org/downloads/)

### Step 2: Install Dependencies
```bash
pip install requests
```

That's it! No compilation required.

## Usage

### Basic Usage
```bash
python network_scanner.py
```

### What It Does

1. **Detects your local network** - Automatically identifies your network range
2. **Scans ARP table** - Quickly finds devices from system cache
3. **Performs ping sweep** - Discovers all active devices on the network
4. **Resolves MAC addresses** - Gets hardware addresses for each device
5. **Identifies vendors** - Matches MAC addresses to manufacturers
6. **Scans web ports** - Checks ports 80, 443, 8080, 8000, 8443, 8888, 3000, 5000, 9090
7. **Extracts details** - Gets HTTP status, server type, and page titles
8. **Saves results** - Creates timestamped report file

### Output

The scanner provides:

#### Console Output
```
================================================================================
NETWORK SCANNER - Device and Web Service Detection
================================================================================
Local IP: 192.168.1.100
Network Range: 192.168.1.0/24
OS: Windows

[*] Step 1: Parsing ARP table...
[+] Found 5 devices in ARP table

[*] Scanning network range: 192.168.1.0/24
[*] Progress: 254/254 hosts checked
[+] Found 8 alive hosts

[*] Step 3: Resolving MAC addresses...
[*] Step 4: Identifying vendors...
[*] Step 5: Scanning 8 devices for web services...
[*] Progress: 8/8 devices scanned for web services

================================================================================
SCAN RESULTS
================================================================================

Total devices found: 8
Devices with web services: 3

--------------------------------------------------------------------------------
IP Address      MAC Address        Vendor               Web Services
--------------------------------------------------------------------------------
192.168.1.1     AA:BB:CC:DD:EE:FF  TP-Link             1 service(s)
  └─ http://192.168.1.1:80
     Status: 200 | Server: nginx
     Title: Router Admin Panel

192.168.1.100   11:22:33:44:55:66  Apple               None
192.168.1.150   66:77:88:99:AA:BB  Samsung             2 service(s)
  └─ http://192.168.1.150:80
     Status: 200 | Server: Apache
     Title: Home Server
  └─ http://192.168.1.150:8080
     Status: 200 | Server: Node.js
     Title: Development Server
--------------------------------------------------------------------------------
```

#### Text File Output
Results are automatically saved to a timestamped file:
- Filename format: `network_scan_YYYYMMDD_HHMMSS.txt`
- Location: Same directory as the script
- Contains: All device details, web services, and scan metadata

## Scanned Web Ports

The scanner checks these common web service ports:
- **80** - HTTP
- **443** - HTTPS
- **8080** - HTTP Alternate
- **8000** - HTTP Development
- **8443** - HTTPS Alternate
- **8888** - HTTP Alternate
- **3000** - Node.js/React Development
- **5000** - Flask Development
- **9090** - Management/Admin Interfaces

## Vendor Detection

The scanner includes an extensive MAC vendor database with 500+ manufacturers including:
- Apple
- Samsung
- Cisco
- TP-Link
- Netgear
- D-Link
- Linksys
- Asus
- Google
- Microsoft
- Raspberry Pi
- VMware
- And many more...

## Platform-Specific Notes

### Windows
- Requires Administrator privileges for best results (ARP table access)
- Uses `ping -n 1 -w 1000` for host detection
- Parses `arp -a` output for MAC addresses

### Linux
- May require `sudo` for full ARP table access
- Uses `ping -c 1 -W 1` for host detection
- Parses `arp -a` or `arp -n` for MAC addresses

### macOS
- May require elevated privileges for ARP access
- Uses `ping -c 1 -W 1` for host detection
- Parses `arp -a` output for MAC addresses

## Running with Elevated Privileges

For best results, run with administrator/sudo privileges:

**Windows (Administrator):**
```cmd
# Right-click Command Prompt -> "Run as Administrator"
python network_scanner.py
```

**Linux/macOS:**
```bash
sudo python3 network_scanner.py
```

## Troubleshooting

### "No devices found"
- Ensure you're connected to a network
- Try running with elevated privileges
- Check if firewall is blocking pings

### "SSL Certificate Error"
- This is normal for HTTPS services with self-signed certificates
- The scanner automatically handles this by trying HTTP fallback

### "Slow scanning"
- Larger networks take longer (up to 5 minutes for /24 subnet)
- Progress indicators show current status
- You can interrupt with Ctrl+C and still get partial results

### "Missing MAC addresses"
- Some devices may not respond to ARP requests
- Firewall settings can block ARP responses
- Virtual machines may show different MAC patterns

## Example Use Cases

1. **Home Network Audit**: See all devices connected to your home WiFi
2. **Security Check**: Identify unknown devices on your network
3. **Web Server Discovery**: Find running web services (routers, NAS, IoT devices)
4. **IT Administration**: Quick network inventory and service discovery
5. **IoT Device Management**: Locate smart home devices and their web interfaces

## Technical Details

### Architecture
- **Scanning Engine**: Multi-threaded with `concurrent.futures.ThreadPoolExecutor`
- **Network Detection**: Uses socket connection to determine local IP
- **ARP Parsing**: Cross-platform regex-based parsing
- **Web Detection**: `requests` library with SSL verification disabled for self-signed certs
- **Progress Tracking**: Real-time progress indicators for long operations

### Performance
- Typical /24 subnet scan: 2-5 minutes
- Parallel ping: 50 concurrent threads
- Parallel web scan: 5 concurrent devices, 10 ports per device
- Timeout: 1-3 seconds per operation

### Limitations
- Assumes /24 subnet (can be modified in code)
- Only scans common web ports (extensible)
- Cannot detect devices that don't respond to ping
- MAC vendor database limited to common manufacturers

## Security Considerations

⚠️ **Use Responsibly**: Only scan networks you own or have permission to scan  
⚠️ **Legal Compliance**: Unauthorized network scanning may be illegal in your jurisdiction  
⚠️ **Privacy**: The scanner accesses local network information only  
⚠️ **No Data Collection**: All data stays local, nothing is sent externally  

## Customization

### Scan Different Subnet
Edit the `_get_network_range()` method:
```python
return "10.0.0.0/24"  # Change to your network
```

### Add More Ports
Edit the `common_ports` list in `_scan_ports_on_device()`:
```python
common_ports = [80, 443, 8080, 8000, 8443, 8888, 3000, 5000, 9090, 3306, 5432]
```

### Add More Vendors
Add entries to the `MAC_VENDORS` dictionary:
```python
'AA:BB:CC': 'Your Company',
```

## Contributing

Feel free to extend this scanner with:
- More MAC vendor entries
- Additional port scanning
- Service fingerprinting
- Network topology mapping
- Custom reporting formats

## License

This tool is provided as-is for educational and administrative purposes.

## Author

Created as a comprehensive network discovery tool for home and small business use.

---

**Version**: 1.0  
**Last Updated**: February 2026  
**Python**: 3.6+  
**Dependencies**: requests
