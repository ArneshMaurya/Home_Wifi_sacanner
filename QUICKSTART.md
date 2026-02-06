# Quick Start Guide - Network Scanner

## Installation (5 minutes)

### Option 1: Automatic Installation

**Windows:**
1. Double-click `install.bat`
2. Wait for installation to complete

**Linux/macOS:**
```bash
chmod +x install.sh
./install.sh
```

### Option 2: Manual Installation

```bash
# Install the only required package
pip install requests
```

That's it! No C++ compilers or complex dependencies needed.

## Running the Scanner

### Basic Usage (Recommended)

**Windows (as Administrator):**
1. Right-click Command Prompt
2. Select "Run as Administrator"
3. Navigate to scanner directory
4. Run: `python network_scanner.py`

**Linux/macOS:**
```bash
sudo python3 network_scanner.py
```

### Without Admin Rights

You can run without admin, but you might get fewer results:
```bash
python network_scanner.py
```

## What Happens During a Scan

```
Step 1: Parse ARP Table (5 seconds)
  ├─ Reads system ARP cache
  └─ Quickly finds recently active devices

Step 2: Network Ping Sweep (30-60 seconds)
  ├─ Pings all 254 IPs in your subnet
  ├─ Uses 50 parallel threads for speed
  └─ Shows real-time progress

Step 3: Resolve MAC Addresses (10 seconds)
  ├─ Gets hardware addresses for each IP
  └─ Updates ARP table as needed

Step 4: Identify Vendors (1 second)
  ├─ Matches MAC to manufacturer database
  └─ Recognizes 500+ vendors

Step 5: Scan Web Services (60-120 seconds)
  ├─ Checks 9 common web ports per device
  ├─ Tests HTTP and HTTPS protocols
  ├─ Extracts page titles and server info
  └─ Scans 5 devices in parallel

Total Time: 2-5 minutes for typical home network
```

## Understanding the Output

### Console Output
```
IP Address      MAC Address        Vendor        Web Services
192.168.1.1     E8:48:B8:C8:D7:1A  TP-Link      1 service(s)
  └─ http://192.168.1.1:80
     Status: 200 | Server: GoAhead-Webs
     Title: TP-LINK Wireless Router
```

- **IP Address**: Network address of the device
- **MAC Address**: Hardware address (unique identifier)
- **Vendor**: Device manufacturer
- **Web Services**: Number of web interfaces found

### Saved Report

Automatically saved as: `network_scan_YYYYMMDD_HHMMSS.txt`

Contains:
- Full scan details
- All devices with complete information
- Web service URLs and details
- Timestamp and network information

## Common Use Cases

### 1. Find Your Router's Admin Page
Look for your router's vendor (TP-Link, Netgear, etc.) and check its web services.

### 2. Discover Smart Home Devices
Find IoT devices and their web interfaces (cameras, NAS, hubs).

### 3. Identify Unknown Devices
Check MAC vendors to see what's connected to your network.

### 4. Locate Development Servers
Find running web servers on ports 3000, 5000, 8000, 8080.

### 5. Network Security Audit
See all connected devices and verify they're authorized.

## Interpreting Results

### Web Service Status Codes
- **200**: Service is running and accessible
- **401/403**: Authentication required or forbidden
- **404**: Service exists but page not found
- **500**: Server error

### Common Vendors
- **Apple**: iPhones, iPads, Macs, Apple TV
- **Samsung**: Phones, tablets, smart TVs
- **Google**: Chromecast, Nest devices, Pixel phones
- **Raspberry Pi**: DIY projects, home servers, Pi-hole
- **Synology**: Network attached storage (NAS)
- **TP-Link/Netgear/Asus**: Routers and network equipment
- **VMware/VirtualBox**: Virtual machines
- **Unknown**: Generic/unregistered manufacturers

### Common Web Services
- **Port 80**: Standard HTTP web server
- **Port 443**: HTTPS (secure) web server
- **Port 8080**: Alternative HTTP (often admin interfaces)
- **Port 3000**: Development servers (React, Node.js)
- **Port 5000**: Flask/Python development servers
- **Port 8123**: Home Assistant
- **Port 9090**: Cockpit/Admin panels

## Troubleshooting

### Problem: "No devices found"
**Solutions:**
- Run as Administrator/sudo
- Check you're connected to WiFi
- Try scanning a different subnet
- Disable firewall temporarily

### Problem: "No web services found"
**Solutions:**
- Most devices don't run web servers (this is normal)
- Some devices block port scans
- Check if the device actually has a web interface

### Problem: "Scan is slow"
**Solutions:**
- Normal for large networks (wait 3-5 minutes)
- You can press Ctrl+C to stop early
- Partial results are still saved

### Problem: "SSL/Certificate errors"
**Solutions:**
- These are normal for self-signed certificates
- The scanner automatically handles them
- You can ignore these warnings

## Next Steps

1. **Review the results**: Check the console and saved file
2. **Access web interfaces**: Use the URLs to visit device admin pages
3. **Document your network**: Keep scan results for reference
4. **Set up security**: Change default passwords on web interfaces
5. **Schedule regular scans**: Monitor for new/unknown devices

## Tips for Best Results

✅ **Run with admin privileges** for complete ARP table access  
✅ **Scan during low network activity** for faster results  
✅ **Keep the scanner updated** with new MAC vendors  
✅ **Run regularly** to track network changes  
✅ **Save reports** for comparison over time  

## Privacy & Security Notes

- All scanning happens on your local network only
- No data is sent to external servers
- Results are saved locally on your computer
- Only scan networks you own or have permission to scan
- Change default passwords on discovered web interfaces

## Getting Help

If you encounter issues:

1. Check the troubleshooting section above
2. Ensure Python 3.6+ is installed
3. Verify `requests` library is installed: `pip install requests`
4. Try running with admin/sudo privileges
5. Check that you're connected to the network

## Example Session

```bash
$ sudo python3 network_scanner.py

================================================================================
                        NETWORK SCANNER v1.0
                   Device & Web Service Discovery
================================================================================

================================================================================
NETWORK SCANNER - Device and Web Service Detection
================================================================================
Local IP: 192.168.1.100
Network Range: 192.168.1.0/24
OS: Linux

[*] Step 1: Parsing ARP table...
[+] Found 8 devices in ARP table

[*] Scanning network range: 192.168.1.0/24
[*] Progress: 254/254 hosts checked
[+] Found 12 alive hosts

[*] Step 3: Resolving MAC addresses...
[*] Step 4: Identifying vendors...
[*] Step 5: Scanning 12 devices for web services...
[*] Progress: 12/12 devices scanned for web services

================================================================================
SCAN RESULTS
================================================================================

Total devices found: 12
Devices with web services: 5

[Output continues with detailed device information...]

[+] Results saved to: network_scan_20260206_143045.txt

Scan completed in 182.45 seconds
```

---

**You're all set! Happy scanning! 🔍**
