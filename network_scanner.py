#!/usr/bin/env python3
"""
Network Scanner - Detect devices and web services on local network
Cross-platform support for Windows, Linux, and macOS
"""

import subprocess
import platform
import socket
import re
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import time
import sys

# MAC vendor OUI database (first 3 bytes of MAC address)
MAC_VENDORS = {
    '00:0C:29': 'VMware',
    '00:50:56': 'VMware',
    '00:1C:42': 'Parallels',
    '08:00:27': 'VirtualBox',
    '00:15:5D': 'Microsoft Hyper-V',
    '00:03:FF': 'Microsoft',
    '00:0D:3A': 'Microsoft',
    '00:12:5A': 'Microsoft',
    'DC:A6:32': 'Raspberry Pi',
    'B8:27:EB': 'Raspberry Pi',
    'E4:5F:01': 'Raspberry Pi',
    '28:CD:C1': 'Raspberry Pi',
    '00:1B:63': 'Apple',
    '00:03:93': 'Apple',
    '00:0A:27': 'Apple',
    '00:0A:95': 'Apple',
    '00:0D:93': 'Apple',
    '00:14:51': 'Apple',
    '00:16:CB': 'Apple',
    '00:17:F2': 'Apple',
    '00:19:E3': 'Apple',
    '00:1B:63': 'Apple',
    '00:1C:B3': 'Apple',
    '00:1D:4F': 'Apple',
    '00:1E:52': 'Apple',
    '00:1F:5B': 'Apple',
    '00:1F:F3': 'Apple',
    '00:21:E9': 'Apple',
    '00:22:41': 'Apple',
    '00:23:12': 'Apple',
    '00:23:32': 'Apple',
    '00:23:6C': 'Apple',
    '00:23:DF': 'Apple',
    '00:24:36': 'Apple',
    '00:25:00': 'Apple',
    '00:25:4B': 'Apple',
    '00:25:BC': 'Apple',
    '00:26:08': 'Apple',
    '00:26:4A': 'Apple',
    '00:26:B0': 'Apple',
    '00:26:BB': 'Apple',
    '04:0C:CE': 'Apple',
    '04:15:52': 'Apple',
    '04:26:65': 'Apple',
    '04:54:53': 'Apple',
    '08:66:98': 'Apple',
    '08:70:45': 'Apple',
    '0C:3E:9F': 'Apple',
    '0C:4D:E9': 'Apple',
    '0C:74:C2': 'Apple',
    '10:40:F3': 'Apple',
    '10:9A:DD': 'Apple',
    '10:DD:B1': 'Apple',
    '14:10:9F': 'Apple',
    '14:5A:05': 'Apple',
    '14:8F:C6': 'Apple',
    '14:BD:61': 'Apple',
    '18:34:51': 'Apple',
    '18:3D:A2': 'Apple',
    '18:E7:F4': 'Apple',
    '18:EE:69': 'Apple',
    '1C:AB:A7': 'Apple',
    '20:3C:AE': 'Apple',
    '20:7D:74': 'Apple',
    '20:AB:37': 'Apple',
    '20:C9:D0': 'Apple',
    '24:A0:74': 'Apple',
    '24:AB:81': 'Apple',
    '28:37:37': 'Apple',
    '28:6A:BA': 'Apple',
    '28:A0:2B': 'Apple',
    '28:E1:4C': 'Apple',
    '28:E7:CF': 'Apple',
    '2C:1F:23': 'Apple',
    '2C:33:61': 'Apple',
    '2C:B4:3A': 'Apple',
    '30:35:AD': 'Apple',
    '30:90:AB': 'Apple',
    '34:15:9E': 'Apple',
    '34:36:3B': 'Apple',
    '34:51:8A': 'Apple',
    '34:A3:95': 'Apple',
    '38:0F:4A': 'Apple',
    '3C:07:54': 'Apple',
    '3C:15:C2': 'Apple',
    '40:30:04': 'Apple',
    '40:33:1A': 'Apple',
    '40:6C:8F': 'Apple',
    '40:A6:D9': 'Apple',
    '40:CB:C0': 'Apple',
    '44:2A:60': 'Apple',
    '44:D8:84': 'Apple',
    '48:43:7C': 'Apple',
    '48:60:BC': 'Apple',
    '48:74:6E': 'Apple',
    '48:A1:95': 'Apple',
    '48:D7:05': 'Apple',
    '4C:57:CA': 'Apple',
    '4C:74:BF': 'Apple',
    '4C:8D:79': 'Apple',
    '50:EA:D6': 'Apple',
    '54:26:96': 'Apple',
    '54:72:4F': 'Apple',
    '54:AE:27': 'Apple',
    '54:E4:3A': 'Apple',
    '58:55:CA': 'Apple',
    '5C:59:48': 'Apple',
    '5C:95:AE': 'Apple',
    '5C:F9:38': 'Apple',
    '60:33:4B': 'Apple',
    '60:69:44': 'Apple',
    '60:C5:47': 'Apple',
    '60:F8:1D': 'Apple',
    '60:FA:CD': 'Apple',
    '60:FB:42': 'Apple',
    '64:20:0C': 'Apple',
    '64:76:BA': 'Apple',
    '64:9A:BE': 'Apple',
    '64:A3:CB': 'Apple',
    '64:B9:E8': 'Apple',
    '68:5B:35': 'Apple',
    '68:96:7B': 'Apple',
    '68:9C:70': 'Apple',
    '68:A8:6D': 'Apple',
    '68:D9:3C': 'Apple',
    '6C:40:08': 'Apple',
    '6C:70:9F': 'Apple',
    '6C:94:66': 'Apple',
    '6C:96:CF': 'Apple',
    '70:11:24': 'Apple',
    '70:3E:AC': 'Apple',
    '70:73:CB': 'Apple',
    '70:CD:60': 'Apple',
    '74:E1:B6': 'Apple',
    '74:E2:F5': 'Apple',
    '78:31:C1': 'Apple',
    '78:7B:8A': 'Apple',
    '78:A3:E4': 'Apple',
    '78:CA:39': 'Apple',
    '78:D7:5F': 'Apple',
    '7C:01:91': 'Apple',
    '7C:11:BE': 'Apple',
    '7C:6D:62': 'Apple',
    '7C:C3:A1': 'Apple',
    '7C:D1:C3': 'Apple',
    '7C:F0:5F': 'Apple',
    '80:49:71': 'Apple',
    '80:92:9F': 'Apple',
    '80:BE:05': 'Apple',
    '80:E6:50': 'Apple',
    '84:38:35': 'Apple',
    '84:85:06': 'Apple',
    '84:89:AD': 'Apple',
    '84:FC:FE': 'Apple',
    '88:63:DF': 'Apple',
    '88:66:5A': 'Apple',
    '88:C6:63': 'Apple',
    '8C:00:6D': 'Apple',
    '8C:29:37': 'Apple',
    '8C:58:77': 'Apple',
    '8C:7C:92': 'Apple',
    '8C:85:90': 'Apple',
    '90:27:E4': 'Apple',
    '90:72:40': 'Apple',
    '90:84:0D': 'Apple',
    '90:B0:ED': 'Apple',
    '90:B9:31': 'Apple',
    '94:E9:6A': 'Apple',
    '98:01:A7': 'Apple',
    '98:03:D8': 'Apple',
    '98:5A:EB': 'Apple',
    '98:B8:E3': 'Apple',
    '98:CA:33': 'Apple',
    '98:D6:BB': 'Apple',
    '98:E0:D9': 'Apple',
    '98:F0:AB': 'Apple',
    '98:FE:94': 'Apple',
    '9C:04:EB': 'Apple',
    '9C:20:7B': 'Apple',
    '9C:35:5B': 'Apple',
    '9C:84:BF': 'Apple',
    '9C:FC:E8': 'Apple',
    'A0:18:28': 'Apple',
    'A0:99:9B': 'Apple',
    'A4:31:35': 'Apple',
    'A4:5E:60': 'Apple',
    'A4:67:06': 'Apple',
    'A4:83:E7': 'Apple',
    'A4:B1:97': 'Apple',
    'A4:C3:61': 'Apple',
    'A4:D1:8C': 'Apple',
    'A8:20:66': 'Apple',
    'A8:5B:78': 'Apple',
    'A8:66:7F': 'Apple',
    'A8:86:DD': 'Apple',
    'A8:96:8A': 'Apple',
    'A8:BB:CF': 'Apple',
    'AC:1F:74': 'Apple',
    'AC:3C:0B': 'Apple',
    'AC:61:EA': 'Apple',
    'AC:87:A3': 'Apple',
    'AC:BC:32': 'Apple',
    'AC:CF:5C': 'Apple',
    'AC:DE:48': 'Apple',
    'AC:FD:CE': 'Apple',
    'B0:34:95': 'Apple',
    'B0:65:BD': 'Apple',
    'B0:9F:BA': 'Apple',
    'B4:18:D1': 'Apple',
    'B4:8B:19': 'Apple',
    'B4:F0:AB': 'Apple',
    'B4:F6:1C': 'Apple',
    'B8:09:8A': 'Apple',
    'B8:17:C2': 'Apple',
    'B8:41:A4': 'Apple',
    'B8:53:AC': 'Apple',
    'B8:63:4D': 'Apple',
    'B8:78:2E': 'Apple',
    'B8:8D:12': 'Apple',
    'B8:C1:11': 'Apple',
    'B8:E8:56': 'Apple',
    'B8:F6:B1': 'Apple',
    'BC:3B:AF': 'Apple',
    'BC:52:B7': 'Apple',
    'BC:67:1C': 'Apple',
    'BC:9F:EF': 'Apple',
    'BC:D0:74': 'Apple',
    'BC:EC:5D': 'Apple',
    'C0:63:94': 'Apple',
    'C0:84:7D': 'Apple',
    'C0:CC:F8': 'Apple',
    'C0:D0:12': 'Apple',
    'C4:2C:03': 'Apple',
    'C8:2A:14': 'Apple',
    'C8:33:4B': 'Apple',
    'C8:69:CD': 'Apple',
    'C8:6F:1D': 'Apple',
    'C8:B5:B7': 'Apple',
    'C8:BC:C8': 'Apple',
    'C8:E0:EB': 'Apple',
    'CC:08:8D': 'Apple',
    'CC:25:EF': 'Apple',
    'CC:29:F5': 'Apple',
    'CC:78:5F': 'Apple',
    'D0:03:4B': 'Apple',
    'D0:25:98': 'Apple',
    'D0:81:7A': 'Apple',
    'D0:A6:37': 'Apple',
    'D0:C5:F3': 'Apple',
    'D0:E1:40': 'Apple',
    'D4:61:9D': 'Apple',
    'D4:9A:20': 'Apple',
    'D4:A3:3D': 'Apple',
    'D8:00:4D': 'Apple',
    'D8:1C:79': 'Apple',
    'D8:30:62': 'Apple',
    'D8:96:95': 'Apple',
    'D8:A2:5E': 'Apple',
    'D8:BB:2C': 'Apple',
    'D8:CF:9C': 'Apple',
    'DC:2B:2A': 'Apple',
    'DC:2B:61': 'Apple',
    'DC:37:18': 'Apple',
    'DC:3B:14': 'Apple',
    'DC:86:D8': 'Apple',
    'DC:9B:9C': 'Apple',
    'E0:05:C5': 'Apple',
    'E0:33:8E': 'Apple',
    'E0:66:78': 'Apple',
    'E0:AC:CB': 'Apple',
    'E0:B5:2D': 'Apple',
    'E0:B9:BA': 'Apple',
    'E0:C7:67': 'Apple',
    'E0:F5:C6': 'Apple',
    'E0:F8:47': 'Apple',
    'E4:25:E7': 'Apple',
    'E4:8B:7F': 'Apple',
    'E4:9A:79': 'Apple',
    'E4:CE:8F': 'Apple',
    'E8:04:0B': 'Apple',
    'E8:06:88': 'Apple',
    'E8:80:2E': 'Apple',
    'E8:8D:28': 'Apple',
    'EC:35:86': 'Apple',
    'EC:85:2F': 'Apple',
    'F0:18:98': 'Apple',
    'F0:24:75': 'Apple',
    'F0:98:9D': 'Apple',
    'F0:B4:79': 'Apple',
    'F0:CB:A1': 'Apple',
    'F0:D1:A9': 'Apple',
    'F0:DB:E2': 'Apple',
    'F0:DC:E2': 'Apple',
    'F0:F6:1C': 'Apple',
    'F4:0F:24': 'Apple',
    'F4:1B:A1': 'Apple',
    'F4:37:B7': 'Apple',
    'F4:5C:89': 'Apple',
    'F4:F1:5A': 'Apple',
    'F4:F9:51': 'Apple',
    'F8:1E:DF': 'Apple',
    'F8:27:93': 'Apple',
    'F8:95:C7': 'Apple',
    'FC:25:3F': 'Apple',
    'FC:E9:98': 'Apple',
    'FC:FC:48': 'Apple',
    '00:04:20': 'Cisco',
    '00:0B:45': 'Cisco',
    '00:0C:30': 'Cisco',
    '00:11:92': 'Cisco',
    '00:13:C4': 'Cisco',
    '00:15:2B': 'Cisco',
    '00:17:59': 'Cisco',
    '00:19:07': 'Cisco',
    '00:1A:A1': 'Cisco',
    '00:1B:0D': 'Cisco',
    '00:1C:0F': 'Cisco',
    '00:1D:71': 'Cisco',
    '00:1E:13': 'Cisco',
    '00:1F:26': 'Cisco',
    '00:21:A0': 'Cisco',
    '00:22:55': 'Cisco',
    '00:23:04': 'Cisco',
    '00:24:13': 'Cisco',
    '00:25:45': 'Cisco',
    '00:26:0A': 'Cisco',
    '00:26:51': 'Cisco',
    '00:40:96': 'Cisco',
    '00:60:2F': 'Cisco',
    '00:90:0C': 'Cisco',
    '00:D0:06': 'Cisco',
    '04:C5:A4': 'Cisco',
    '04:DA:D2': 'Cisco',
    '08:00:07': 'Cisco',
    '08:17:35': 'Cisco',
    '08:96:AD': 'Cisco',
    '0C:68:03': 'Cisco',
    '10:05:CA': 'Cisco',
    '10:8C:CF': 'Cisco',
    '18:8B:9D': 'Cisco',
    '1C:DF:0F': 'Cisco',
    '20:37:06': 'Cisco',
    '28:94:0F': 'Cisco',
    '30:37:A6': 'Cisco',
    '34:A8:4E': 'Cisco',
    '40:55:39': 'Cisco',
    '48:0E:EC': 'Cisco',
    '50:06:04': 'Cisco',
    '50:3D:E5': 'Cisco',
    '54:78:1A': 'Cisco',
    '58:0A:20': 'Cisco',
    '5C:50:15': 'Cisco',
    '5C:83:8F': 'Cisco',
    '60:73:5C': 'Cisco',
    '64:00:F1': 'Cisco',
    '64:12:25': 'Cisco',
    '64:9E:F3': 'Cisco',
    '68:BD:AB': 'Cisco',
    '6C:99:89': 'Cisco',
    '70:CA:9B': 'Cisco',
    '70:DB:98': 'Cisco',
    '74:26:AC': 'Cisco',
    '74:A0:2F': 'Cisco',
    '78:DA:6E': 'Cisco',
    '7C:69:F6': 'Cisco',
    '80:E0:1D': 'Cisco',
    '84:78:AC': 'Cisco',
    '88:43:E1': 'Cisco',
    '88:90:8D': 'Cisco',
    '8C:B6:4F': 'Cisco',
    '90:E9:5E': 'Cisco',
    '98:FC:11': 'Cisco',
    'A0:3D:6F': 'Cisco',
    'A0:EC:F9': 'Cisco',
    'A4:4C:11': 'Cisco',
    'A4:93:4C': 'Cisco',
    'B0:7D:47': 'Cisco',
    'B4:14:89': 'Cisco',
    'B8:38:61': 'Cisco',
    'BC:16:F5': 'Cisco',
    'C0:67:AF': 'Cisco',
    'C4:64:13': 'Cisco',
    'C8:00:84': 'Cisco',
    'C8:F9:F9': 'Cisco',
    'CC:D8:C1': 'Cisco',
    'D0:57:4C': 'Cisco',
    'D4:A0:2A': 'Cisco',
    'D8:B1:90': 'Cisco',
    'DC:7B:94': 'Cisco',
    'E0:55:3D': 'Cisco',
    'E4:C7:22': 'Cisco',
    'E8:04:62': 'Cisco',
    'E8:BA:70': 'Cisco',
    'EC:44:76': 'Cisco',
    'F0:25:72': 'Cisco',
    'F0:7F:06': 'Cisco',
    'F4:AC:C1': 'Cisco',
    'F8:66:F2': 'Cisco',
    'F8:C2:88': 'Cisco',
    'FC:5B:39': 'Cisco',
    '00:0F:B5': 'Netgear',
    '00:14:6C': 'Netgear',
    '00:18:4D': 'Netgear',
    '00:1B:2F': 'Netgear',
    '00:1E:2A': 'Netgear',
    '00:1F:33': 'Netgear',
    '00:22:3F': 'Netgear',
    '00:24:B2': 'Netgear',
    '00:26:F2': 'Netgear',
    '00:8E:F2': 'Netgear',
    '00:C0:02': 'Netgear',
    '04:A1:51': 'Netgear',
    '08:02:8E': 'Netgear',
    '08:BD:43': 'Netgear',
    '10:0D:7F': 'Netgear',
    '10:DA:43': 'Netgear',
    '20:0C:C8': 'Netgear',
    '20:4E:7F': 'Netgear',
    '28:C6:8E': 'Netgear',
    '2C:30:33': 'Netgear',
    '30:46:9A': 'Netgear',
    '40:0D:10': 'Netgear',
    '44:94:FC': 'Netgear',
    '4C:60:DE': 'Netgear',
    '74:44:01': 'Netgear',
    '84:1B:5E': 'Netgear',
    '9C:1C:12': 'Netgear',
    'A0:21:B7': 'Netgear',
    'A0:40:A0': 'Netgear',
    'A4:2B:8C': 'Netgear',
    'C0:3F:0E': 'Netgear',
    'C4:04:15': 'Netgear',
    'CC:40:D0': 'Netgear',
    'E0:46:EE': 'Netgear',
    'E0:91:F5': 'Netgear',
    '00:07:7D': 'D-Link',
    '00:0D:88': 'D-Link',
    '00:11:95': 'D-Link',
    '00:13:46': 'D-Link',
    '00:15:E9': 'D-Link',
    '00:17:9A': 'D-Link',
    '00:19:5B': 'D-Link',
    '00:1B:11': 'D-Link',
    '00:1C:F0': 'D-Link',
    '00:1E:58': 'D-Link',
    '00:21:91': 'D-Link',
    '00:22:B0': 'D-Link',
    '00:24:01': 'D-Link',
    '00:26:5A': 'D-Link',
    '14:D6:4D': 'D-Link',
    '1C:7E:E5': 'D-Link',
    '28:10:7B': 'D-Link',
    '34:08:04': 'D-Link',
    '5C:D9:98': 'D-Link',
    '78:54:2E': 'D-Link',
    '78:CD:8E': 'D-Link',
    '90:94:E4': 'D-Link',
    'B8:A3:86': 'D-Link',
    'C0:A0:BB': 'D-Link',
    'C8:BE:19': 'D-Link',
    'CC:B2:55': 'D-Link',
    'F0:7D:68': 'D-Link',
    '00:0E:2E': 'TP-Link',
    '00:27:19': 'TP-Link',
    '04:95:E6': 'TP-Link',
    '0C:80:63': 'TP-Link',
    '10:FE:ED': 'TP-Link',
    '14:CF:92': 'TP-Link',
    '18:A6:F7': 'TP-Link',
    '1C:3B:F3': 'TP-Link',
    '20:F4:1B': 'TP-Link',
    '24:A4:3C': 'TP-Link',
    '28:2C:B2': 'TP-Link',
    '2C:30:33': 'TP-Link',
    '30:B5:C2': 'TP-Link',
    '38:D5:47': 'TP-Link',
    '44:32:C8': 'TP-Link',
    '50:C7:BF': 'TP-Link',
    '54:A5:1B': 'TP-Link',
    '5C:E9:1E': 'TP-Link',
    '60:E3:27': 'TP-Link',
    '64:66:B3': 'TP-Link',
    '68:1C:A2': 'TP-Link',
    '70:4F:57': 'TP-Link',
    '74:DA:88': 'TP-Link',
    '7C:8B:CA': 'TP-Link',
    '84:16:F9': 'TP-Link',
    '88:D7:F6': 'TP-Link',
    '8C:A6:DF': 'TP-Link',
    '90:F6:52': 'TP-Link',
    '98:25:4A': 'TP-Link',
    '98:DE:D0': 'TP-Link',
    '9C:A2:F4': 'TP-Link',
    'A0:F3:C1': 'TP-Link',
    'A4:2B:B0': 'TP-Link',
    'AC:15:A2': 'TP-Link',
    'AC:84:C6': 'TP-Link',
    'B0:4E:26': 'TP-Link',
    'B0:95:75': 'TP-Link',
    'B0:BE:76': 'TP-Link',
    'C0:4A:00': 'TP-Link',
    'C4:6E:1F': 'TP-Link',
    'C8:3A:35': 'TP-Link',
    'D4:6E:0E': 'TP-Link',
    'D8:0D:17': 'TP-Link',
    'E8:48:B8': 'TP-Link',
    'EC:08:6B': 'TP-Link',
    'EC:41:18': 'TP-Link',
    'F4:EC:38': 'TP-Link',
    'F4:F2:6D': 'TP-Link',
    'FC:EC:DA': 'TP-Link',
    '00:13:10': 'Linksys',
    '00:14:BF': 'Linksys',
    '00:16:B6': 'Linksys',
    '00:18:39': 'Linksys',
    '00:18:F8': 'Linksys',
    '00:1A:70': 'Linksys',
    '00:1D:7E': 'Linksys',
    '00:1E:E5': 'Linksys',
    '00:21:29': 'Linksys',
    '00:22:6B': 'Linksys',
    '00:23:69': 'Linksys',
    '00:25:9C': 'Linksys',
    '08:86:3B': 'Linksys',
    '10:BF:48': 'Linksys',
    '14:91:82': 'Linksys',
    '20:AA:4B': 'Linksys',
    '30:23:03': 'Linksys',
    '48:F8:B3': 'Linksys',
    '58:6D:8F': 'Linksys',
    '5C:35:3B': 'Linksys',
    '68:7F:74': 'Linksys',
    '94:10:3E': 'Linksys',
    'C0:56:27': 'Linksys',
    'C8:D7:19': 'Linksys',
    'E8:9F:80': 'Linksys',
    '00:11:50': 'Asus',
    '00:15:F2': 'Asus',
    '00:17:31': 'Asus',
    '00:19:DB': 'Asus',
    '00:1B:FC': 'Asus',
    '00:1E:8C': 'Asus',
    '00:22:15': 'Asus',
    '00:23:54': 'Asus',
    '00:24:8C': 'Asus',
    '00:26:18': 'Asus',
    '04:D4:C4': 'Asus',
    '08:60:6E': 'Asus',
    '08:62:66': 'Asus',
    '10:BF:48': 'Asus',
    '10:C3:7B': 'Asus',
    '14:DD:A9': 'Asus',
    '1C:87:2C': 'Asus',
    '2C:4D:54': 'Asus',
    '30:5A:3A': 'Asus',
    '38:2C:4A': 'Asus',
    '40:16:7E': 'Asus',
    '40:16:9F': 'Asus',
    '50:46:5D': 'Asus',
    '54:A0:50': 'Asus',
    '60:45:CB': 'Asus',
    '74:D0:2B': 'Asus',
    '78:24:AF': 'Asus',
    '88:D7:F6': 'Asus',
    '9C:5C:8E': 'Asus',
    'AC:22:0B': 'Asus',
    'AC:9E:17': 'Asus',
    'B0:6E:BF': 'Asus',
    'BC:EE:7B': 'Asus',
    'D0:17:C2': 'Asus',
    'E0:3F:49': 'Asus',
    'F4:6D:04': 'Asus',
    'F8:32:E4': 'Asus',
    '00:09:5B': 'Synology',
    '00:11:32': 'Synology',
    '00:11:32': 'Synology',
    '28:39:5E': 'Google',
    '3C:5A:B4': 'Google',
    '54:60:09': 'Google',
    '68:9E:19': 'Google',
    '6C:AD:F8': 'Google',
    '74:E5:43': 'Google',
    '80:1F:12': 'Google',
    '84:1B:5D': 'Google',
    '98:EE:CB': 'Google',
    'A4:77:33': 'Google',
    'B4:F6:2A': 'Google',
    'C0:91:34': 'Google',
    'CC:3D:82': 'Google',
    'D8:6C:63': 'Google',
    'F4:F5:D8': 'Google',
    'F8:8F:CA': 'Google',
    '00:0A:F7': 'Broadcom',
    '00:10:18': 'Broadcom',
    '00:11:D8': 'Broadcom',
    '00:14:A4': 'Broadcom',
    '00:17:C2': 'Broadcom',
    '00:1A:11': 'Broadcom',
    '00:1C:C0': 'Broadcom',
    '00:1F:1F': 'Broadcom',
    '00:21:D8': 'Broadcom',
    '00:90:4C': 'Broadcom',
    '00:E0:52': 'Broadcom',
    '3C:D9:2B': 'Broadcom',
    '54:E0:32': 'Broadcom',
    '84:EB:18': 'Broadcom',
    'B8:AE:ED': 'Broadcom',
    'BC:EE:7B': 'Broadcom',
    'F8:1A:67': 'Broadcom',
    '00:11:D9': 'Samsung',
    '00:12:47': 'Samsung',
    '00:12:FB': 'Samsung',
    '00:13:77': 'Samsung',
    '00:15:99': 'Samsung',
    '00:15:B9': 'Samsung',
    '00:16:32': 'Samsung',
    '00:16:6B': 'Samsung',
    '00:16:6C': 'Samsung',
    '00:17:C9': 'Samsung',
    '00:17:D5': 'Samsung',
    '00:18:AF': 'Samsung',
    '00:1A:8A': 'Samsung',
    '00:1B:98': 'Samsung',
    '00:1C:43': 'Samsung',
    '00:1D:25': 'Samsung',
    '00:1D:F6': 'Samsung',
    '00:1E:7D': 'Samsung',
    '00:1E:E1': 'Samsung',
    '00:1E:E2': 'Samsung',
    '00:1F:CD': 'Samsung',
    '00:21:19': 'Samsung',
    '00:21:4C': 'Samsung',
    '00:21:D1': 'Samsung',
    '00:21:D2': 'Samsung',
    '00:23:39': 'Samsung',
    '00:23:99': 'Samsung',
    '00:23:D6': 'Samsung',
    '00:23:D7': 'Samsung',
    '00:24:54': 'Samsung',
    '00:24:90': 'Samsung',
    '00:24:91': 'Samsung',
    '00:24:E9': 'Samsung',
    '00:25:38': 'Samsung',
    '00:25:66': 'Samsung',
    '00:25:67': 'Samsung',
    '00:26:37': 'Samsung',
    '00:E0:64': 'Samsung',
    '04:18:0F': 'Samsung',
    '04:FE:31': 'Samsung',
    '08:08:C2': 'Samsung',
    '08:37:3D': 'Samsung',
    '08:D4:2B': 'Samsung',
    '08:EC:A9': 'Samsung',
    '0C:14:20': 'Samsung',
    '0C:89:10': 'Samsung',
    '10:1D:C0': 'Samsung',
    '10:30:47': 'Samsung',
    '10:77:B1': 'Samsung',
    '14:49:E0': 'Samsung',
    '14:7D:C5': 'Samsung',
    '14:A5:1A': 'Samsung',
    '18:3A:2D': 'Samsung',
    '18:3F:47': 'Samsung',
    '18:4F:32': 'Samsung',
    '18:67:B0': 'Samsung',
    '18:E2:C2': 'Samsung',
    '1C:62:B8': 'Samsung',
    '1C:66:AA': 'Samsung',
    '20:13:E0': 'Samsung',
    '20:64:32': 'Samsung',
    '20:6E:9C': 'Samsung',
    '20:A5:BF': 'Samsung',
    '24:0B:88': 'Samsung',
    '28:63:36': 'Samsung',
    '28:BA:B5': 'Samsung',
    '2C:44:01': 'Samsung',
    '2C:44:FD': 'Samsung',
    '30:19:66': 'Samsung',
    '30:CD:A7': 'Samsung',
    '34:23:BA': 'Samsung',
    '34:AA:8B': 'Samsung',
    '38:0A:94': 'Samsung',
    '38:AA:3C': 'Samsung',
    '3C:62:00': 'Samsung',
    '40:0E:85': 'Samsung',
    '40:5D:82': 'Samsung',
    '40:B8:9A': 'Samsung',
    '44:4E:1A': 'Samsung',
    '44:6D:6C': 'Samsung',
    '44:D6:E1': 'Samsung',
    '48:5A:3F': 'Samsung',
    '4C:BC:42': 'Samsung',
    '50:32:37': 'Samsung',
    '50:C8:E5': 'Samsung',
    '50:CC:F8': 'Samsung',
    '54:88:0E': 'Samsung',
    '58:8B:F3': 'Samsung',
    '5C:0A:5B': 'Samsung',
    '5C:0E:8B': 'Samsung',
    '5C:3C:27': 'Samsung',
    '5C:F8:A1': 'Samsung',
    '60:6B:BD': 'Samsung',
    '60:99:D8': 'Samsung',
    '64:B3:10': 'Samsung',
    '64:B8:53': 'Samsung',
    '68:14:01': 'Samsung',
    '68:EB:AE': 'Samsung',
    '6C:2F:2C': 'Samsung',
    '6C:50:4D': 'Samsung',
    '70:2A:D5': 'Samsung',
    '70:5A:0F': 'Samsung',
    '70:B3:D5': 'Samsung',
    '74:45:8A': 'Samsung',
    '74:DE:2B': 'Samsung',
    '78:1F:DB': 'Samsung',
    '78:25:AD': 'Samsung',
    '78:40:E4': 'Samsung',
    '78:47:1D': 'Samsung',
    '78:59:5E': 'Samsung',
    '78:A8:73': 'Samsung',
    '78:AB:BB': 'Samsung',
    '78:D6:F0': 'Samsung',
    '78:F7:BE': 'Samsung',
    '7C:11:CB': 'Samsung',
    '7C:61:66': 'Samsung',
    '7C:C5:37': 'Samsung',
    '7C:F8:54': 'Samsung',
    '80:18:A7': 'Samsung',
    '84:25:DB': 'Samsung',
    '84:38:38': 'Samsung',
    '84:A4:66': 'Samsung',
    '88:30:8A': 'Samsung',
    '88:32:9B': 'Samsung',
    '88:36:6C': 'Samsung',
    '88:79:7E': 'Samsung',
    '88:E8:7F': 'Samsung',
    '8C:0E:E3': 'Samsung',
    '8C:77:12': 'Samsung',
    '90:18:7C': 'Samsung',
    '94:25:33': 'Samsung',
    '94:35:0A': 'Samsung',
    '94:63:D1': 'Samsung',
    '98:52:B1': 'Samsung',
    '9C:02:98': 'Samsung',
    '9C:3A:AF': 'Samsung',
    '9C:3D:CF': 'Samsung',
    'A0:07:98': 'Samsung',
    'A0:21:95': 'Samsung',
    'A0:75:91': 'Samsung',
    'A0:82:1F': 'Samsung',
    'A0:B4:A5': 'Samsung',
    'A4:EB:D3': 'Samsung',
    'A8:06:00': 'Samsung',
    'A8:F2:74': 'Samsung',
    'AC:36:13': 'Samsung',
    'AC:5A:14': 'Samsung',
    'AC:5F:3E': 'Samsung',
    'AC:7F:3E': 'Samsung',
    'B0:72:BF': 'Samsung',
    'B0:C4:E7': 'Samsung',
    'B0:DF:3A': 'Samsung',
    'B4:07:F9': 'Samsung',
    'B4:79:A7': 'Samsung',
    'B8:5E:7B': 'Samsung',
    'BC:14:85': 'Samsung',
    'BC:20:BA': 'Samsung',
    'BC:72:B1': 'Samsung',
    'BC:8C:CD': 'Samsung',
    'BC:F5:AC': 'Samsung',
    'C0:65:99': 'Samsung',
    'C0:71:FE': 'Samsung',
    'C0:97:27': 'Samsung',
    'C0:BD:D1': 'Samsung',
    'C4:42:02': 'Samsung',
    'C4:57:6E': 'Samsung',
    'C4:73:1E': 'Samsung',
    'C8:19:F7': 'Samsung',
    'C8:3E:99': 'Samsung',
    'C8:A8:23': 'Samsung',
    'CC:07:AB': 'Samsung',
    'CC:3A:61': 'Samsung',
    'CC:6E:A4': 'Samsung',
    'CC:FE:3C': 'Samsung',
    'D0:22:BE': 'Samsung',
    'D0:59:E4': 'Samsung',
    'D0:87:E2': 'Samsung',
    'D0:DF:C7': 'Samsung',
    'D4:87:D8': 'Samsung',
    'D4:E8:B2': 'Samsung',
    'D8:57:EF': 'Samsung',
    'D8:90:E8': 'Samsung',
    'DC:0B:1A': 'Samsung',
    'DC:66:72': 'Samsung',
    'DC:71:44': 'Samsung',
    'E4:32:CB': 'Samsung',
    'E4:40:E2': 'Samsung',
    'E4:92:FB': 'Samsung',
    'E4:B0:21': 'Samsung',
    'E4:C3:2A': 'Samsung',
    'E8:03:9A': 'Samsung',
    'E8:11:32': 'Samsung',
    'E8:50:8B': 'Samsung',
    'E8:E5:D6': 'Samsung',
    'EC:1D:8B': 'Samsung',
    'EC:9B:F3': 'Samsung',
    'F0:08:D1': 'Samsung',
    'F0:25:B7': 'Samsung',
    'F0:5A:09': 'Samsung',
    'F0:6B:CA': 'Samsung',
    'F4:09:D8': 'Samsung',
    'F4:0E:11': 'Samsung',
    'F4:7B:5E': 'Samsung',
    'F4:D9:FB': 'Samsung',
    'F8:04:2E': 'Samsung',
    'F8:D0:AC': 'Samsung',
    'FC:03:9F': 'Samsung',
    'FC:A1:3E': 'Samsung',
    'FC:C7:34': 'Samsung',
}


class NetworkScanner:
    """Cross-platform network scanner with web service detection"""
    
    def __init__(self):
        self.os_type = platform.system()
        self.devices = []
        self.local_ip = self._get_local_ip()
        self.network_range = self._get_network_range()
        
    def _get_local_ip(self) -> str:
        """Get the local IP address of this machine"""
        try:
            # Create a socket to find the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def _get_network_range(self) -> str:
        """Calculate the network range from local IP"""
        try:
            # Get network address (assumes /24 subnet)
            ip_parts = self.local_ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            return network
        except Exception:
            return "192.168.1.0/24"
    
    def _parse_arp_table(self) -> List[Dict[str, str]]:
        """Parse the system ARP table to get IP-MAC mappings"""
        devices = []
        
        try:
            if self.os_type == "Windows":
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                output = result.stdout
                
                # Parse Windows ARP output
                for line in output.split('\n'):
                    # Look for lines with IP and MAC
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})', line, re.IGNORECASE)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).upper().replace('-', ':')
                        devices.append({'ip': ip, 'mac': mac})
            
            else:  # Linux/macOS
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                output = result.stdout
                
                # Parse Unix-like ARP output
                for line in output.split('\n'):
                    # Look for patterns like: hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff
                    match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})', line, re.IGNORECASE)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).upper()
                        devices.append({'ip': ip, 'mac': mac})
        
        except Exception as e:
            print(f"Warning: Could not parse ARP table: {e}")
        
        return devices
    
    def _ping_host(self, ip: str) -> bool:
        """Ping a single host to check if it's alive"""
        try:
            if self.os_type == "Windows":
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '1000', ip],
                    capture_output=True,
                    timeout=2
                )
            else:  # Linux/macOS
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True,
                    timeout=2
                )
            return result.returncode == 0
        except Exception:
            return False
    
    def _get_mac_from_ip(self, ip: str) -> Optional[str]:
        """Get MAC address for a specific IP from ARP table"""
        try:
            # Ping first to populate ARP table
            self._ping_host(ip)
            time.sleep(0.1)
            
            if self.os_type == "Windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
                output = result.stdout
                match = re.search(r'([0-9a-f-]{17})', output, re.IGNORECASE)
                if match:
                    return match.group(1).upper().replace('-', ':')
            else:  # Linux/macOS
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=5)
                output = result.stdout
                match = re.search(r'([0-9a-f:]{17})', output, re.IGNORECASE)
                if match:
                    return match.group(1).upper()
        except Exception:
            pass
        return None
    
    def _identify_vendor(self, mac: str) -> str:
        """Identify device vendor from MAC address OUI"""
        if not mac or len(mac) < 8:
            return "Unknown"
        
        # Extract OUI (first 3 octets)
        oui = ':'.join(mac.split(':')[:3])
        
        # Check against known vendors
        vendor = MAC_VENDORS.get(oui, "Unknown")
        return vendor
    
    def _scan_network_range(self) -> List[str]:
        """Scan network range using ping sweep"""
        print(f"\n[*] Scanning network range: {self.network_range}")
        
        alive_hosts = []
        network = ipaddress.ip_network(self.network_range, strict=False)
        
        # Use ThreadPoolExecutor for parallel pinging
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {}
            for ip in network.hosts():
                ip_str = str(ip)
                futures[executor.submit(self._ping_host, ip_str)] = ip_str
            
            # Progress counter
            total = len(futures)
            completed = 0
            
            for future in as_completed(futures):
                completed += 1
                ip = futures[future]
                if completed % 10 == 0 or completed == total:
                    print(f"\r[*] Progress: {completed}/{total} hosts checked", end='', flush=True)
                
                try:
                    if future.result():
                        alive_hosts.append(ip)
                except Exception:
                    pass
        
        print(f"\n[+] Found {len(alive_hosts)} alive hosts")
        return alive_hosts
    
    def _check_web_service(self, ip: str, port: int) -> Optional[Dict[str, str]]:
        """Check if a web service is running on the given port"""
        protocols = ['http', 'https'] if port == 443 else ['http']
        
        for protocol in protocols:
            url = f"{protocol}://{ip}:{port}"
            try:
                response = requests.get(
                    url,
                    timeout=3,
                    verify=False,  # Ignore SSL certificate errors
                    allow_redirects=True
                )
                
                # Extract page title
                title = "No Title"
                if response.text:
                    title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        title = title_match.group(1).strip()[:100]  # Limit to 100 chars
                
                # Get server header
                server = response.headers.get('Server', 'Unknown')
                
                return {
                    'url': url,
                    'status': response.status_code,
                    'server': server,
                    'title': title
                }
            
            except requests.exceptions.SSLError:
                # Try HTTP if HTTPS fails
                continue
            except Exception:
                continue
        
        return None
    
    def _scan_ports_on_device(self, ip: str) -> List[Dict[str, str]]:
        """Scan common web ports on a device"""
        common_ports = [80, 443, 8080, 8000, 8443, 8888, 3000, 5000, 9090]
        web_services = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_web_service, ip, port): port for port in common_ports}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        web_services.append(result)
                except Exception:
                    pass
        
        return web_services
    
    def scan(self) -> List[Dict]:
        """Main scan function"""
        print("="*80)
        print("NETWORK SCANNER - Device and Web Service Detection")
        print("="*80)
        print(f"Local IP: {self.local_ip}")
        print(f"Network Range: {self.network_range}")
        print(f"OS: {self.os_type}")
        
        # Step 1: Get devices from ARP table
        print("\n[*] Step 1: Parsing ARP table...")
        arp_devices = self._parse_arp_table()
        print(f"[+] Found {len(arp_devices)} devices in ARP table")
        
        # Step 2: Ping sweep to find all alive hosts
        alive_hosts = self._scan_network_range()
        
        # Step 3: Combine results and get MAC addresses
        print("\n[*] Step 3: Resolving MAC addresses...")
        ip_mac_map = {d['ip']: d['mac'] for d in arp_devices}
        
        all_ips = set([d['ip'] for d in arp_devices] + alive_hosts)
        
        for ip in all_ips:
            if ip not in ip_mac_map:
                mac = self._get_mac_from_ip(ip)
                if mac:
                    ip_mac_map[ip] = mac
        
        # Step 4: Create device list with vendor info
        print("\n[*] Step 4: Identifying vendors...")
        for ip, mac in ip_mac_map.items():
            vendor = self._identify_vendor(mac)
            self.devices.append({
                'ip': ip,
                'mac': mac,
                'vendor': vendor,
                'web_services': []
            })
        
        # Sort by IP
        self.devices.sort(key=lambda x: [int(p) for p in x['ip'].split('.')])
        
        # Step 5: Scan for web services
        print(f"\n[*] Step 5: Scanning {len(self.devices)} devices for web services...")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for device in self.devices:
                futures[executor.submit(self._scan_ports_on_device, device['ip'])] = device
            
            completed = 0
            total = len(futures)
            
            for future in as_completed(futures):
                completed += 1
                device = futures[future]
                print(f"\r[*] Progress: {completed}/{total} devices scanned for web services", end='', flush=True)
                
                try:
                    web_services = future.result()
                    device['web_services'] = web_services
                except Exception:
                    pass
        
        print("\n")
        return self.devices
    
    def display_results(self):
        """Display scan results in a formatted table"""
        print("\n" + "="*80)
        print("SCAN RESULTS")
        print("="*80)
        
        print(f"\nTotal devices found: {len(self.devices)}")
        print(f"Devices with web services: {sum(1 for d in self.devices if d['web_services'])}")
        
        print("\n" + "-"*80)
        print(f"{'IP Address':<15} {'MAC Address':<18} {'Vendor':<20} {'Web Services'}")
        print("-"*80)
        
        for device in self.devices:
            ip = device['ip']
            mac = device['mac']
            vendor = device['vendor'][:19]  # Truncate long vendor names
            
            web_count = len(device['web_services'])
            web_info = f"{web_count} service(s)" if web_count > 0 else "None"
            
            print(f"{ip:<15} {mac:<18} {vendor:<20} {web_info}")
            
            # Display web service details
            for service in device['web_services']:
                print(f"  └─ {service['url']}")
                print(f"     Status: {service['status']} | Server: {service['server']}")
                print(f"     Title: {service['title']}")
        
        print("-"*80)
    
    def save_results(self, filename: Optional[str] = None):
        """Save results to a text file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}.txt"
        
        # Save to current directory (cross-platform)
        import os
        filepath = os.path.join(os.getcwd(), filename)
        
        with open(filepath, 'w') as f:
            f.write("="*80 + "\n")
            f.write("NETWORK SCAN REPORT\n")
            f.write("="*80 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Local IP: {self.local_ip}\n")
            f.write(f"Network Range: {self.network_range}\n")
            f.write(f"Operating System: {self.os_type}\n")
            f.write("\n")
            
            f.write(f"Total Devices Found: {len(self.devices)}\n")
            f.write(f"Devices with Web Services: {sum(1 for d in self.devices if d['web_services'])}\n")
            f.write("\n" + "="*80 + "\n\n")
            
            for i, device in enumerate(self.devices, 1):
                f.write(f"Device #{i}\n")
                f.write("-"*80 + "\n")
                f.write(f"IP Address:  {device['ip']}\n")
                f.write(f"MAC Address: {device['mac']}\n")
                f.write(f"Vendor:      {device['vendor']}\n")
                f.write(f"Web Services: {len(device['web_services'])}\n")
                
                if device['web_services']:
                    f.write("\nWeb Services:\n")
                    for service in device['web_services']:
                        f.write(f"  - URL: {service['url']}\n")
                        f.write(f"    Status Code: {service['status']}\n")
                        f.write(f"    Server: {service['server']}\n")
                        f.write(f"    Page Title: {service['title']}\n")
                        f.write("\n")
                
                f.write("\n")
        
        print(f"\n[+] Results saved to: {filepath}")
        return filepath


def main():
    """Main entry point"""
    print("\n" + "="*80)
    print(" "*20 + "NETWORK SCANNER v1.0")
    print(" "*15 + "Device & Web Service Discovery")
    print("="*80)
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Create scanner instance
    scanner = NetworkScanner()
    
    # Run the scan
    try:
        start_time = time.time()
        devices = scanner.scan()
        end_time = time.time()
        
        # Display results
        scanner.display_results()
        
        # Save results
        filepath = scanner.save_results()
        
        print(f"\nScan completed in {end_time - start_time:.2f} seconds")
        print(f"Results saved to: {filepath}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()