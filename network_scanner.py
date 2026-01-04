import socket
import ipaddress
import concurrent.futures
from datetime import datetime
import json
import subprocess
import platform
import re
import sys
import os
import ssl
import urllib.request
import urllib.error
import hashlib
from collections import defaultdict
import time

geteuid_func = getattr(os, 'geteuid', None)

def is_admin():
    """Check if script is running with admin privileges"""
    if platform.system().lower() == 'windows':
        try:
            subprocess.check_call(['net', 'session'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False
    else:
        if geteuid_func is not None:
            return geteuid_func() == 0
        else:
            return False

def get_local_ip():
    """Get the local IP address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_public_ip():
    """Get public IP address"""
    try:
        response = urllib.request.urlopen('https://api.ipify.org', timeout=3)
        return response.read().decode('utf-8')
    except:
        return "Unknown"

def get_network_interfaces():
    """Get all network interfaces"""
    interfaces = []
    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(['ipconfig', '/all'],
                                  capture_output=True,
                                  text=True,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            result = subprocess.run(['ifconfig'],
                                  capture_output=True,
                                  text=True)
        
        interfaces_text = result.stdout
        return interfaces_text[:500]  # First 500 chars
    except:
        return "Unable to fetch"

def refresh_arp_table(ip):
    """Ping device first to populate ARP table"""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        flags = subprocess.CREATE_NO_WINDOW if platform.system().lower() == 'windows' else 0
        subprocess.run(['ping', param, '1', '-w', '500', str(ip)],
                      stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL,
                      timeout=2,
                      creationflags=flags)
    except:
        pass

def get_mac_address_windows(ip):
    """Get MAC address on Windows using multiple methods"""
    mac = "Unknown"
    
    # Method 1: ARP command
    try:
        result = subprocess.run(['arp', '-a', ip],
                              capture_output=True,
                              text=True,
                              timeout=2,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        
        for line in result.stdout.split('\n'):
            if ip in line:
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                if mac_match:
                    mac = mac_match.group(0).replace('-', ':').upper()
                    return mac
    except:
        pass
    
    # Method 2: getmac command
    try:
        result = subprocess.run(['getmac', '/v', '/fo', 'csv'],
                              capture_output=True,
                              text=True,
                              timeout=3,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        
        for line in result.stdout.split('\n'):
            if ip in line:
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                if mac_match:
                    mac = mac_match.group(0).replace('-', ':').upper()
                    return mac
    except:
        pass
    
    # Method 3: nbtstat (for Windows devices)
    try:
        result = subprocess.run(['nbtstat', '-A', ip],
                              capture_output=True,
                              text=True,
                              timeout=3,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        
        mac_match = re.search(r'MAC Address = ([0-9A-F]{2}-){5}[0-9A-F]{2}', result.stdout)
        if mac_match:
            mac = mac_match.group(0).split('=')[1].strip().replace('-', ':')
            return mac
    except:
        pass
    
    return mac

def get_mac_address(ip):
    """Get MAC address with better detection"""
    refresh_arp_table(ip)
    
    if platform.system().lower() == 'windows':
        return get_mac_address_windows(ip)
    else:
        try:
            result = subprocess.run(['arp', '-n', ip],
                                  capture_output=True,
                                  text=True,
                                  timeout=2)
            
            for line in result.stdout.split('\n'):
                if ip in line:
                    mac_match = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', line)
                    if mac_match:
                        return mac_match.group(0).upper()
        except:
            pass
    
    return "Unknown"

def get_vendor_from_mac(mac):
    """Enhanced vendor detection with comprehensive database"""
    if mac == "Unknown" or mac == "N/A":
        return "Unknown"
    
    oui = mac.replace(':', '').replace('-', '')[:6].upper()
    
    vendors = {
        # Apple
        '001B63': 'Apple', '001451': 'Apple', '0019E3': 'Apple', '002312': 'Apple',
        '00254B': 'Apple', '002608': 'Apple', '0C74C2': 'Apple', '10DDB1': 'Apple',
        '3C2EF9': 'Apple', '4C74BF': 'Apple', '4CDD31': 'Apple', 'A4C361': 'Apple',
        'F0CBA1': 'Apple', 'F4F951': 'Apple', '64A5C3': 'Apple', '78A3E4': 'Apple',
        
        # Samsung
        '0015B9': 'Samsung', '001632': 'Samsung', '001D25': 'Samsung', '002566': 'Samsung',
        '34145F': 'Samsung', '3C5A37': 'Samsung', '5C0A5B': 'Samsung', '68DFDD': 'Samsung',
        'A093EB': 'Samsung', 'D85D4C': 'Samsung', 'E4B021': 'Samsung', 'EC9B2F': 'Samsung',
        '78BD3B': 'Samsung', '40163B': 'Samsung', '88329B': 'Samsung',
        
        # Google/Nest
        '001A11': 'Google', '3C5282': 'Google', '54A051': 'Google Nest', '2C3AE8': 'Google Nest',
        'F4F5D8': 'Google', '6C4B90': 'Google Chromecast', 'D0E140': 'Google', 'F8E4FB': 'Google',
        
        # Amazon
        '44650D': 'Amazon Echo/Fire', 'F81A67': 'Amazon Echo', 'FC65DE': 'Amazon',
        '6837E9': 'Amazon Fire TV', '00FC8B': 'Amazon', 'AC63BE': 'Amazon', 'CC9E00': 'Amazon',
        
        # Microsoft
        '001C0E': 'Microsoft', '00155D': 'Microsoft Hyper-V', '0050F2': 'Microsoft',
        '002248': 'Microsoft', '002586': 'Microsoft', '7C1E52': 'Microsoft', '00506C': 'Microsoft',
        '60EB69': 'Microsoft Xbox', '7CD1C3': 'Microsoft Xbox',
        
        # HP
        '001A4B': 'HP', '009C02': 'HP', '00A0C9': 'HP', '0C8DCB': 'HP',
        '0019BB': 'HP', 'DC2C6E': 'HP Printer', '1C:C1:DE': 'HP',
        
        # Dell
        '001C23': 'Dell', '002219': 'Dell', '0026B9': 'Dell', '5C5948': 'Dell',
        '84A938': 'Dell', 'B083FE': 'Dell', '18DB F2': 'Dell',
        
        # Cisco
        '0001C9': 'Cisco', '001D45': 'Cisco', '00216A': 'Cisco Router',
        '001DD8': 'Cisco', '1CE6C7': 'Cisco', '006400': 'Cisco',
        
        # TP-Link
        '001C0E': 'TP-Link', '1C3BF3': 'TP-Link', '2C3E0F': 'TP-Link',
        'E8DE27': 'TP-Link', '98DE5D': 'TP-Link', 'F4F26D': 'TP-Link',
        '50C7BF': 'TP-Link', 'EC0869': 'TP-Link',
        
        # Raspberry Pi
        'B827EB': 'Raspberry Pi', 'DCA632': 'Raspberry Pi', 'E45F01': 'Raspberry Pi',
        'DC3743': 'Raspberry Pi', '2841D8': 'Raspberry Pi',
        
        # Xiaomi
        '341299': 'Xiaomi', '50EC50': 'Xiaomi', '64B473': 'Xiaomi', '78023F': 'Xiaomi',
        '8CFABA': 'Xiaomi', 'CC2D83': 'Xiaomi', 'F4F5DB': 'Xiaomi', '04CF8C': 'Xiaomi',
        
        # Virtual Machines
        '00505': 'VMware', '005056': 'VMware', '000C29': 'VMware',
        '080027': 'VirtualBox', '525400': 'QEMU/KVM', '0A0027': 'VirtualBox',
        
        # Gaming & Entertainment
        '001F3B': 'Nintendo', '001F32': 'Nintendo Wii', '0009BF': 'Nintendo',
        '0023CC': 'Sony PlayStation', '7CC537': 'Sony PlayStation', '00D9D1': 'Sony PS4',
        
        # Networking
        '0024E4': 'Netgear', '20E52A': 'Netgear', '001E2A': 'Linksys',
        '00045A': 'Linksys', 'C0C1C0': 'Linksys', '00147A': 'D-Link',
        
        # Others
        '001E68': 'Roku', '00272D': 'Canon', '002583': 'Epson',
        '00044B': 'NVIDIA', '00259A': 'Asus', '0025D3': 'Asus',
    }
    
    return vendors.get(oui, f"Unknown Vendor ({oui[:4]}...)")

def get_os_guess(ttl):
    """Guess OS based on TTL value"""
    if ttl <= 64:
        return "Linux/Unix", "TTL <= 64"
    elif ttl <= 128:
        return "Windows", "TTL <= 128"
    else:
        return "Unknown", "TTL > 128"

def get_hostname(ip):
    """Get hostname and workgroup/domain"""
    hostname = "Unknown"
    workgroup = "N/A"
    
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except:
        pass
    
    # Attempt to get workgroup/domain (Windows specific)
    if platform.system().lower() == 'windows':
        try:
            result = subprocess.run(['nbtstat', '-A', ip],
                                  capture_output=True,
                                  text=True,
                                  timeout=1,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            
            for line in result.stdout.split('\n'):
                if 'Workgroup' in line or 'Domain' in line:
                    workgroup = line.split()[-1].strip()
                    break
        except:
            pass
            
    return hostname, workgroup

def scan_port(ip, port, timeout=0.5):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            service = socket.getservbyport(port)
            return {'port': port, 'status': 'open', 'service': service}
        else:
            return None
    except:
        return None

def scan_ports_enhanced(ip, quick=True):
    """Scan common or all ports with concurrency"""
    
    # Common ports for quick scan
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
    ]
    
    # All ports for full scan (0-1024 for now to keep it manageable in a quick demo)
    all_ports = list(range(1, 1025))
    
    ports_to_scan = common_ports if quick else all_ports
    
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, 0.5): port for port in ports_to_scan}
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)
                
    # Sort by port number
    open_ports.sort(key=lambda x: x['port'])
    
    # Add banner and risk info
    for port_info in open_ports:
        banner, version = get_banner(ip, port_info['port'])
        port_info['banner'] = banner
        port_info['version'] = version
        port_info['risk_level'] = assess_port_risk(port_info['port'], port_info['service'], banner)
        
    return open_ports

def get_banner(ip, port, timeout=1):
    """Get service banner from an open port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Use SSL for common secure ports
        if port == 443 or port == 993 or port == 995:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=ip)
            
        sock.connect((ip, port))
        
        # Send a simple request for common HTTP/FTP ports
        if port == 80 or port == 8080:
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        elif port == 21:
            pass  # FTP sends banner automatically
        elif port == 22:
            pass  # SSH sends banner automatically
        elif port == 25:
            pass  # SMTP sends banner
        elif port == 3306:
            pass  # MySQL sends version
        else:
            sock.send(b'\r\n\r\n')
        
        # Receive banner
        try:
            raw_banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
        except:
            raw_banner = ""
        
        sock.close()
        
        if raw_banner:
            # Clean banner
            banner = raw_banner.split('\n')[0][:100]
            
            # Extract version info
            version = extract_version(banner, port)
            
            return banner, version
        
        return "No banner", "Unknown"
    except:
        return "No banner", "Unknown"

def extract_version(banner, port):
    """Extract version information from banner"""
    banner_lower = banner.lower()
    
    # Common version patterns
    patterns = [
        r'apache[/\s]+([\d\.]+)',
        r'nginx[/\s]+([\d\.]+)',
        r'openssh[_/\s]+([\d\.]+)',
        r'microsoft[/\s]+iis[/\s]+([\d\.]+)',
        r'mysql[/\s]+([\d\.]+)',
        r'postgresql[/\s]+([\d\.]+)',
        r'(\d+\.\d+\.\d+)',  # Generic version
    ]
    
    for pattern in patterns:
        match = re.search(pattern, banner_lower)
        if match:
            return match.group(1) if len(match.groups()) > 0 else match.group(0)
    
    # Service-specific detection
    if 'ssh' in banner_lower:
        return "SSH Server"
    elif 'ftp' in banner_lower:
        return "FTP Server"
    elif 'smtp' in banner_lower:
        return "SMTP Server"
    
    return "Unknown"

def assess_port_risk(port, service, banner):
    """Assess security risk of open port"""
    high_risk_ports = [21, 23, 69, 135, 139, 445, 1433, 3389, 5900]
    medium_risk_ports = [22, 25, 110, 143, 3306, 5432, 8080, 8443]
    
    if port in high_risk_ports:
        return "HIGH"
    elif port in medium_risk_ports:
        return "MEDIUM"
    elif port == 80 or port == 443:
        return "LOW"
    else:
        return "INFO"

def get_http_info(ip, port=80):
    """Get HTTP server information"""
    try:
        url = f"http://{ip}:{port}/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        response = urllib.request.urlopen(req, timeout=3)
        
        headers = dict(response.headers)
        server = headers.get('Server', 'Unknown')
        powered_by = headers.get('X-Powered-By', 'Unknown')
        
        return {
            'server': server,
            'powered_by': powered_by,
            'status': response.status
        }
    except:
        return None

def get_device_type_enhanced(hostname, mac, vendor, open_ports, os_guess):
    """Ultra-enhanced device type detection"""
    hostname_lower = hostname.lower() if hostname != "Unknown" else ""
    
    # Comprehensive hostname patterns
    patterns = {
        'Mobile Phone': ['android', 'phone', 'mobile', 'galaxy', 'pixel', 'oneplus'],
        'iPhone/iPad': ['iphone', 'ipad', 'ios'],
        'Printer': ['printer', 'print', 'canon', 'epson', 'brother', 'xerox', 'ricoh'],
        'Router/Gateway': ['router', 'gateway', 'modem', 'att', 'comcast', 'verizon', 'spectrum'],
        'Desktop PC': ['desktop', 'pc', 'workstation'],
        'Laptop': ['laptop', 'notebook', 'thinkpad', 'macbook'],
        'Server': ['server', 'srv', 'host', 'node', 'vm'],
        'IP Camera': ['camera', 'cam', 'nvr', 'dvr', 'ipcam'],
        'Smart TV': ['tv', 'television', 'roku', 'firetv', 'appletv'],
        'Gaming Console': ['xbox', 'playstation', 'ps4', 'ps5', 'nintendo', 'switch'],
        'Smart Speaker': ['echo', 'alexa', 'nest', 'hub', 'assistant', 'homepod'],
        'NAS/Storage': ['nas', 'storage', 'synology', 'qnap', 'freenas'],
        'IoT Device': ['iot', 'smart', 'sensor', 'thermostat', 'bulb'],
        'Access Point': ['ap', 'wifi', 'wireless', 'ubiquiti', 'unifi'],
    }
    
    for device_type, keywords in patterns.items():
        if any(keyword in hostname_lower for keyword in keywords):
            return device_type
    
    # Vendor-based detection
    if 'Raspberry' in vendor:
        return "Raspberry Pi / SBC"
    elif 'Apple' in vendor:
        return "Apple Device"
    elif 'Samsung' in vendor:
        return "Samsung Device"
    elif 'Google' in vendor or 'Nest' in vendor:
        return "Google Device"
    elif 'Amazon' in vendor or 'Echo' in vendor:
        return "Amazon Device"
    elif 'Cisco' in vendor:
        return "Cisco Network Equipment"
    elif 'Printer' in vendor or 'HP' in vendor or 'Canon' in vendor:
        return "Printer"
    elif 'Xbox' in vendor or 'PlayStation' in vendor or 'Nintendo' in vendor:
        return "Gaming Console"
    elif 'VMware' in vendor or 'VirtualBox' in vendor or 'QEMU' in vendor:
        return "Virtual Machine"
    
    # Port-based detection
    if open_ports:
        port_nums = [p['port'] for p in open_ports]
        
        if 3389 in port_nums:
            return "Windows Computer (RDP)"
        elif 22 in port_nums and 80 in port_nums and 443 in port_nums:
            return "Linux Web Server"
        elif 445 in port_nums or 139 in port_nums:
            return "Windows Computer (File Sharing)"
        elif 548 in port_nums:
            return "macOS Computer (AFP)"
        elif 5900 in port_nums or 5901 in port_nums:
            return "Computer (VNC)"
        elif 515 in port_nums or 631 in port_nums or 9100 in port_nums:
            return "Network Printer"
        elif 8080 in port_nums or 8443 in port_nums or 9090 in port_nums:
            return "Web Application Server"
        elif 3306 in port_nums or 5432 in port_nums or 1433 in port_nums:
            return "Database Server"
        elif 554 in port_nums or 8000 in port_nums:
            return "IP Camera / DVR"
    
    # OS-based detection
    if 'Windows' in os_guess:
        return "Windows Computer"
    elif 'Linux' in os_guess:
        return "Linux Device"
    elif 'Mac' in os_guess:
        return "macOS Device"
    
    return "Unknown Device"

def calculate_device_fingerprint(device):
    """Generate unique fingerprint for device"""
    fingerprint_string = f"{device.get('mac_address', 'unknown')}_{device.get('hostname', 'unknown')}_{device.get('vendor', 'unknown')}"
    return hashlib.md5(fingerprint_string.encode()).hexdigest()[:8]

def scan_single_ip(ip, scan_ports_flag=False, quick_scan=True):
    """Comprehensive single IP scan with all features"""
    ip_str = str(ip)
    
    alive, ping_time, ttl, packet_loss = ping_host_detailed(ip_str)
    
    if alive:
        # Gather all information
        hostname, workgroup = get_hostname(ip_str)
        mac = get_mac_address(ip_str)
        vendor = get_vendor_from_mac(mac)
        os_guess, _ = get_os_guess(ttl)
        
        device = {
            'ip': ip_str,
            'status': 'online',
            'hostname': hostname,
            'workgroup': workgroup,
            'mac_address': mac,
            'vendor': vendor,
            'ping_time': ping_time,
            'packet_loss': packet_loss,
            'ttl': ttl,
            'os_guess': os_guess,
            'os_details': '',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'open_ports': [],
            'device_type': 'Analyzing...',
            'http_info': None,
            'security_score': 100,
            'risk_summary': []
        }
        
        banner_info = []
        
        if scan_ports_flag:
            device['open_ports'] = scan_ports_enhanced(ip_str, quick=quick_scan)
            
            # Collect banners for OS detection
            for port_info in device['open_ports']:
                if port_info['banner'] != "No banner":
                    banner_info.append(port_info['banner'])
                
                # Check for HTTP info
                if port_info['port'] == 80 or port_info['port'] == 443:
                    http_info = get_http_info(ip_str, port_info['port'])
                    if http_info:
                        device['http_info'] = http_info
                        
            # Security assessment
            device['security_score'], device['risk_summary'] = perform_security_assessment(device)
            
        # Final device type detection
        device['device_type'] = get_device_type_enhanced(hostname, mac, vendor, device['open_ports'], os_guess)
        
        # Fingerprint
        device['fingerprint'] = calculate_device_fingerprint(device)
        
        return device
    else:
        return {'ip': ip_str, 'status': 'offline', 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

def perform_security_assessment(device):
    """Calculate security score and generate risk summary"""
    score = 100
    risk_summary = []
    
    high_risk_ports = 0
    medium_risk_ports = 0
    
    for port_info in device['open_ports']:
        risk = port_info.get('risk_level')
        if risk == 'HIGH':
            high_risk_ports += 1
            score -= 15
            risk_summary.append(f"High Risk Port: {port_info['port']}/{port_info['service']} is open.")
        elif risk == 'MEDIUM':
            medium_risk_ports += 1
            score -= 5
            risk_summary.append(f"Medium Risk Port: {port_info['port']}/{port_info['service']} is open.")
            
        # Check for default/known vulnerable versions (simplified check)
        version = port_info.get('version', '').lower()
        if 'apache 2.2' in version or 'iis 6.0' in version:
            score -= 10
            risk_summary.append(f"Outdated/Vulnerable Service: {port_info['service']} running version {version}.")
            
    # Check for HTTP info
    if device['http_info']:
        server = device['http_info'].get('server', '').lower()
        if 'iis' in server or 'apache' in server:
            risk_summary.append(f"Web Server Detected: {server}")
            
    # Check for common vulnerable device types
    if device['device_type'] in ['IoT Device', 'IP Camera', 'NAS/Storage']:
        score -= 10
        risk_summary.append(f"Device Type Risk: {device['device_type']} often requires extra security hardening.")
        
    # Ensure score is not negative
    score = max(0, score)
    
    if not risk_summary and score == 100:
        risk_summary.append("No immediate security risks detected based on open ports and services.")
        
    return score, risk_summary

def scan_network(network_range, scan_ports_flag=False, quick_scan=True):
    """Scan a network range using concurrent futures"""
    
    try:
        network = ipaddress.ip_network(network_range, strict=False)
    except ValueError as e:
        print(f"[!] Invalid network range: {e}")
        return []
        
    hosts = [str(ip) for ip in network.hosts()]
    
    print(f"[*] Scanning {len(hosts)} hosts in {network_range}...")
    
    devices = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(scan_single_ip, ip, scan_ports_flag, quick_scan): ip for ip in hosts}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_ip)):
            device = future.result()
            if device and device['status'] == 'online':
                devices.append(device)
                print(f"   [+] Found: {device['ip']} ({device['hostname']}) - {device['device_type']} - Score: {device['security_score']}")
            else:
                print(f"   [-] Offline: {device['ip']}")
                
            # Simple progress update
            if (i + 1) % 10 == 0:
                print(f"[*] Progress: {i + 1}/{len(hosts)} hosts checked. Found {len(devices)} online.")
                
    return devices

def display_results(devices):
    """Display scan results in a formatted table"""
    
    print("\n" + "="*90)
    print("SCAN RESULTS")
    print("="*90)
    
    # Prepare data for tabulate
    table_data = []
    for device in devices:
        ports_str = ', '.join([f"{p['port']}/{p['risk_level'][0]}" for p in device['open_ports']])
        
        # Determine security badge
        score = device.get('security_score', 100)
        if score >= 80:
            sec_badge = "SECURE"
        elif score >= 50:
            sec_badge = "WARNING"
        else:
            sec_badge = "DANGER"
            
        table_data.append([
            device['ip'],
            device['hostname'],
            device['mac_address'],
            device['vendor'],
            device['device_type'],
            device['os_guess'],
            device['ping_time'],
            sec_badge,
            ports_str if ports_str else "None"
        ])
        
    headers = ["IP", "Hostname", "MAC", "Vendor", "Type", "OS", "Ping", "Security", "Open Ports"]
    
    try:
        from tabulate import tabulate
        print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    except ImportError:
        print("Warning: 'tabulate' not installed. Displaying simple table.")
        print("-" * 90)
        print(" | ".join(headers))
        print("-" * 90)
        for row in table_data:
            print(" | ".join(row))
        print("-" * 90)
        
    # Detailed risk summary
    print("\n" + "="*90)
    print("SECURITY RISK SUMMARY")
    print("="*90)
    
    for device in devices:
        if device.get('security_score', 100) < 100:
            print(f"\n[!] {device['ip']} ({device['hostname']}) - Score: {device['security_score']}")
            for risk in device['risk_summary']:
                print(f"    - {risk}")
                
def save_results(devices, filename="network_scan_results.json"):
    """Save scan results to a JSON file"""
    try:
        with open(filename, 'w') as f:
            json.dump(devices, f, indent=4)
        return filename
    except Exception as e:
        print(f"[!] Error saving JSON: {e}")
        return None

def export_to_csv(devices, filename="network_scan_results.csv"):
    """Export scan results to a CSV file"""
    try:
        import csv
        
        # Define headers
        headers = [
            "IP", "Status", "Hostname", "Workgroup", "MAC Address", "Vendor", 
            "Ping Time", "Packet Loss", "TTL", "OS Guess", "Device Type", 
            "Security Score", "Risk Summary", "Open Ports"
        ]
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for device in devices:
                # Format open ports
                ports_list = [f"{p['port']}/{p['service']}/{p['risk_level']}" for p in device.get('open_ports', [])]
                ports_str = "; ".join(ports_list)
                
                # Format risk summary
                risk_str = "; ".join(device.get('risk_summary', []))
                
                row = [
                    device.get('ip', 'N/A'),
                    device.get('status', 'N/A'),
                    device.get('hostname', 'N/A'),
                    device.get('workgroup', 'N/A'),
                    device.get('mac_address', 'N/A'),
                    device.get('vendor', 'N/A'),
                    device.get('ping_time', 'N/A'),
                    device.get('packet_loss', 'N/A'),
                    device.get('ttl', 'N/A'),
                    device.get('os_guess', 'N/A'),
                    device.get('device_type', 'N/A'),
                    device.get('security_score', 'N/A'),
                    risk_str,
                    ports_str
                ]
                writer.writerow(row)
                
        return filename
    except ImportError:
        print("[!] CSV export requires 'csv' module (standard library).")
        return None
    except Exception as e:
        print(f"[!] Error saving CSV: {e}")
        return None

def export_to_html(devices, filename="network_security_report.html"):
    """Generate a comprehensive, styled HTML report"""
    
    # --- Data Aggregation for Report ---
    total_devices = len(devices)
    secure_devices = sum(1 for d in devices if d.get('security_score', 0) >= 80)
    at_risk = total_devices - secure_devices
    
    total_ports = sum(len(d.get('open_ports', [])) for d in devices)
    high_risk_ports = sum(1 for d in devices for p in d.get('open_ports', []) if p.get('risk_level') == 'HIGH')
    
    vendors = defaultdict(int)
    device_types = defaultdict(int)
    
    for device in devices:
        vendors[device['vendor']] += 1
        device_types[device['device_type']] += 1
        
    # --- HTML Template ---
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Scan Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        body {{
            font-family: 'Poppins', sans-serif;
            background-color: #f4f7f6;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #ffffff;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.05);
        }}
        h1 {{
            color: #1a1a1a;
            font-weight: 700;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #666;
            font-size: 1.1em;
            margin-bottom: 30px;
        }}
        
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-card h3 {{ font-size: 2.5em; margin: 0; font-weight: 700; }}
        .stat-card p {{ opacity: 0.9; text-transform: uppercase; font-size: 0.85em; letter-spacing: 1px; }}
        
        .security-card {{ background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }}
        .risk-card {{ background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); }}
        .port-card {{ background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }}
        
        table {{ 
            width: 100%;
            border-collapse: collapse;
            margin: 30px 0;
            font-size: 0.95em;
        }}
        th {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        td {{ 
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }}
        tr:hover {{ background: #f8f9fa; }}
        
        .ip {{ color: #0066cc; font-weight: 600; font-family: 'Courier New', monospace; }}
        .mac {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
        .port {{ 
            background: #e3f2fd;
            padding: 4px 10px;
            border-radius: 12px;
            margin: 3px;
            display: inline-block;
            font-size: 0.85em;
            font-weight: 500;
        }}
        .port.high-risk {{ background: #ffebee; color: #c62828; }}
        .port.medium-risk {{ background: #fff3e0; color: #ef6c00; }}
        
        .security-badge {{
            padding: 5px 12px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85em;
            display: inline-block;
        }}
        .secure {{ background: #c8e6c9; color: #2e7d32; }}
        .warning {{ background: #ffe0b2; color: #e65100; }}
        .danger {{ background: #ffcdd2; color: #c62828; }}
        
        .vendor {{ 
            background: #fef7e0;
            padding: 4px 10px;
            border-radius: 8px;
            font-size: 0.9em;
            display: inline-block;
        }}
        
        .charts-section {{
            margin: 40px 0;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
        }}
        .chart-card {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .chart-card h3 {{
            color: #1a1a1a;
            margin-bottom: 20px;
            font-size: 1.3em;
        }}
        .chart-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #e0e0e0;
        }}
        .chart-item:last-child {{ border-bottom: none; }}
        .chart-bar {{
            height: 8px;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            border-radius: 4px;
            margin-top: 5px;
        }}
        
        .risk-indicator {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
        }}
        .risk-high {{ background: #f44336; }}
        .risk-medium {{ background: #ff9800; }}
        .risk-low {{ background: #4caf50; }}
        
        @media print {{
            body {{ background: white; padding: 0; }}
            .container {{ box-shadow: none; }}
            .stat-card {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Network Security Scan Report</h1>
        <div class="subtitle">
            Comprehensive network discovery and security assessment<br>
            Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
        
        <div class="dashboard">
            <div class="stat-card">
                <h3>{total_devices}</h3>
                <p>Total Devices</p>
            </div>
            <div class="stat-card security-card">
                <h3>{secure_devices}</h3>
                <p>Secure Devices</p>
            </div>
            <div class="stat-card risk-card">
                <h3>{at_risk}</h3>
                <p>At Risk</p>
            </div>
            <div class="stat-card port-card">
                <h3>{total_ports}</h3>
                <p>Open Ports</p>
            </div>
            <div class="stat-card risk-card">
                <h3>{high_risk_ports}</h3>
                <p>High Risk Ports</p>
            </div>
        </div>
        
        <div class="charts-section">
            <div class="chart-card">
                <h3>📊 Top Vendors</h3>
"""
    
    for vendor, count in sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:6]:
        percentage = (count / total_devices) * 100 if total_devices > 0 else 0
        html += f"""
                <div class="chart-item">
                    <span>{vendor}</span>
                    <strong>{count}</strong>
                </div>
                <div class="chart-bar" style="width: {percentage}%"></div>
"""
    
    html += """
            </div>
            <div class="chart-card">
                <h3>💻 Device Types</h3>
"""
    
    for dtype, count in sorted(device_types.items(), key=lambda x: x[1], reverse=True)[:6]:
        percentage = (count / total_devices) * 100 if total_devices > 0 else 0
        html += f"""
                <div class="chart-item">
                    <span>{dtype}</span>
                    <strong>{count}</strong>
                </div>
                <div class="chart-bar" style="width: {percentage}%"></div>
"""
    
    html += """
            </div>
        </div>
        
        <h2 style="margin-top: 40px; color: #1a1a1a;">🖥️ Discovered Devices</h2>
        <table>
            <tr>
                <th>IP</th>
                <th>Hostname</th>
                <th>MAC</th>
                <th>Vendor</th>
                <th>Type</th>
                <th>OS</th>
                <th>Ping</th>
                <th>Security</th>
                <th>Open Ports</th>
            </tr>
"""
    
    for device in sorted(devices, key=lambda x: ipaddress.ip_address(x['ip'])):
        sec_score = device.get('security_score', 100)
        sec_class = "secure" if sec_score >= 80 else "warning" if sec_score >= 50 else "danger"
        sec_text = f"🔒 {sec_score}" if sec_score >= 80 else f"⚠️  {sec_score}" if sec_score >= 50 else f"❌ {sec_score}"
        
        ports_html = ''
        for p in device.get('open_ports', []):
            risk_class = ''
            if p.get('risk_level') == 'HIGH':
                risk_class = ' high-risk'
            elif p.get('risk_level') == 'MEDIUM':
                risk_class = ' medium-risk'
            ports_html += f'<span class="port{risk_class}">{p["port"]}/{p["service"]}</span> '
        
        if not ports_html:
            ports_html = '<span style="color: #999;">None</span>'
        
        html += f"""
            <tr>
                <td><span class="ip">{device['ip']}</span></td>
                <td>{device['hostname']}</td>
                <td><span class="mac">{device['mac_address']}</span></td>
                <td><span class="vendor">{device['vendor']}</span></td>
                <td>{device['device_type']}</td>
                <td>{device['os_guess']}</td>
                <td>{device['ping_time']}</td>
                <td><span class="security-badge {sec_class}">{sec_text}</span></td>
                <td>{ports_html}</td>
            </tr>
"""
    
    html += """
        </table>
        
        <div style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #667eea;">
            <h3 style="color: #1a1a1a; margin-bottom: 10px;">🔐 Security Recommendations</h3>
            <ul style="line-height: 2; color: #666;">
                <li>Review all devices with HIGH risk ports</li>
                <li>Disable unused services and close unnecessary ports</li>
                <li>Ensure all devices have updated firmware</li>
                <li>Implement network segmentation for IoT devices</li>
                <li>Use strong authentication for all network services</li>
                <li>Monitor for unauthorized devices on the network</li>
            </ul>
        </div>
        
        <div style="margin-top: 30px; text-align: center; color: #999; font-size: 0.9em;">
            Generated by Advanced Network Scanner v2.0 | Educational Lab Use Only
        </div>
    </div>
</body>
</html>
"""
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] Enhanced HTML report: {filename}")
        return filename
    except Exception as e:
        print(f"[!] Error creating HTML: {e}")
        return None

def ping_host_detailed(ip):
    """Enhanced ping with comprehensive stats"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    count_param = '4' if platform.system().lower() == 'windows' else '4'
    command = ['ping', param, count_param, '-w' if platform.system().lower() == 'windows' else '-W', '1000', str(ip)]
    
    try:
        flags = subprocess.CREATE_NO_WINDOW if platform.system().lower() == 'windows' else 0
        result = subprocess.run(command,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              timeout=6,
                              creationflags=flags,
                              text=True)
        
        if result.returncode == 0:
            output = result.stdout
            
            # Extract ping stats
            ping_time = "N/A"
            packet_loss = "0%"
            ttl = 0
            
            if platform.system().lower() == 'windows':
                # Average time
                match = re.search(r'Average = (\d+)ms', output)
                if match:
                    ping_time = f"{match.group(1)}ms"
                
                # Packet loss
                loss_match = re.search(r'\((\d+)% loss\)', output)
                if loss_match:
                    packet_loss = f"{loss_match.group(1)}%"
                    
                # TTL (from the first reply)
                ttl_match = re.search(r'TTL=(\d+)', output)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
            else:
                match = re.search(r'avg.*?= \d+\.\d+/(\d+\.\d+)/', output)
                if match:
                    ping_time = f"{match.group(1)}ms"
                
                loss_match = re.search(r'(\d+)% packet loss', output)
                if loss_match:
                    packet_loss = f"{loss_match.group(1)}%"
                    
                # TTL (from the first reply)
                ttl_match = re.search(r'ttl=(\d+)', output)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    
            return True, ping_time, ttl, packet_loss
        else:
            return False, "N/A", 0, "100%"
    except subprocess.TimeoutExpired:
        return False, "Timeout", 0, "100%"
    except:
        return False, "Error", 0, "100%"

def main():
    print("="*90)
    print("    🔍 ADVANCED NETWORK SCANNER - ULTIMATE EDITION v2.0")
    print("    Comprehensive Network Discovery & Security Assessment")
    print("    Educational Lab Use Only")
    print("="*90)
    
    # System info
    local_ip = get_local_ip()
    public_ip = get_public_ip()
    network_prefix = '.'.join(local_ip.split('.')[:-1])
    default_range = f"{network_prefix}.0/24"
    
    print(f"\n📡 Network Information:")
    print(f"   Local IP:  {local_ip}")
    print(f"   Public IP: {public_ip}")
    print(f"   Network:   {default_range}")
    
    # Check admin
    if is_admin():
        print(f"\n✓ Running with Administrator privileges")
    else:
        print(f"\n⚠️  NOT running as Administrator")
        print(f"   For best results: Right-click → Run as Administrator")
    
    print("\n" + "="*90)
    print("SCAN OPTIONS:")
    print("="*90)
    print("1. 🏃 Quick Scan      - Hostname, MAC, Vendor (Fast)")
    print("2. 🔍 Deep Scan       - + Common Ports & Services (Recommended)")
    print("3. 🔬 Full Scan       - + All Ports & Security Assessment (Thorough)")
    print("4. ⚙️  Custom Range    - Specify custom network range")
    print("="*90)
    
    choice = input("\n➤ Select scan type (1-4): ").strip()
    
    scan_ports = False
    quick_scan = True
    network_range = default_range
    
    if choice == '2':
        scan_ports = True
        print("\n[*] Deep scan selected - scanning common ports...")
    elif choice == '3':
        scan_ports = True
        quick_scan = False
        print("\n[*] Full scan selected - this may take several minutes...")
        print("[*] This will perform comprehensive security assessment")
    elif choice == '4':
        network_range = input("\n➤ Enter network range (e.g., 192.168.1.0/24): ").strip()
        port_choice = input("➤ Scan ports? (1=No, 2=Common, 3=All): ").strip()
        if port_choice == '2':
            scan_ports = True
        elif port_choice == '3':
            scan_ports = True
            quick_scan = False
    
    print("\n" + "="*90)
    print("🚀 STARTING SCAN...")
    print("="*90)
    
    devices = scan_network(network_range, scan_ports_flag=scan_ports, quick_scan=quick_scan)
    
    if devices:
        display_results(devices)
        
        print("\n" + "="*90)
        print("💾 EXPORT OPTIONS:")
        print("="*90)
        
        exports = []
        
        if input("➤ Save JSON? (y/n): ").lower() == 'y':
            result = save_results(devices)
            if result:
                exports.append(result)
        
        if input("➤ Export CSV? (y/n): ").lower() == 'y':
            result = export_to_csv(devices)
            if result:
                exports.append(result)
        
        if input("➤ Create HTML Security Report? (y/n): ").lower() == 'y':
            result = export_to_html(devices)
            if result:
                exports.append(result)
        
        if exports:
            print(f"\n✓ Exported {len(exports)} file(s):")
            for exp in exports:
                print(f"  📄 {exp}")
    else:
        print("\n[!] No devices found on the network")
    
    print("\n" + "="*90)
    print("✅ SCAN COMPLETE!")
    print("="*90)
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        print("[!] Partial results may have been saved")
    except Exception as e:
        print(f"\n[!] Critical error: {e}")
        import traceback
        traceback.print_exc()
