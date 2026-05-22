"""
=============================================================
  SENTINELHOME101 — Network Scanner Module
  File: modules/scanner.py

  Core network scanning engine. Handles:
  - Local IP and network range detection
  - Ping sweep to find active devices
  - Port scanning on discovered devices
  - Service banner grabbing
  - OUI database lookups for manufacturer identification
  - ARP table queries for MAC addresses

  DATA PRIVACY: All operations in this module communicate
  ONLY with devices on the local network. No data is sent
  to the internet. The OUI lookup is done against the local
  database file — no external API calls.
=============================================================
"""

import socket           # Network connections and hostname lookups
import subprocess       # Running Windows commands (arp, netsh)
import ipaddress        # Working with IP address ranges
import concurrent.futures  # Running multiple checks simultaneously
import os               # File path operations
import re               # Regular expressions for parsing output
import struct           # For building ICMP packets
import ctypes           # For raw socket privilege check
from modules.constants import *

# Suppress console window flash on every subprocess call (Windows)
CREATE_NO_WINDOW = 0x08000000


class NetworkScanner:
    """
    Handles all network scanning and device discovery operations.

    All methods in this class operate only on the local network.
    No data is sent outside the local subnet.
    """

    def __init__(self, oui_db_path, progress_callback=None):
        """
        Initializes the network scanner.

        Parameters:
            oui_db_path       (str)     : Path to the oui_database.txt file.
            progress_callback (callable): Optional function called with
                                          (message, percent) to report progress.
        """
        self.oui_db_path = oui_db_path
        self.progress_callback = progress_callback or (lambda msg, pct: None)

        # Load OUI database into memory for fast lookups
        # This is a one-time operation on initialization
        self._oui_cache = {}
        self._load_oui_database()

        # Standard ports to check (from constants.py feature list)
        self.ports_to_check = {
            21:    "FTP — insecure file transfer",
            22:    "SSH — remote login",
            23:    "Telnet — INSECURE plain text remote",
            25:    "SMTP — email sending",
            53:    "DNS — domain name service",
            80:    "HTTP — unencrypted web interface",
            110:   "POP3 — email retrieval",
            143:   "IMAP — email access",
            443:   "HTTPS — secure web interface",
            445:   "SMB — Windows file sharing",
            631:   "IPP — network printing",
            515:   "LPD — legacy printing",
            1883:  "MQTT — IoT/smart home protocol",
            3389:  "RDP — Remote Desktop",
            5900:  "VNC — remote desktop control",
            8080:  "HTTP Alt — alternate web interface",
            8443:  "HTTPS Alt — alternate secure web",
            8888:  "Common IoT/camera port",
            9100:  "RAW printing port",
            49152: "UPnP — universal plug and play",
        }

        # High-risk ports that trigger critical findings
        self.high_risk_ports = {23, 21, 3389, 5900, 49152}


    def _load_oui_database(self):
        """
        Loads the IEEE OUI database from the local text file.

        Parses the oui.txt format and builds a dictionary mapping
        MAC prefixes (first 6 hex chars) to manufacturer names.

        The OUI file format looks like:
        XX-XX-XX   (hex)   Manufacturer Name

        We store it as {XXXXXX: "Manufacturer Name"}
        """
        if not os.path.exists(self.oui_db_path):
            return  # Database file not found — skip OUI lookups

        try:
            with open(self.oui_db_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Match lines like: "00-00-00   (hex)   XEROX CORPORATION"
                    match = re.match(
                        r'^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$',
                        line.strip()
                    )
                    if match:
                        # Convert "AA-BB-CC" to "AABBCC" for easy lookup
                        prefix = match.group(1).replace('-', '').upper()
                        manufacturer = match.group(2).strip()
                        self._oui_cache[prefix] = manufacturer

        except Exception:
            pass    # If loading fails, OUI lookups will return "Unknown"


    def lookup_manufacturer(self, mac_address):
        """
        Looks up the manufacturer for a MAC address.

        Uses the locally loaded OUI database — no internet required.

        Parameters:
            mac_address (str): MAC address in any common format
                               (XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, etc.)

        Returns:
            str: Manufacturer name, or "Unknown" if not found.
        """
        if not mac_address or mac_address in ('Not found', 'Unknown', ''):
            return "Unknown"

        # Normalize the MAC address — remove separators, uppercase
        clean = re.sub(r'[:\-\.]', '', mac_address).upper()

        if len(clean) < 6:
            return "Unknown"

        # First 6 characters identify the manufacturer
        prefix = clean[:6]
        return self._oui_cache.get(prefix, "Unknown")


    def get_local_ip(self):
        """
        Determines this computer's IP address on the local network.

        Uses a UDP socket trick — connects to a non-existent external
        address just to determine which local interface would be used.
        No actual data is sent.

        Returns:
            str: Local IP address (e.g., "192.168.1.105") or None.
        """
        try:
            # Creating a UDP socket and "connecting" to an external address
            # lets the OS tell us which local IP it would use.
            # No data is actually transmitted.
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))         # Fake connect — no data sent
            local_ip = s.getsockname()[0]       # Get the local IP chosen
            s.close()
            return local_ip
        except Exception:
            # Fallback: get hostname and resolve it
            try:
                hostname = socket.gethostname()
                return socket.gethostbyname(hostname)
            except Exception:
                return None


    def get_network_range(self, local_ip):
        """
        Calculates the network range to scan based on local IP.

        Assumes a standard /24 home network (most home routers use this).
        For example: 192.168.1.105 → 192.168.1.0/24

        Parameters:
            local_ip (str): This computer's local IP address.

        Returns:
            ipaddress.IPv4Network: The network range to scan.
        """
        try:
            # Replace last octet with 0 and add /24 subnet mask
            parts = local_ip.split('.')
            network_addr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            return ipaddress.ip_network(network_addr, strict=False)
        except Exception:
            return None


    def ping_host(self, ip, timeout_ms=500):
        """
        Checks if a host is alive using a TCP socket connection attempt.

        This replaces the subprocess ping approach entirely.
        No ping.exe is spawned — no console windows flash.

        Strategy: attempt a TCP connection to port 80, 443, or 445.
        If any responds the host is up. If none respond we fall back
        to a raw ICMP echo using Windows ICMP API via ctypes.

        Parameters:
            ip         (str): IP address to check.
            timeout_ms (int): Milliseconds to wait.

        Returns:
            bool: True if host is reachable, False if not.
        """
        timeout_s = timeout_ms / 1000.0

        # --- Method 1: TCP probe on common ports ---
        # Fast and reliable for most devices. No special permissions needed.
        for port in (80, 443, 445, 22, 8080, 3389):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout_s)
                result = sock.connect_ex((str(ip), port))
                sock.close()
                if result == 0:
                    return True     # Port responded — host is up
            except Exception:
                pass

        # --- Method 2: Windows ICMP API via ctypes ---
        # Falls back to this for devices that block all TCP ports (printers,
        # some routers, IoT). Uses Windows icmp.dll — no subprocess needed.
        try:
            icmp = ctypes.windll.iphlpapi
            handle = icmp.IcmpCreateFile()
            if handle:
                # Build a 32-byte data buffer for the echo request
                data = ctypes.create_string_buffer(32)
                # Reply buffer: sizeof(ICMP_ECHO_REPLY) + 32 bytes data
                reply_size = 28 + 32
                reply_buf = ctypes.create_string_buffer(reply_size)

                # InetAddr converts "192.168.1.1" to a 32-bit integer
                ip_int = struct.unpack("!I", socket.inet_aton(str(ip)))[0]
                # Swap bytes for Windows little-endian format
                ip_le = struct.unpack("I", struct.pack("!I", ip_int))[0]

                ret = icmp.IcmpSendEcho(
                    handle,
                    ip_le,
                    data, 32,
                    None,
                    reply_buf, reply_size,
                    int(timeout_ms)
                )
                icmp.IcmpCloseHandle(handle)
                if ret > 0:
                    return True     # Got an echo reply — host is up
        except Exception:
            pass

        return False


    def get_hostname(self, ip):
        """
        Performs a reverse DNS lookup to get the hostname for an IP.

        This query goes to your local router/DNS server only —
        it does not query any external DNS service.

        Parameters:
            ip (str): IP address to look up.

        Returns:
            str: Hostname if found, "Unknown" if not.
        """
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except Exception:
            return "Unknown"


    def get_mac_address(self, ip):
        """
        Gets the MAC address for an IP address from the ARP table.

        ARP (Address Resolution Protocol) maps IP addresses to
        MAC addresses on the local network. The ARP table is
        maintained by Windows and contains recently seen devices.

        Parameters:
            ip (str): IP address to look up.

        Returns:
            str: MAC address (XX-XX-XX-XX-XX-XX format) or "Unknown".
        """
        try:
            # Run Windows arp -a to query the ARP table
            result = subprocess.run(
                ['arp', '-a', str(ip)],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=CREATE_NO_WINDOW
            )

            # Parse output to find the MAC address
            for line in result.stdout.split('\n'):
                if str(ip) in line:
                    # Line format: "  192.168.1.1    aa-bb-cc-dd-ee-ff  dynamic"
                    parts = line.split()
                    if len(parts) >= 2:
                        mac = parts[1]
                        # Validate it looks like a MAC address
                        if re.match(r'^[0-9a-f]{2}[-:][0-9a-f]{2}', mac, re.I):
                            return mac.upper()

        except Exception:
            pass

        return "Unknown"


    def check_port(self, ip, port, timeout=0.5):
        """
        Attempts to connect to a specific port on a host.

        A successful connection means the port is open and something
        is listening there. An open port is not necessarily dangerous —
        it depends on what service is running.

        Parameters:
            ip      (str)  : Host IP address.
            port    (int)  : Port number to check.
            timeout (float): Seconds to wait for connection.

        Returns:
            bool: True if port is open, False if closed/blocked.
        """
        try:
            # Create a TCP socket and attempt connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)            # Set timeout for this attempt
            result = sock.connect_ex((str(ip), port))  # connect_ex returns 0 on success
            sock.close()
            return result == 0                  # 0 = connected successfully
        except Exception:
            return False


    def get_service_banner(self, ip, port, timeout=2.0):
        """
        Tries to read the banner message from an open port.

        Many services announce themselves when you connect —
        for example, an FTP server might say "220 FileZilla 1.2.3".
        This helps identify the software and version running.

        Parameters:
            ip      (str)  : Host IP address.
            port    (int)  : Port to read banner from.
            timeout (float): Seconds to wait for banner.

        Returns:
            str: Banner text (first line only), or empty string.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((str(ip), port))

            # Send a basic HTTP HEAD request — works for HTTP ports
            # Other services often send their banner without any prompt
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

            # Read up to 1024 bytes of response
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()

            # Return just the first line to keep it concise
            first_line = banner.split('\n')[0].strip()
            return first_line[:100]             # Limit to 100 characters

        except Exception:
            return ""


    def scan_ports(self, ip, profile='standard'):
        """
        Scans all configured ports on a single host.

        Runs port checks in parallel for speed.

        Parameters:
            ip      (str): IP address to scan.
            profile (str): 'quick' = fewer ports, 'standard'/'deep' = all ports.

        Returns:
            list: List of dicts for each open port found.
                  Each dict has: port, description, banner, high_risk
        """
        # Quick scan checks fewer ports for speed
        if profile == 'quick':
            ports = {p: d for p, d in self.ports_to_check.items()
                    if p in {23, 80, 443, 3389, 445, 22}}
        else:
            ports = self.ports_to_check

        open_ports = []

        # Check all ports in parallel (up to 50 at once)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {
                executor.submit(self.check_port, ip, port): (port, desc)
                for port, desc in ports.items()
            }

            for future in concurrent.futures.as_completed(future_to_port):
                port, desc = future_to_port[future]
                try:
                    if future.result():     # Port is open
                        # Try to get service banner
                        banner = self.get_service_banner(ip, port)

                        open_ports.append({
                            'port':        port,
                            'description': desc,
                            'banner':      banner,
                            'high_risk':   port in self.high_risk_ports
                        })
                except Exception:
                    pass

        # Sort by port number for consistent display
        return sorted(open_ports, key=lambda x: x['port'])


    def discover_devices(self, profile='standard'):
        """
        Main device discovery method.

        Performs a ping sweep across the entire local network
        to find all active devices.

        Parameters:
            profile (str): Scan profile affects thread count and timeout.

        Returns:
            tuple: (active_ips, local_ip, network_range)
        """
        local_ip = self.get_local_ip()
        if not local_ip:
            return [], None, None

        network = self.get_network_range(local_ip)
        if not network:
            return [], local_ip, None

        self.progress_callback(
            f"Scanning {network} ({network.num_addresses - 2} addresses)...",
            10
        )

        active_hosts = []
        all_hosts = list(network.hosts())   # All usable IPs in range
        total = len(all_hosts)

        # Thread count: quick = fewer threads (faster but less thorough)
        # standard/deep = more threads
        max_workers = 30 if profile == 'quick' else 80

        # Ping all addresses in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(self.ping_host, str(ip)): str(ip)
                for ip in all_hosts
            }

            completed = 0
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1

                try:
                    if future.result():
                        active_hosts.append(ip)
                except Exception:
                    pass

                # Report progress every 20 completed pings
                if completed % 20 == 0:
                    pct = 10 + int((completed / total) * 40)    # 10-50% progress
                    self.progress_callback(
                        f"Discovering devices... {completed}/{total}",
                        pct
                    )

        self.progress_callback(
            f"Found {len(active_hosts)} device(s). Scanning details...",
            50
        )

        return active_hosts, local_ip, str(network)


    def full_device_scan(self, ip, profile='standard'):
        """
        Performs a complete scan of a single device.

        Gathers: hostname, MAC address, manufacturer,
        open ports, and service banners.

        Parameters:
            ip      (str): IP address to scan.
            profile (str): Scan profile.

        Returns:
            dict: Complete device information.
        """
        # Get hostname (reverse DNS)
        hostname = self.get_hostname(ip)

        # Get MAC address (ARP table)
        mac = self.get_mac_address(ip)

        # Look up manufacturer from OUI database
        manufacturer = self.lookup_manufacturer(mac)

        # Scan ports
        open_ports = self.scan_ports(ip, profile)

        return {
            'ip':           ip,
            'hostname':     hostname,
            'mac':          mac,
            'manufacturer': manufacturer,
            'open_ports':   open_ports,
        }


    def run_full_scan(self, profile='standard'):
        """
        Runs a complete network scan.

        1. Discovers local network range
        2. Finds all active devices (ping sweep)
        3. Scans each device for ports and services
        4. Returns complete results

        Parameters:
            profile (str): 'quick', 'standard', or 'deep'

        Returns:
            dict: Complete scan results with all devices.
        """
        # Step 1: Discover devices
        active_hosts, local_ip, network_range = self.discover_devices(profile)

        if not active_hosts:
            return {
                'local_ip':     local_ip,
                'network_range': network_range,
                'devices':      [],
                'error':        'No devices found'
            }

        # Step 2: Detailed scan of each device
        devices = []
        total = len(active_hosts)

        for i, ip in enumerate(active_hosts):
            pct = 50 + int((i / total) * 45)    # 50-95% progress
            self.progress_callback(
                f"Scanning {ip} ({i+1}/{total})...",
                pct
            )

            device = self.full_device_scan(ip, profile)
            devices.append(device)

        self.progress_callback("Scan complete. Analyzing results...", 95)

        return {
            'local_ip':      local_ip,
            'network_range': network_range,
            'devices':       devices,
        }
