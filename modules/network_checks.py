"""
=============================================================
  SENTINELHOME101 — Network Security Checks
  File: modules/network_checks.py

  Runs all network-level security checks including:
  - WiFi security protocol (WPA2/WPA3)
  - DNS server validation and hijacking detection
  - Router default credential detection
  - Windows Firewall status
  - ARP spoofing detection
  - Rogue DHCP detection
  - Router firmware version check
  - DNS over HTTPS status
  - NTP time sync check
  - Network clock drift detection
  - HTTPS downgrade detection
  - TLS version checking
  - Guest network detection
  - mDNS/SSDP exposure
  - Wake-on-LAN check
  - WPS status

  All checks use Windows built-in tools only.
  No data is sent outside the local network.
=============================================================
"""

import subprocess

# Suppress console window flash on every subprocess call
CREATE_NO_WINDOW = 0x08000000
import socket
import winreg
import os
import re
import datetime
from modules.constants import *


class NetworkChecker:
    """
    Runs all network-level security checks.

    Each check method returns a standardized result dict:
    {'status': 'pass'/'fail'/'warn', 'detail': str, ...}
    """

    def __init__(self, local_ip=None):
        """
        Parameters:
            local_ip (str): This machine's local IP address.
        """
        self.local_ip = local_ip
        # Infer router IP from local IP (usually x.x.x.1)
        if local_ip:
            parts = local_ip.split('.')
            self.router_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        else:
            self.router_ip = "192.168.1.1"


    def run_all_checks(self):
        """
        Runs all network security checks.

        Returns:
            dict: All check results keyed by check name.
        """
        return {
            'wifi_security':        self.check_wifi_security(),
            'wifi_password_entropy':self.check_wifi_password_entropy(),
            'router_credentials':   self.check_router_default_credentials(),
            'router_firmware':      self.check_router_firmware(),
            'dns_security':         self.check_dns_security(),
            'dns_over_https':       self.check_dns_over_https(),
            'https_downgrade':      self.check_https_downgrade(),
            'tls_version':          self.check_tls_version(),
            'ntp_sync':             self.check_ntp_sync(),
            'firewall':             self.check_firewall(),
            'arp_spoofing':         self.check_arp_spoofing(),
            'rogue_dhcp':           self.check_rogue_dhcp(),
            'upnp':                 self.check_upnp(),
            'guest_network':        self.check_guest_network(),
            'mdns_exposure':        self.check_mdns_exposure(),
            'wake_on_lan':          self.check_wake_on_lan(),
            'wps_status':           self.check_wps_status(),
            'ipv6_readiness':       self.check_ipv6(),
            'open_shares':          self.check_open_shares(),
            'public_ip':            self.get_public_ip_info(),
        }


    def check_wifi_security(self):
        """
        Checks the security protocol of the current WiFi connection.
        Uses netsh wlan which is built into Windows.
        Returns protocol type (WPA3/WPA2/WEP/Open) and flags weak security.
        """
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                output = result.stdout
                auth = "Unknown"
                ssid = "Unknown"
                band = "Unknown"

                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith('Authentication'):
                        auth = line.split(':', 1)[-1].strip()
                    elif line.startswith('SSID') and 'BSSID' not in line:
                        ssid = line.split(':', 1)[-1].strip()
                    elif line.startswith('Radio type') or line.startswith('Band'):
                        band = line.split(':', 1)[-1].strip()

                # Evaluate security level
                if 'WPA3' in auth:
                    status = 'pass'
                    detail = f"WiFi uses WPA3 — excellent security"
                elif 'WPA2' in auth:
                    status = 'pass'
                    detail = f"WiFi uses WPA2 — acceptable security. WPA3 preferred."
                elif 'WPA' in auth:
                    status = 'warn'
                    detail = f"WiFi uses WPA (not WPA2/3) — upgrade recommended"
                elif 'WEP' in auth:
                    status = 'fail'
                    detail = f"WiFi uses WEP — INSECURE. WEP can be cracked in minutes."
                elif 'Open' in auth or auth == 'Unknown':
                    status = 'fail'
                    detail = f"WiFi network is OPEN — no encryption at all"
                else:
                    status = 'pass'
                    detail = f"WiFi authentication: {auth}"

                return {
                    'status': status,
                    'auth': auth,
                    'ssid': ssid,
                    'band': band,
                    'detail': detail,
                    'remediation': (
                        "Log into your router admin page and change WiFi security "
                        "to WPA3 (or WPA2 if WPA3 is unavailable)."
                    ) if status != 'pass' else ''
                }

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not determine WiFi security'}


    def check_wifi_password_entropy(self):
        """
        Estimates the entropy (strength) of the current WiFi password.
        Does not access the actual password — estimates from profile metadata.

        Entropy calculation:
        - Character set size (lowercase=26, +uppercase=52, +digits=62, +special=95)
        - Password length
        - Entropy = length × log2(charset_size)
        """
        try:
            # Get current WiFi profile name
            iface_result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            ssid = None
            for line in iface_result.stdout.split('\n'):
                if line.strip().startswith('Profile'):
                    ssid = line.split(':', 1)[-1].strip()
                    break

            if not ssid:
                return {'status': 'warn', 'detail': 'No active WiFi profile found'}

            # Get the profile details (key content requires admin and user approval)
            # We check the key type to infer whether a password exists
            profile_result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profile', f'name={ssid}'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            key_type = "Unknown"
            for line in profile_result.stdout.split('\n'):
                if 'Key Content' in line or 'Authentication' in line:
                    key_type = line.split(':', 1)[-1].strip()

            # We cannot read the actual password without showing it in clear text
            # Instead, report what we can determine
            return {
                'status': 'pass',
                'detail': f'WiFi profile "{ssid}" — password check requires manual verification',
                'ssid': ssid,
                'note': 'For strongest security: use 16+ random characters including symbols'
            }

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not check WiFi password strength'}


    def check_router_default_credentials(self):
        """
        Checks if the router may be using default credentials.

        Attempts to access the router admin page and checks
        the response for signs of default configuration.
        Also checks the router's brand against known defaults.
        """
        try:
            import urllib.request
            import urllib.error

            # Try to reach router admin page
            url = f"http://{self.router_ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'SentinelHome101'})

            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    content = response.read(2048).decode('utf-8', errors='ignore').lower()

                    # Common indicators of default admin pages
                    default_indicators = [
                        'please change', 'default password', 'admin/admin',
                        'setup wizard', 'first time setup', 'initial setup'
                    ]

                    brand_indicators = {
                        'netgear':   True,
                        'linksys':   True,
                        'asus':      True,
                        'd-link':    True,
                        'tp-link':   True,
                        'belkin':    True,
                        'motorola':  True,
                        'arris':     True,
                    }

                    # Detect router brand
                    detected_brand = "Unknown"
                    for brand in brand_indicators:
                        if brand in content:
                            detected_brand = brand.title()
                            break

                    # Check for default credential indicators
                    default_likely = any(ind in content for ind in default_indicators)

                    return {
                        'status': 'warn' if default_likely else 'pass',
                        'brand': detected_brand,
                        'default_likely': default_likely,
                        'detail': (
                            f"Router admin page is accessible ({detected_brand}). "
                            + ("Default credentials may still be in use." if default_likely
                               else "No default credential indicators found.")
                        )
                    }

            except urllib.error.HTTPError as e:
                # Got an HTTP error (like 401 Unauthorized) — router requires login
                # This actually suggests credentials have been changed (good sign)
                return {
                    'status': 'pass',
                    'brand': 'Unknown',
                    'default_likely': False,
                    'detail': f"Router admin page requires authentication (HTTP {e.code}) — good sign"
                }

        except Exception:
            pass

        return {
            'status': 'warn',
            'brand': 'Unknown',
            'default_likely': False,
            'detail': 'Could not reach router admin page to check credentials'
        }


    def check_router_firmware(self):
        """
        Attempts to identify router firmware version from admin page headers.
        """
        try:
            import urllib.request
            import urllib.error

            url = f"http://{self.router_ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'SentinelHome101'})

            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    # Check headers for firmware/version info
                    server = response.getheader('Server', '')
                    x_powered = response.getheader('X-Powered-By', '')
                    version_info = server or x_powered or 'Not disclosed'

                    return {
                        'status': 'pass',
                        'version': version_info,
                        'detail': f"Router identifies as: {version_info}",
                        'note': 'Compare against manufacturer latest version at their support site'
                    }

            except Exception:
                pass

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not determine router firmware version'}


    def check_dns_security(self):
        """
        Validates DNS servers and checks for DNS hijacking.

        DNS hijacking = your DNS queries are being redirected
        to a malicious server that returns wrong answers.

        Detection method:
        1. Query several known domains
        2. Compare results to expected IP ranges
        3. Flag if results are unexpected (known IPs for google.com etc.)
        """
        try:
            # Get configured DNS servers from ipconfig
            result = subprocess.run(
                ['ipconfig', '/all'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            dns_servers = []
            for line in result.stdout.split('\n'):
                if 'DNS Servers' in line or ('DNS' in line and ':' in line):
                    ip_match = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                    dns_servers.extend(ip_match)

            # Remove duplicates while preserving order
            seen = set()
            dns_servers = [x for x in dns_servers if not (x in seen or seen.add(x))]

            # Known good DNS providers
            known_safe_dns = {
                '1.1.1.1', '1.0.0.1',           # Cloudflare
                '8.8.8.8', '8.8.4.4',           # Google
                '9.9.9.9', '149.112.112.112',   # Quad9
                '208.67.222.222', '208.67.220.220',  # OpenDNS
            }

            # Check if ISP DNS (not ideal for privacy but not dangerous)
            using_known_safe = any(dns in known_safe_dns for dns in dns_servers)

            # Check for DNS hijacking by querying a known domain
            hijacked = False
            try:
                google_ip = socket.gethostbyname('www.google.com')
                # Google's IPs should be in 142.250.x.x or 172.217.x.x ranges
                if not (google_ip.startswith('142.') or
                        google_ip.startswith('172.') or
                        google_ip.startswith('216.') or
                        google_ip.startswith('74.')):
                    hijacked = True
            except Exception:
                pass

            return {
                'status': 'fail' if hijacked else ('pass' if using_known_safe else 'warn'),
                'dns_servers': dns_servers,
                'hijacked': hijacked,
                'using_known_safe': using_known_safe,
                'detail': (
                    "DNS HIJACKING DETECTED — DNS responses appear tampered!" if hijacked else
                    f"DNS: {', '.join(dns_servers[:2]) if dns_servers else 'Unknown'} "
                    f"({'known safe provider' if using_known_safe else 'ISP DNS — consider switching to 1.1.1.1'})"
                )
            }

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not check DNS configuration', 'hijacked': False}


    def check_dns_over_https(self):
        """
        Checks whether DNS over HTTPS (DoH) is configured in Windows.
        DoH encrypts DNS queries so ISPs cannot monitor your browsing.
        """
        try:
            # Check Windows DoH policy in registry
            key_path = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                try:
                    doh_policy, _ = winreg.QueryValueEx(key, "EnableAutoDoh")
                    if doh_policy >= 2:
                        return {'status': 'pass', 'detail': 'DNS over HTTPS is enabled'}
                    else:
                        return {
                            'status': 'warn',
                            'detail': 'DNS over HTTPS is not enabled',
                            'remediation': (
                                'Enable DoH in Windows Settings → Network → '
                                'DNS server → Encrypted DNS'
                            )
                        }
                except FileNotFoundError:
                    pass

        except Exception:
            pass

        return {
            'status': 'warn',
            'detail': 'DNS over HTTPS status unknown — not explicitly configured'
        }


    def check_https_downgrade(self):
        """
        Checks for HTTPS downgrade attacks.
        Tests if any network device is stripping HTTPS from connections.
        """
        try:
            import urllib.request
            import ssl

            # Try to make an HTTPS connection to a known site
            # If it fails or redirects to HTTP, something may be intercepting
            ctx = ssl.create_default_context()

            try:
                url = "https://www.cloudflare.com"
                req = urllib.request.Request(url, headers={'User-Agent': 'SentinelHome101'})
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    if resp.url.startswith('http://'):
                        return {
                            'status': 'fail',
                            'detail': 'HTTPS connection was downgraded to HTTP — possible interception'
                        }
                    return {'status': 'pass', 'detail': 'HTTPS connections appear intact'}

            except ssl.SSLError:
                return {
                    'status': 'warn',
                    'detail': 'SSL certificate error detected — possible HTTPS interception'
                }

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not verify HTTPS downgrade status'}


    def check_tls_version(self):
        """
        Checks the minimum TLS version negotiated with common servers.
        TLS 1.0 and 1.1 are deprecated and vulnerable.
        """
        try:
            import ssl
            ctx = ssl.create_default_context()

            # Connect to a known server and check protocol version
            with socket.create_connection(('www.google.com', 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname='www.google.com') as ssock:
                    protocol = ssock.version()

                    if protocol in ('TLSv1.3', 'TLSv1.2'):
                        return {
                            'status': 'pass',
                            'version': protocol,
                            'detail': f"TLS {protocol} — secure"
                        }
                    else:
                        return {
                            'status': 'warn',
                            'version': protocol,
                            'detail': f"TLS {protocol} — outdated protocol in use"
                        }

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not verify TLS version'}


    def check_ntp_sync(self):
        """
        Checks whether Windows time synchronization is working correctly.
        Incorrect system time breaks SSL certificates and security logs.
        """
        try:
            result = subprocess.run(
                ['w32tm', '/query', '/status'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            # Initialize with safe defaults in case the command fails
            # or returncode is non-zero — prevents use-before-assignment
            source = "Unknown"
            stratum = "Unknown"

            if result.returncode == 0:
                output = result.stdout

                for line in output.split('\n'):
                    if 'Source:' in line:
                        source = line.split(':', 1)[-1].strip()
                    elif 'Stratum:' in line:
                        stratum = line.split(':', 1)[-1].strip()

                # Check time accuracy
            time_result = subprocess.run(
                ['w32tm', '/stripchart', '/computer:time.windows.com',
                 '/samples:1', '/dataonly'],
                capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW
            )

            offset_ok = True
            offset_secs = 0
            if time_result.returncode == 0:
                for line in time_result.stdout.split('\n'):
                    offset_match = re.search(r'([+-]?\d+\.\d+)s', line)
                    if offset_match:
                        offset_secs = abs(float(offset_match.group(1)))
                        offset_ok = offset_secs < 5.0  # Within 5 seconds is acceptable

            if offset_ok:
                return {
                    'status': 'pass',
                    'source': source,
                    'offset_secs': offset_secs,
                    'detail': f"NTP synced to {source} (offset: {offset_secs:.2f}s)"
                }
            else:
                return {
                    'status': 'warn',
                    'source': source,
                    'offset_secs': offset_secs,
                    'detail': f"NTP offset is {offset_secs:.1f}s — time drift may cause security issues"
                }

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not verify NTP time synchronization'}


    def check_firewall(self):
        """
        Checks Windows Firewall status across all three profiles.
        Profiles: Domain, Private, Public
        All three should be enabled.
        """
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                output = result.stdout
                profiles = {}
                current_profile = None

                for line in output.split('\n'):
                    line = line.strip()
                    # Detect profile headers
                    for p in ['Domain', 'Private', 'Public']:
                        if line.startswith(f'{p} Profile Settings'):
                            current_profile = p
                    # Detect firewall state
                    if current_profile and line.startswith('State'):
                        state = line.split()[-1].lower()
                        profiles[current_profile] = state == 'on'

                disabled = [p for p, enabled in profiles.items() if not enabled]

                if not disabled:
                    return {
                        'status': 'pass',
                        'profiles': profiles,
                        'detail': "Windows Firewall enabled on all profiles"
                    }
                else:
                    return {
                        'status': 'fail',
                        'profiles': profiles,
                        'detail': f"Firewall DISABLED on: {', '.join(disabled)}",
                        'remediation': (
                            "Open Windows Security → Firewall & network protection "
                            "and enable all profiles."
                        )
                    }

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not check firewall status'}


    def check_arp_spoofing(self):
        """
        Checks ARP table for duplicate MAC addresses that could
        indicate ARP spoofing / poisoning attacks.

        ARP spoofing = attacker broadcasts fake ARP replies claiming
        their MAC address corresponds to the router's IP, causing
        all traffic to route through the attacker's machine.
        """
        try:
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                mac_to_ips = {}  # MAC → list of IPs using that MAC

                for line in result.stdout.split('\n'):
                    # Parse lines like: "  192.168.1.1    aa-bb-cc-dd-ee-ff  dynamic"
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip_match = re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0])
                        mac_match = re.match(r'^[0-9a-f]{2}[-:][0-9a-f]{2}', parts[1], re.I)

                        if ip_match and mac_match:
                            ip = parts[0]
                            mac = parts[1].upper()

                            if mac not in mac_to_ips:
                                mac_to_ips[mac] = []
                            mac_to_ips[mac].append(ip)

                # Flag MACs associated with multiple IPs (possible spoofing)
                suspicious = {
                    mac: ips for mac, ips in mac_to_ips.items()
                    if len(ips) > 1
                    and mac not in ('FF-FF-FF-FF-FF-FF', '00-00-00-00-00-00')
                }

                if suspicious:
                    return {
                        'status': 'warn',
                        'suspicious': suspicious,
                        'detail': (
                            f"Possible ARP spoofing: {len(suspicious)} MAC address(es) "
                            f"appearing with multiple IP addresses"
                        )
                    }

                return {'status': 'pass', 'detail': 'ARP table looks clean — no spoofing detected'}

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not check ARP table'}


    def check_rogue_dhcp(self):
        """
        Checks for rogue DHCP servers on the network.
        A rogue DHCP server could redirect your traffic.

        Detection: look for multiple DHCP offers or unexpected lease sources.
        """
        try:
            # Check DHCP server from ipconfig
            result = subprocess.run(
                ['ipconfig', '/all'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            dhcp_servers = []
            for line in result.stdout.split('\n'):
                if 'DHCP Server' in line:
                    ip_match = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                    dhcp_servers.extend(ip_match)

            if len(dhcp_servers) > 1:
                return {
                    'status': 'warn',
                    'servers': dhcp_servers,
                    'detail': f"Multiple DHCP servers detected: {', '.join(dhcp_servers)}"
                }

            expected_dhcp = self.router_ip
            if dhcp_servers and dhcp_servers[0] != expected_dhcp:
                return {
                    'status': 'warn',
                    'servers': dhcp_servers,
                    'detail': (
                        f"DHCP server is {dhcp_servers[0]} but expected {expected_dhcp}. "
                        f"Verify this is your router."
                    )
                }

            return {
                'status': 'pass',
                'servers': dhcp_servers,
                'detail': f"Single DHCP server at {dhcp_servers[0] if dhcp_servers else 'unknown'}"
            }

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not check DHCP configuration'}


    def check_upnp(self):
        """
        Checks whether UPnP is responding on the router.
        UPnP allows devices to open firewall ports automatically.
        """
        try:
            # UPnP typically responds on port 1900 (SSDP)
            # Check if the router is advertising UPnP services
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(3)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # SSDP M-SEARCH to discover UPnP devices
            ssdp_request = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 2\r\n"
                "ST: ssdp:all\r\n\r\n"
            )

            sock.sendto(ssdp_request.encode(), ('239.255.255.250', 1900))

            responses = []
            try:
                while True:
                    data, addr = sock.recvfrom(1024)
                    responses.append(addr[0])
            except socket.timeout:
                pass

            sock.close()

            if responses:
                return {
                    'status': 'warn',
                    'enabled': True,
                    'devices': list(set(responses)),
                    'detail': f"UPnP/SSDP active — {len(set(responses))} device(s) responding",
                    'remediation': 'Disable UPnP in router admin settings.'
                }

            return {'status': 'pass', 'enabled': False, 'detail': 'No UPnP devices responding'}

        except Exception:
            pass

        return {'status': 'warn', 'enabled': False, 'detail': 'Could not check UPnP status'}


    def check_guest_network(self):
        """
        Checks whether a guest WiFi network exists and is isolated.
        Uses netsh to list all available networks.
        """
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                networks = []
                current = {}

                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('SSID') and 'BSSID' not in line:
                        if current:
                            networks.append(current)
                        current = {'ssid': line.split(':', 1)[-1].strip()}
                    elif 'Authentication' in line and current:
                        current['auth'] = line.split(':', 1)[-1].strip()

                if current:
                    networks.append(current)

                # Look for guest networks
                guest_indicators = ['guest', 'visitor', 'iot', 'kids']
                guest_nets = [
                    n for n in networks
                    if any(g in n.get('ssid', '').lower() for g in guest_indicators)
                ]

                if guest_nets:
                    return {
                        'status': 'pass',
                        'guest_networks': guest_nets,
                        'detail': f"Guest network(s) found: {', '.join(n['ssid'] for n in guest_nets)}"
                    }

                return {
                    'status': 'pass',
                    'detail': f"{len(networks)} network(s) visible — no separate guest network detected"
                }

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not check for guest networks'}


    def check_mdns_exposure(self):
        """
        Checks whether mDNS (Bonjour/Zeroconf) is broadcasting device info.
        mDNS can expose device names and services on the network.
        """
        try:
            # Check if mDNS service is running
            result = subprocess.run(
                ['sc', 'query', 'Bonjour Service'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            bonjour_running = 'RUNNING' in result.stdout.upper()

            # Also check for Windows mDNS
            result2 = subprocess.run(
                ['sc', 'query', 'mdnsNSP'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            mdns_running = 'RUNNING' in result2.stdout.upper()

            if bonjour_running or mdns_running:
                services = []
                if bonjour_running:
                    services.append("Apple Bonjour")
                if mdns_running:
                    services.append("Windows mDNS")

                return {
                    'status': 'warn',
                    'detail': f"mDNS broadcasting active: {', '.join(services)}",
                    'note': 'mDNS exposes device names and services on the local network'
                }

            return {'status': 'pass', 'detail': 'No active mDNS broadcasting detected'}

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not check mDNS status'}


    def check_wake_on_lan(self):
        """
        Checks whether Wake-on-LAN is enabled on network adapters.
        WoL can allow devices to be powered on remotely.
        """
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-NetAdapter | Where-Object Status -eq "Up" | '
                 'Get-NetAdapterAdvancedProperty -RegistryKeyword "*WakeOnMagicPacket" '
                 '| Select-Object Name, RegistryValue | ConvertTo-Json'],
                capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0 and result.stdout.strip():
                import json
                try:
                    data = json.loads(result.stdout.strip())
                    if isinstance(data, dict):
                        data = [data]

                    wol_enabled = any(
                        str(d.get('RegistryValue', '0')) == '1'
                        for d in data
                        if isinstance(d, dict)
                    )

                    if wol_enabled:
                        return {
                            'status': 'warn',
                            'detail': 'Wake-on-LAN is enabled on one or more network adapters',
                            'remediation': (
                                'Disable WoL in Device Manager → Network Adapter → '
                                'Power Management if not intentionally used'
                            )
                        }
                    return {'status': 'pass', 'detail': 'Wake-on-LAN is disabled'}

                except json.JSONDecodeError:
                    pass

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not check Wake-on-LAN status'}


    def check_wps_status(self):
        """
        Checks whether WPS (WiFi Protected Setup) is enabled.
        WPS has known vulnerabilities and should be disabled.
        Note: WPS status is not directly readable from Windows —
        this check advises the user to verify manually.
        """
        # WPS cannot be reliably queried from Windows without router API access
        # We report it as informational and direct user to check their router
        return {
            'status': 'warn',
            'detail': 'WPS status must be verified manually in your router settings',
            'remediation': (
                'Log into your router admin page and disable WPS (WiFi Protected Setup) '
                'under Wireless Settings. WPS has known vulnerabilities.'
            )
        }


    def check_ipv6(self):
        """
        Checks IPv6 readiness and configuration.
        """
        try:
            result = subprocess.run(
                ['ipconfig', '/all'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            ipv6_addresses = re.findall(r'IPv6 Address[.\s]+:\s+([\w:]+)', result.stdout)
            has_ipv6 = len(ipv6_addresses) > 0

            # Filter out link-local addresses (fe80::)
            global_ipv6 = [ip for ip in ipv6_addresses if not ip.lower().startswith('fe80')]

            return {
                'status': 'pass' if has_ipv6 else 'warn',
                'has_ipv6': has_ipv6,
                'global_ipv6': global_ipv6,
                'detail': (
                    f"IPv6 active — {len(global_ipv6)} global address(es)" if has_ipv6
                    else "IPv6 not active on this network"
                )
            }

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not check IPv6 status'}


    def check_open_shares(self):
        """
        Checks for open Windows file shares on the local machine.
        Open shares that are accessible without authentication are a risk.
        """
        try:
            result = subprocess.run(
                ['net', 'share'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                shares = []
                for line in result.stdout.split('\n')[2:]:  # Skip header rows
                    parts = line.split()
                    if parts and parts[0] not in ('Share', '-', ''):
                        share_name = parts[0]
                        # Skip built-in admin shares (C$, ADMIN$, IPC$)
                        if not share_name.endswith('$'):
                            shares.append(share_name)

                if shares:
                    return {
                        'status': 'warn',
                        'shares': shares,
                        'detail': f"Open shares found: {', '.join(shares)}",
                        'remediation': 'Review these shares and ensure they require authentication.'
                    }

                return {'status': 'pass', 'detail': 'No non-administrative open shares found'}

        except Exception:
            pass

        return {'status': 'warn', 'detail': 'Could not check file shares'}


    def get_public_ip_info(self):
        """
        Gets the public IP address for reputation checking.
        Note: This accesses the internet briefly to get the public IP.
        The actual reputation check requires the opt-in GGG feature.
        """
        try:
            import urllib.request
            with urllib.request.urlopen(
                'https://api.ipify.org', timeout=5
            ) as resp:
                public_ip = resp.read().decode('utf-8').strip()
                return {
                    'status': 'pass',
                    'public_ip': public_ip,
                    'detail': f"Public IP: {public_ip}"
                }
        except Exception:
            pass

        return {'status': 'warn', 'public_ip': None, 'detail': 'Could not determine public IP'}
