"""
=============================================================
  SENTINELHOME101 — Security Analysis Engine
  File: modules/analyzer.py

  Takes raw scan data and generates:
  - Security findings with severity levels
  - Remediation guidance for each finding
  - Network score (0-100)
  - Change detection vs previous scans
  - Risk score per device

  This is the brain of SentinelHome101 — it interprets
  raw data and turns it into actionable security findings.
=============================================================
"""

import os
import socket
import subprocess
import re
import datetime
import winreg
from modules.constants import *


class SecurityAnalyzer:
    """
    Analyzes scan results and generates security findings.

    Takes raw network scan data and host check results,
    applies security rules, and produces prioritized findings
    with plain-English explanations and remediation steps.
    """

    def __init__(self, db, oui_lookup_func=None):
        """
        Parameters:
            db              : Database instance for historical comparisons.
            oui_lookup_func : Function to look up manufacturer from MAC.
        """
        self.db = db
        self.oui_lookup = oui_lookup_func or (lambda mac: "Unknown")
        self.findings = []      # Accumulated findings for current scan
        self.score = 100        # Current score, reduced by penalties


    def reset(self):
        """Resets findings and score for a new scan."""
        self.findings = []
        self.score = 100


    def add_finding(self, feature_number, severity, title, detail,
                    device_ip='', remediation=''):
        """
        Adds a security finding to the current scan's results.

        Parameters:
            feature_number (int): Which of the 101 features triggered this.
            severity       (str): SEVERITY_CRITICAL/WARNING/INFO/PASS
            title          (str): Short description.
            detail         (str): Full plain-English explanation.
            device_ip      (str): IP of affected device (if applicable).
            remediation    (str): How to fix this.
        """
        finding = {
            'feature_number': feature_number,
            'severity':       severity,
            'title':          title,
            'detail':         detail,
            'device_ip':      device_ip,
            'remediation':    remediation,
        }
        self.findings.append(finding)

        # Apply score penalty
        penalty = SCORE_PENALTY.get(severity, 0)
        self.score = max(0, self.score - penalty)


    def get_findings(self):
        """
        Returns findings sorted by severity (critical first).

        Returns:
            list: Sorted findings list.
        """
        order = {
            SEVERITY_CRITICAL: 0,
            SEVERITY_WARNING:  1,
            SEVERITY_INFO:     2,
            SEVERITY_PASS:     3
        }
        return sorted(self.findings,
                      key=lambda f: order.get(f['severity'], 4))


    def get_score(self):
        """Returns the current network score (0-100)."""
        return max(0, min(100, self.score))


    # =================================================================
    # NETWORK ANALYSIS METHODS
    # These analyze data returned by the NetworkScanner
    # =================================================================

    def analyze_device(self, device):
        """
        Analyzes a single device's scan results and generates findings.

        Parameters:
            device (dict): Device data from NetworkScanner.full_device_scan()

        Returns:
            dict: Analysis results including risk score for this device.
        """
        ip = device.get('ip', '')
        mac = device.get('mac', 'Unknown')
        manufacturer = device.get('manufacturer', 'Unknown')
        open_ports = device.get('open_ports', [])
        hostname = device.get('hostname', 'Unknown')

        device_findings = []
        device_risk = 0     # Risk score for this specific device

        # --- Check for Telnet (Feature 7: Port banner/service) ---
        if any(p['port'] == 23 for p in open_ports):
            self.add_finding(
                feature_number=7,
                severity=SEVERITY_CRITICAL,
                title=f"Telnet open on {hostname or ip}",
                detail=(
                    f"Telnet (port 23) is open on {ip}. Telnet sends all data "
                    f"including passwords in plain text — anyone on your network "
                    f"can intercept this traffic."
                ),
                device_ip=ip,
                remediation=(
                    "Log into the device's settings and disable Telnet. "
                    "If it is a smart TV or IoT device, check the device's "
                    "support documentation or contact the manufacturer."
                )
            )
            device_risk += 30

        # --- Check for FTP (Feature 7) ---
        if any(p['port'] == 21 for p in open_ports):
            self.add_finding(
                feature_number=7,
                severity=SEVERITY_WARNING,
                title=f"FTP open on {hostname or ip}",
                detail=(
                    f"FTP (port 21) is open on {ip}. FTP transmits "
                    f"files and login credentials without encryption."
                ),
                device_ip=ip,
                remediation=(
                    "Disable FTP if not actively used. Use SFTP (port 22) "
                    "as a secure alternative if file transfer is needed."
                )
            )
            device_risk += 15

        # --- Check for RDP (Feature 32: Network awareness) ---
        if any(p['port'] == 3389 for p in open_ports):
            self.add_finding(
                feature_number=32,
                severity=SEVERITY_WARNING,
                title=f"Remote Desktop open on {hostname or ip}",
                detail=(
                    f"Remote Desktop (RDP, port 3389) is open on {ip}. "
                    f"RDP is a common attack target. If you did not "
                    f"intentionally enable this, disable it immediately."
                ),
                device_ip=ip,
                remediation=(
                    "If this is a Windows PC: Settings → System → Remote Desktop → Turn Off. "
                    "If this is another device, consult its documentation."
                )
            )
            device_risk += 20

        # --- Check for UPnP (Feature 59: ICMP/network) ---
        if any(p['port'] == 49152 for p in open_ports):
            self.add_finding(
                feature_number=59,
                severity=SEVERITY_WARNING,
                title=f"UPnP active on {hostname or ip}",
                detail=(
                    f"UPnP (port 49152) is detected on {ip}. "
                    f"UPnP allows devices to automatically open "
                    f"ports in your firewall without your knowledge."
                ),
                device_ip=ip,
                remediation=(
                    "Log into your router admin page (usually 192.168.1.1 "
                    "or 192.168.0.1) and disable UPnP in the advanced settings."
                )
            )
            device_risk += 10

        # --- Check for unencrypted web interfaces (Feature 7) ---
        has_http = any(p['port'] == 80 for p in open_ports)
        has_https = any(p['port'] == 443 for p in open_ports)

        if has_http and not has_https:
            self.add_finding(
                feature_number=7,
                severity=SEVERITY_INFO,
                title=f"Unencrypted web interface on {hostname or ip}",
                detail=(
                    f"HTTP (port 80) is open on {ip} but HTTPS (port 443) is not. "
                    f"This device's web interface is accessible without encryption."
                ),
                device_ip=ip,
                remediation=(
                    "Check the device's settings for an HTTPS option and enable it. "
                    "Many routers offer HTTPS-only admin access."
                )
            )
            device_risk += 5

        # --- Check for unknown devices (Feature 28: MAC lookup) ---
        if manufacturer == "Unknown" and mac not in ('Unknown', 'Not found'):
            self.add_finding(
                feature_number=28,
                severity=SEVERITY_INFO,
                title=f"Unknown manufacturer device at {ip}",
                detail=(
                    f"Device at {ip} (MAC: {mac}) has an unrecognized manufacturer. "
                    f"This may be a new device or one using a virtual/spoofed MAC address."
                ),
                device_ip=ip,
                remediation=(
                    "Check your router's connected devices list and verify this "
                    "device belongs on your network. If unrecognized, investigate "
                    "and consider changing your WiFi password."
                )
            )
            device_risk += 5

        # --- Check for IoT devices (Feature 56: IoT isolation) ---
        iot_manufacturers = [
            'wyze', 'ring', 'nest', 'arlo', 'amazon', 'google',
            'samsung', 'lg', 'sony', 'philips', 'tp-link', 'tplink'
        ]
        is_iot = any(m in manufacturer.lower() for m in iot_manufacturers)

        if is_iot and has_http:
            self.add_finding(
                feature_number=56,
                severity=SEVERITY_INFO,
                title=f"IoT device with open web port: {manufacturer}",
                detail=(
                    f"IoT device {manufacturer} at {ip} has an open web "
                    f"interface. IoT devices are commonly targeted due to "
                    f"weak default security configurations."
                ),
                device_ip=ip,
                remediation=(
                    "Ensure this device has the latest firmware. "
                    "Consider placing IoT devices on a separate guest network "
                    "to isolate them from your main computers."
                )
            )
            device_risk += 5

        # Calculate device risk score (0-100, lower is worse)
        device_score = max(0, 100 - device_risk)

        return {
            'device':       device,
            'findings':     device_findings,
            'risk_score':   device_score,
        }


    def analyze_network(self, scan_results, network_checks):
        """
        Analyzes the full network scan results and generates findings.

        Parameters:
            scan_results   (dict): From NetworkScanner.run_full_scan()
            network_checks (dict): From NetworkChecker.run_all_checks()
        """
        devices = scan_results.get('devices', [])

        # --- Analyze each device ---
        device_analyses = []
        for device in devices:
            analysis = self.analyze_device(device)
            device_analyses.append(analysis)

        # --- Check for change detection (Feature 47) ---
        self._check_new_devices(devices)

        # --- Network-level findings from network_checks ---
        self._process_network_checks(network_checks)

        return device_analyses


    def _check_new_devices(self, devices):
        """
        Compares current devices against database history.
        Flags any new devices that weren't seen before.
        """
        known_devices = self.db.get_all_devices()
        known_macs = {d['mac_address'] for d in known_devices}

        for device in devices:
            mac = device.get('mac', 'Unknown')
            if mac not in ('Unknown', 'Not found') and mac not in known_macs:
                self.add_finding(
                    feature_number=47,
                    severity=SEVERITY_INFO,
                    title=f"New device appeared: {device.get('manufacturer', 'Unknown')}",
                    detail=(
                        f"A new device was found at {device.get('ip', '?')} "
                        f"(MAC: {mac}, Manufacturer: {device.get('manufacturer', 'Unknown')}). "
                        f"This device has not been seen before."
                    ),
                    device_ip=device.get('ip', ''),
                    remediation=(
                        "Verify this device belongs on your network. "
                        "If unrecognized, check your router's connected devices "
                        "list and consider changing your WiFi password."
                    )
                )


    def _process_network_checks(self, checks):
        """
        Converts network check results into findings.

        Parameters:
            checks (dict): Results from NetworkChecker methods.
        """
        if not checks:
            return

        # WiFi security
        wifi = checks.get('wifi_security', {})
        if wifi.get('status') == 'fail':
            self.add_finding(
                feature_number=17,
                severity=SEVERITY_CRITICAL,
                title="Weak WiFi security protocol",
                detail=wifi.get('detail', 'WiFi security is misconfigured.'),
                remediation=wifi.get('remediation', 'Enable WPA3 in your router settings.')
            )

        # DNS hijacking
        dns = checks.get('dns_security', {})
        if dns.get('hijacked'):
            self.add_finding(
                feature_number=24,
                severity=SEVERITY_CRITICAL,
                title="DNS hijacking detected",
                detail="Your DNS responses appear to be tampered with. "
                       "This can redirect your web traffic to malicious sites.",
                remediation=(
                    "Log into your router and manually set DNS servers to "
                    "1.1.1.1 (Cloudflare) and 8.8.8.8 (Google). "
                    "Consider factory resetting your router if this persists."
                )
            )

        # Router default credentials
        router = checks.get('router_credentials', {})
        if router.get('default_likely'):
            self.add_finding(
                feature_number=21,
                severity=SEVERITY_CRITICAL,
                title="Router may be using default credentials",
                detail=(
                    f"Your router ({router.get('brand', 'Unknown')}) may still "
                    f"be using factory default login credentials, which are "
                    f"publicly documented and easy for attackers to use."
                ),
                remediation=(
                    "Log into your router admin page and change the admin "
                    "password to something strong and unique. The default "
                    "credentials are often printed on the router's label."
                )
            )

        # Firewall status
        fw = checks.get('firewall', {})
        if fw.get('status') == 'fail':
            self.add_finding(
                feature_number=16,
                severity=SEVERITY_CRITICAL,
                title="Windows Firewall is disabled",
                detail=(
                    f"Windows Firewall is disabled on one or more profiles: "
                    f"{fw.get('detail', 'check firewall settings')}."
                ),
                remediation=(
                    "Open Windows Security → Firewall & network protection "
                    "and enable the firewall for all three profiles "
                    "(Domain, Private, Public)."
                )
            )

        # UPnP on router
        upnp = checks.get('upnp', {})
        if upnp.get('enabled'):
            self.add_finding(
                feature_number=59,
                severity=SEVERITY_WARNING,
                title="UPnP enabled on router",
                detail=(
                    "UPnP is enabled on your router. This allows devices to "
                    "automatically open ports in your firewall without your "
                    "knowledge or approval."
                ),
                remediation=(
                    "Log into your router admin page and disable UPnP. "
                    "Check Advanced Settings or Security settings."
                )
            )


    def calculate_device_score(self, device_analysis):
        """
        Calculates a 0-100 risk score for a single device.
        Higher score = safer device.

        Parameters:
            device_analysis (dict): From analyze_device()

        Returns:
            int: Risk score 0-100.
        """
        return device_analysis.get('risk_score', 100)


    def calculate_summary_stats(self, findings=None):
        """
        Calculates summary statistics for the findings feed.

        Parameters:
            findings (list): Findings to summarize. Uses self.findings if None.

        Returns:
            dict: Stats dictionary with counts by severity.
        """
        if findings is None:
            findings = self.findings

        return {
            'critical': sum(1 for f in findings if f['severity'] == SEVERITY_CRITICAL),
            'warnings': sum(1 for f in findings if f['severity'] == SEVERITY_WARNING),
            'info':     sum(1 for f in findings if f['severity'] == SEVERITY_INFO),
            'passed':   sum(1 for f in findings if f['severity'] == SEVERITY_PASS),
            'total':    len(findings),
        }
