"""
=============================================================
  SENTINELHOME101 — Scan Coordinator
  File: modules/scan_coordinator.py

  The central coordinator that runs a complete scan.

  Orchestrates:
  1. Host security checks (modules/ui/host_tab.py checks)
  2. Network device discovery (scanner.py)
  3. Network security checks (network_checks.py)
  4. Threat detection checks
  5. Performance measurements
  6. Security analysis and scoring (analyzer.py)
  7. Results storage in database
  8. Dashboard and UI updates

  This is what gets called when the user presses Run Scan.
  It runs in a background thread so the UI stays responsive.
=============================================================
"""

import threading
import datetime
import os
from modules.constants import *
from modules.scanner import NetworkScanner
from modules.network_checks import NetworkChecker
from modules.analyzer import SecurityAnalyzer

# Suppress console window flash on every subprocess call (Windows)
CREATE_NO_WINDOW = 0x08000000


class ScanCoordinator:
    """
    Orchestrates a complete SentinelHome101 security scan.

    Manages the scan lifecycle:
    - Start scan in background thread
    - Report progress to UI
    - Coordinate all check modules
    - Store results in database
    - Deliver final results to UI callbacks
    """

    def __init__(self, db, app_data_dir, progress_callback=None,
                 complete_callback=None, status_callback=None):
        """
        Parameters:
            db                : Database instance.
            app_data_dir      : Path to AppData/Roaming/SentinelHome101/.
            progress_callback : Called with (message, percent) during scan.
            complete_callback : Called with (results_dict) when scan finishes.
            status_callback   : Called with (message, state) for status bar.
        """
        self.db = db
        self.app_data_dir = app_data_dir

        # Callbacks — use no-ops if not provided
        self.progress_cb = progress_callback or (lambda msg, pct: None)
        self.complete_cb = complete_callback or (lambda results: None)
        self.status_cb   = status_callback   or (lambda msg, state: None)

        # Build OUI database path
        # First try the project assets folder, then AppData
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.oui_path = os.path.join(script_dir, OUI_DATABASE_FILE)
        if not os.path.exists(self.oui_path):
            self.oui_path = os.path.join(app_data_dir, 'oui_database.txt')

        self.is_scanning = False    # Prevent simultaneous scans
        self._scan_thread = None


    def start_scan(self, profile=DEFAULT_SCAN_PROFILE):
        """
        Starts a scan in a background thread.

        Parameters:
            profile (str): 'quick', 'standard', or 'deep'

        Returns:
            bool: True if scan started, False if already scanning.
        """
        if self.is_scanning:
            return False    # Scan already in progress

        self.is_scanning = True
        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(profile,),
            daemon=True     # Thread dies when app closes
        )
        self._scan_thread.start()
        return True


    def _run_scan(self, profile):
        """
        The actual scan logic. Runs in a background thread.

        Parameters:
            profile (str): Scan profile to use.
        """
        start_time = datetime.datetime.now()
        self.status_cb("Scan in progress...", "scanning")

        try:
            # Initialize modules
            analyzer = SecurityAnalyzer(self.db)
            analyzer.reset()

            scanner = NetworkScanner(
                oui_db_path=self.oui_path,
                progress_callback=self.progress_cb
            )

            # =========================================================
            # PHASE 1: Host security checks (features 1-15)
            # =========================================================
            self.progress_cb("Running host security checks...", 5)

            from modules.ui.host_tab import HostTab
            host_checker = HostTab.__new__(HostTab)
            host_checker.db = self.db

            host_results = self._run_host_checks(host_checker, analyzer)

            # =========================================================
            # PHASE 2: Network discovery (features 16-30)
            # =========================================================
            self.progress_cb("Discovering devices on network...", 20)

            network_scan = scanner.run_full_scan(profile)
            local_ip = network_scan.get('local_ip', '')
            devices = network_scan.get('devices', [])

            # =========================================================
            # PHASE 3: Network security checks (features 11-30)
            # =========================================================
            self.progress_cb("Running network security checks...", 60)

            net_checker = NetworkChecker(local_ip=local_ip)
            network_check_results = net_checker.run_all_checks()

            # Analyze network results
            device_analyses = analyzer.analyze_network(
                network_scan, network_check_results
            )

            # =========================================================
            # PHASE 4: Threat detection (features 31-41)
            # =========================================================
            self.progress_cb("Running threat detection...", 75)

            self._run_threat_checks(analyzer, devices, network_check_results)

            # =========================================================
            # PHASE 5: Performance checks (features 60-66)
            # =========================================================
            if profile in ('standard', 'deep'):
                self.progress_cb("Measuring network performance...", 85)
                perf_results = self._run_performance_checks(scanner, local_ip)
            else:
                perf_results = {}

            # =========================================================
            # PHASE 6: Canary file check (feature 6)
            # =========================================================
            self.progress_cb("Verifying ransomware canary files...", 90)
            canary_status = self._check_canary_files()

            # =========================================================
            # FINALIZE: Score, save, and deliver results
            # =========================================================
            self.progress_cb("Calculating security score...", 95)

            end_time = datetime.datetime.now()
            duration_secs = int((end_time - start_time).total_seconds())

            # Get all findings sorted by severity
            findings = analyzer.get_findings()
            score = analyzer.get_score()
            stats = analyzer.calculate_summary_stats()

            # Update device database records
            for device in devices:
                self.db.upsert_device(
                    mac_address=device.get('mac', 'Unknown'),
                    ip_address=device.get('ip', ''),
                    hostname=device.get('hostname', 'Unknown'),
                    manufacturer=device.get('manufacturer', 'Unknown')
                )

            # Save scan to history
            network_name = self.db.get_setting('network_name', 'Home Network')
            scan_id = self.db.save_scan(
                scan_type=profile,
                duration_secs=duration_secs,
                devices_found=len(devices),
                critical_count=stats['critical'],
                warning_count=stats['warnings'],
                score=score,
                network_name=network_name
            )

            # Save individual findings
            for finding in findings:
                self.db.save_finding(
                    scan_id=scan_id,
                    feature_number=finding.get('feature_number', 0),
                    severity=finding['severity'],
                    title=finding['title'],
                    detail=finding.get('detail', ''),
                    device_ip=finding.get('device_ip', ''),
                    remediation=finding.get('remediation', '')
                )

            # Build complete results package for UI
            results = {
                'findings':         findings,
                'score':            score,
                'stats': {
                    'critical':     stats['critical'],
                    'warnings':     stats['warnings'],
                    'devices':      len(devices),
                    'checks':       101,
                },
                'scan_info': {
                    'scan_id':      scan_id,
                    'scan_date':    start_time.isoformat(),
                    'scan_type':    profile,
                    'duration_secs':duration_secs,
                },
                'devices':          devices,
                'device_analyses':  device_analyses,
                'network_checks':   network_check_results,
                'performance':      perf_results,
                'canary':           canary_status,
                'local_ip':         local_ip,
                'network_range':    network_scan.get('network_range', ''),
            }

            self.progress_cb("Scan complete!", 100)
            self.status_cb(
                f"Scan complete — {stats['critical']} critical, "
                f"{stats['warnings']} warnings · Score: {score}/100",
                "ready" if stats['critical'] == 0 else "warning"
            )

            # Deliver results to UI on the main thread via callback
            self.complete_cb(results)

        except Exception as e:
            # Scan failed — report error
            self.status_cb(f"Scan error: {str(e)[:60]}", "error")
            self.progress_cb(f"Scan failed: {str(e)[:80]}", 0)

        finally:
            self.is_scanning = False    # Always reset scanning flag


    def _run_host_checks(self, host_checker, analyzer):
        """
        Runs all host security checks and adds findings to analyzer.

        Parameters:
            host_checker : HostTab instance (used just for its check methods).
            analyzer     : SecurityAnalyzer to add findings to.

        Returns:
            dict: All host check results.
        """
        results = {}

        # Map of check method → (feature_number, friendly_name)
        checks = [
            (host_checker._check_antivirus,         1,  "Antivirus"),
            (host_checker._check_defender_exclusions,2,  "Defender exclusions"),
            (host_checker._check_event_log_tampering,3,  "Event log integrity"),
            (host_checker._check_os_patches,         4,  "OS patches"),
            (host_checker._check_backup,             5,  "Backup status"),
            (host_checker._check_canary_files,       6,  "Canary files"),
            (host_checker._check_bitlocker,          7,  "BitLocker"),
            (host_checker._check_secure_boot,        8,  "Secure Boot"),
            (host_checker._check_user_accounts,      9,  "User accounts"),
            (host_checker._check_credential_manager, 10, "Credential Manager"),
            (host_checker._check_macro_policy,       11, "Macro policy"),
            (host_checker._check_remote_registry,    12, "Remote Registry"),
            (host_checker._check_audit_logs,         13, "Audit logs"),
            (host_checker._check_screen_lock,        14, "Screen lock"),
            (host_checker._check_pagefile,           15, "Pagefile"),
        ]

        for check_fn, feature_num, name in checks:
            try:
                result = check_fn()
                results[name] = result

                # Convert non-pass results into findings
                if result.get('status') in ('fail', 'warn'):
                    severity = result.get('severity', SEVERITY_WARNING)
                    analyzer.add_finding(
                        feature_number=feature_num,
                        severity=severity,
                        title=f"{name}: {result.get('value', 'issue detected')}",
                        detail=result.get('detail', ''),
                        remediation=result.get('remediation', '')
                    )

            except Exception as e:
                results[name] = {
                    'status': 'warn',
                    'value': 'error',
                    'detail': f"Check failed: {str(e)[:60]}"
                }

        return results


    def _run_threat_checks(self, analyzer, devices, network_checks):
        """
        Runs threat-specific checks (features 31-41).

        Parameters:
            analyzer        : SecurityAnalyzer instance.
            devices         : List of discovered devices.
            network_checks  : Results from NetworkChecker.
        """
        # --- Botnet behavior detection (Feature 31) ---
        self._check_botnet_behavior(analyzer, devices)

        # --- Network check results that are threat-level ---
        arp = network_checks.get('arp_spoofing', {})
        if arp.get('status') == 'warn':
            analyzer.add_finding(
                feature_number=32,
                severity=SEVERITY_WARNING,
                title="Possible ARP spoofing detected",
                detail=arp.get('detail', ''),
                remediation=(
                    "Check your network for unauthorized devices. "
                    "A device may be performing a man-in-the-middle attack."
                )
            )

        dhcp = network_checks.get('rogue_dhcp', {})
        if dhcp.get('status') == 'warn':
            analyzer.add_finding(
                feature_number=33,
                severity=SEVERITY_WARNING,
                title="Rogue DHCP server detected",
                detail=dhcp.get('detail', ''),
                remediation=(
                    "Verify all DHCP servers on your network are legitimate. "
                    "An unauthorized DHCP server could redirect your traffic."
                )
            )


    def _check_botnet_behavior(self, analyzer, devices):
        """
        Checks for botnet-like behavior by monitoring connection counts.
        Uses netstat to count outbound connections per device.

        Feature 31: Botnet / compromised device behavior detector.
        """
        try:
            import subprocess
            result = subprocess.run(
                ['netstat', '-n', '-o'],
                capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode != 0:
                return

            # Count outbound connections per remote IP
            # A device making hundreds of connections is suspicious
            connection_counts = {}
            for line in result.stdout.split('\n'):
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] == 'TCP':
                    remote = parts[2]
                    if ':' in remote:
                        remote_ip = remote.rsplit(':', 1)[0]
                        connection_counts[remote_ip] = connection_counts.get(remote_ip, 0) + 1

            # Flag if total external connections is very high
            # (normal is <50, suspicious is >200)
            total_ext = sum(
                count for ip, count in connection_counts.items()
                if not ip.startswith('192.168.') and
                   not ip.startswith('10.') and
                   not ip.startswith('172.') and
                   not ip.startswith('127.')
            )

            if total_ext > 200:
                analyzer.add_finding(
                    feature_number=31,
                    severity=SEVERITY_CRITICAL,
                    title=f"Unusual outbound connections: {total_ext} active",
                    detail=(
                        f"This machine has {total_ext} active outbound connections — "
                        f"far above normal. This may indicate malware, adware, "
                        f"or botnet activity."
                    ),
                    remediation=(
                        "Run a full antivirus scan immediately. "
                        "Check Task Manager → Processes for suspicious programs. "
                        "Consider running Windows Malicious Software Removal Tool."
                    )
                )

        except Exception:
            pass


    def _run_performance_checks(self, scanner, local_ip):
        """
        Runs network performance checks.
        Features 85-92: packet loss, latency, uptime, bandwidth.
        """
        results = {}

        try:
            # Ping the router to measure latency
            if local_ip:
                parts = local_ip.split('.')
                router_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"

                import subprocess
                result = subprocess.run(
                    ['ping', '-n', '10', router_ip],
                    capture_output=True, text=True, timeout=30, creationflags=CREATE_NO_WINDOW
                )

                if result.returncode == 0:
                    # Parse ping statistics
                    output = result.stdout

                    # Extract average round trip time
                    avg_match = __import__('re').search(
                        r'Average = (\d+)ms', output
                    )
                    loss_match = __import__('re').search(
                        r'(\d+)% loss', output
                    )

                    avg_ms = int(avg_match.group(1)) if avg_match else 0
                    loss_pct = int(loss_match.group(1)) if loss_match else 0

                    results['latency_ms'] = avg_ms
                    results['packet_loss_pct'] = loss_pct
                    results['router_ip'] = router_ip

        except Exception:
            pass

        return results


    def _check_canary_files(self):
        """
        Verifies ransomware canary files are still intact.

        Returns:
            list: Canary file status records.
        """
        import hashlib

        canary_files = self.db.get_canary_files()
        statuses = []

        for cf in canary_files:
            path = cf['file_path']
            stored_hash = cf['file_hash']
            status = 'intact'

            if not os.path.exists(path):
                status = 'missing'
            else:
                try:
                    with open(path, 'rb') as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()
                    status = 'intact' if current_hash == stored_hash else 'tampered'
                    if status == 'intact':
                        self.db.update_canary_status(path, 'intact', current_hash)
                    else:
                        self.db.update_canary_status(path, 'tampered', current_hash)
                except Exception:
                    status = 'error'

            statuses.append({
                'file_path': path,
                'status': status
            })

        return statuses
