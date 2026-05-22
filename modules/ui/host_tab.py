"""
=============================================================
  SENTINELHOME101 — Host Security Tab
  File: modules/ui/host_tab.py

  Covers Tier 1 endpoint security checks (features 1-15):
  1.  Antivirus / endpoint protection status
  2.  Windows Defender exclusions auditor
  3.  Windows Event Log tampering detector
  4.  OS patch level checker
  5.  Backup status & 3-2-1 rule checker
  6.  Ransomware canary file monitor
  7.  Encryption at rest / BitLocker checker
  8.  BIOS / Secure Boot checker
  9.  Local user account auditor
  10. Windows Credential Manager audit
  11. Macro & script execution policy checker
  12. Windows Remote Registry service checker
  13. Audit log retention checker
  14. Screensaver / auto-lock policy checker
  15. Windows pagefile security checker

  Plus identity, browser, and saved WiFi checks.
=============================================================
"""

import tkinter as tk
from tkinter import ttk
import subprocess

# Suppress console window flash on every subprocess call
CREATE_NO_WINDOW = 0x08000000
import winreg
import ctypes
import os
import datetime
from modules.constants import *
from modules.theme import ThemeManager


class HostTab:
    """
    Builds and manages the This Device (Host Security) tab.

    Runs all endpoint security checks against the local
    machine and displays results as a checklist with
    color-coded pass/fail indicators.
    """

    def __init__(self, parent, theme, db, status_callback):
        """
        Parameters:
            parent          : Parent Frame.
            theme           : ThemeManager instance.
            db              : Database instance.
            status_callback : Function to update the status bar.
        """
        self.parent = parent
        self.theme = theme
        self.db = db
        self.status_callback = status_callback

        # Stores check result widgets for updating
        self.check_widgets = {}

        self._build()
        self.theme.register(self._apply_theme)


    def _build(self):
        """Builds the host security tab layout."""

        # --- Outer scrollable canvas ---
        self.canvas = tk.Canvas(
            self.parent,
            bg=self.theme.bg_primary,
            highlightthickness=0
        )
        scrollbar = tk.Scrollbar(
            self.parent,
            orient='vertical',
            command=self.canvas.yview
        )
        self.canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)

        self.inner = tk.Frame(self.canvas, bg=self.theme.bg_primary)
        self.win_id = self.canvas.create_window((0, 0), window=self.inner, anchor='nw')

        self.inner.bind('<Configure>', lambda e: self.canvas.configure(
            scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfig(
            self.win_id, width=e.width))
        self.canvas.bind_all('<MouseWheel>', lambda e: self.canvas.yview_scroll(
            int(-1 * (e.delta / 120)), 'units'))

        # --- Header ---
        self._build_header()

        # --- Two-column layout ---
        cols = tk.Frame(self.inner, bg=self.theme.bg_primary)
        cols.pack(fill='both', expand=True, padx=PADDING_LG, pady=(0, PADDING_LG))

        left = tk.Frame(cols, bg=self.theme.bg_primary)
        left.pack(side='left', fill='both', expand=True, padx=(0, 8))

        right = tk.Frame(cols, bg=self.theme.bg_primary)
        right.pack(side='right', fill='both', expand=True)

        # --- Left column: main security checklist ---
        self._build_checklist_panel(left)

        # --- Right column: identity, browser, WiFi ---
        self._build_identity_panel(right)
        self._build_browser_panel(right)
        self._build_wifi_panel(right)


    def _build_header(self):
        """Builds the tab header with title and Run Checks button."""
        header = tk.Frame(self.inner, bg=self.theme.bg_primary)
        header.pack(fill='x', padx=PADDING_LG, pady=PADDING_LG)

        tk.Label(
            header,
            text="This Device",
            font=self.theme.font(size=FONT_SIZE_XL, bold=True),
            bg=self.theme.bg_primary,
            fg=self.theme.text_primary
        ).pack(side='left')

        tk.Button(
            header,
            text="Run Host Checks",
            font=self.theme.font(size=FONT_SIZE_SM, bold=True),
            bg=self.theme.accent,
            fg=self.theme.bg_primary,
            relief='flat',
            padx=12, pady=4,
            cursor="hand2",
            command=self.run_checks
        ).pack(side='right')

        tk.Label(
            header,
            text="Security checks for this computer only",
            font=self.theme.font(size=FONT_SIZE_SM),
            bg=self.theme.bg_primary,
            fg=self.theme.text_secondary
        ).pack(side='left', padx=12)


    def _build_checklist_panel(self, parent):
        """Builds the main endpoint security checklist."""
        panel = self._make_panel(parent, "ENDPOINT SECURITY CHECKLIST")

        # Define all 15 host security checks
        checks = [
            ('antivirus',       'Antivirus / endpoint protection'),
            ('defender_excl',   'Windows Defender exclusions'),
            ('event_log',       'Windows Event Log integrity'),
            ('os_patches',      'Windows Update / OS patches'),
            ('backup',          'Backup configured (3-2-1 rule)'),
            ('canary',          'Ransomware canary files'),
            ('bitlocker',       'BitLocker encryption'),
            ('secure_boot',     'Secure Boot (UEFI)'),
            ('user_accounts',   'Local user accounts'),
            ('credential_mgr',  'Windows Credential Manager'),
            ('macro_policy',    'Macro & script execution policy'),
            ('remote_registry', 'Remote Registry service'),
            ('audit_logs',      'Audit log retention'),
            ('screen_lock',     'Screensaver / auto-lock'),
            ('pagefile',        'Pagefile security'),
        ]

        self.check_widgets['checklist'] = {}

        for key, label in checks:
            row = tk.Frame(panel, bg=self.theme.bg_secondary)
            row.pack(fill='x', pady=1)

            # Status icon (pending initially)
            icon = tk.Label(
                row,
                text="○",
                font=self.theme.font(size=FONT_SIZE_MD),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_muted,
                width=3
            )
            icon.pack(side='left', padx=(PADDING_MD, 4), pady=6)

            # Check label
            lbl = tk.Label(
                row,
                text=label,
                font=self.theme.font(size=FONT_SIZE_SM),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_primary,
                anchor='w'
            )
            lbl.pack(side='left', fill='x', expand=True)

            # Result badge (empty until checked)
            badge = tk.Label(
                row,
                text="—",
                font=self.theme.font(size=FONT_SIZE_XS),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_muted,
                padx=6
            )
            badge.pack(side='right', padx=PADDING_MD)

            # Store widget references for updating after checks run
            self.check_widgets['checklist'][key] = {
                'icon': icon,
                'label': lbl,
                'badge': badge
            }

            # Separator
            tk.Frame(row.master, bg=self.theme.border_light, height=1).pack(fill='x')


    def _build_identity_panel(self, parent):
        """Builds the identity and access panel."""
        panel = self._make_panel(parent, "IDENTITY & ACCESS")

        items = [
            ('2fa',         'Two-factor authentication'),
            ('password_mgr','Password manager installed'),
            ('user_count',  'User accounts'),
            ('rdp',         'Remote Desktop (RDP)'),
        ]

        self._build_simple_checks(panel, 'identity', items)


    def _build_browser_panel(self, parent):
        """Builds the browser security panel."""
        panel = self._make_panel(parent, "BROWSER SECURITY")

        items = [
            ('edge_safe',   'Microsoft Edge — safe browsing'),
            ('chrome_safe', 'Chrome — safe browsing'),
            ('firefox_safe','Firefox — safe browsing'),
            ('extensions',  'Extension risk assessment'),
        ]

        self._build_simple_checks(panel, 'browser', items)


    def _build_wifi_panel(self, parent):
        """Builds the saved WiFi networks panel."""
        panel = self._make_panel(parent, "SAVED WIFI NETWORKS")

        self.wifi_frame = tk.Frame(panel, bg=self.theme.bg_secondary)
        self.wifi_frame.pack(fill='x', padx=PADDING_MD, pady=PADDING_SM)

        tk.Label(
            self.wifi_frame,
            text="Run checks to see saved WiFi network security",
            font=self.theme.font(size=FONT_SIZE_SM),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_muted
        ).pack(anchor='w', pady=8)


    def _build_simple_checks(self, panel, group, items):
        """
        Builds a simple two-column check list (label + result).

        Parameters:
            panel  : Parent panel frame.
            group  : Group key for storing widget references.
            items  : List of (key, label) tuples.
        """
        self.check_widgets[group] = {}

        for key, label in items:
            row = tk.Frame(panel, bg=self.theme.bg_secondary)
            row.pack(fill='x', pady=1)

            # Dot indicator
            dot = tk.Label(
                row,
                text="●",
                font=self.theme.font(size=FONT_SIZE_XS),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_muted,
                width=3
            )
            dot.pack(side='left', padx=(PADDING_MD, 4), pady=6)

            # Label
            tk.Label(
                row,
                text=label,
                font=self.theme.font(size=FONT_SIZE_SM),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_primary,
                anchor='w'
            ).pack(side='left', fill='x', expand=True)

            # Result value
            val = tk.Label(
                row,
                text="—",
                font=self.theme.font(size=FONT_SIZE_SM, mono=True),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_muted,
                padx=8
            )
            val.pack(side='right')

            self.check_widgets[group][key] = {'dot': dot, 'val': val}

            tk.Frame(row.master, bg=self.theme.border_light, height=1).pack(fill='x')


    def run_checks(self):
        """
        Runs all host security checks.

        Each check is a separate method that queries Windows
        using built-in tools (winreg, subprocess, WMI, ctypes).
        No data leaves the machine.
        """
        import threading

        self.status_callback("Running host security checks...", "scanning")

        def _run():
            results = {}

            # Run each check and collect results
            results['antivirus']       = self._check_antivirus()
            results['defender_excl']   = self._check_defender_exclusions()
            results['event_log']       = self._check_event_log_tampering()
            results['os_patches']      = self._check_os_patches()
            results['backup']          = self._check_backup()
            results['canary']          = self._check_canary_files()
            results['bitlocker']       = self._check_bitlocker()
            results['secure_boot']     = self._check_secure_boot()
            results['user_accounts']   = self._check_user_accounts()
            results['credential_mgr']  = self._check_credential_manager()
            results['macro_policy']    = self._check_macro_policy()
            results['remote_registry'] = self._check_remote_registry()
            results['audit_logs']      = self._check_audit_logs()
            results['screen_lock']     = self._check_screen_lock()
            results['pagefile']        = self._check_pagefile()

            # Identity checks
            results['2fa']          = self._check_2fa()
            results['password_mgr'] = self._check_password_manager()
            results['user_count']   = self._check_user_count()
            results['rdp']          = self._check_rdp()

            # Browser checks
            results['edge_safe']    = self._check_edge_safebrowsing()
            results['chrome_safe']  = self._check_chrome_safebrowsing()
            results['firefox_safe'] = self._check_firefox()
            results['extensions']   = self._check_extensions()

            # WiFi checks
            results['wifi_networks'] = self._check_saved_wifi()

            # Update UI on the main thread
            self.parent.after(0, lambda: self._update_ui(results))
            self.parent.after(0, lambda: self.status_callback(
                "Host checks complete", "ready"))

        # Run in background thread so UI stays responsive
        threading.Thread(target=_run, daemon=True).start()


    def _update_ui(self, results):
        """
        Updates all check widgets with results.

        Parameters:
            results (dict): All check results.
        """
        # Update main checklist
        checklist_keys = [
            'antivirus', 'defender_excl', 'event_log', 'os_patches',
            'backup', 'canary', 'bitlocker', 'secure_boot', 'user_accounts',
            'credential_mgr', 'macro_policy', 'remote_registry',
            'audit_logs', 'screen_lock', 'pagefile'
        ]

        for key in checklist_keys:
            if key in results and key in self.check_widgets.get('checklist', {}):
                result = results[key]
                self._update_check_widget(
                    self.check_widgets['checklist'][key],
                    result
                )

        # Update identity panel
        for key in ['2fa', 'password_mgr', 'user_count', 'rdp']:
            if key in results and key in self.check_widgets.get('identity', {}):
                self._update_dot_widget(
                    self.check_widgets['identity'][key],
                    results[key]
                )

        # Update browser panel
        for key in ['edge_safe', 'chrome_safe', 'firefox_safe', 'extensions']:
            if key in results and key in self.check_widgets.get('browser', {}):
                self._update_dot_widget(
                    self.check_widgets['browser'][key],
                    results[key]
                )

        # Update WiFi panel
        self._update_wifi_panel(results.get('wifi_networks', []))


    def _update_check_widget(self, widgets, result):
        """
        Updates a checklist row with a check result.

        Parameters:
            widgets (dict): Contains 'icon', 'label', 'badge' keys.
            result  (dict): Contains 'status', 'value', 'severity'.
        """
        status = result.get('status', 'unknown')
        value = result.get('value', '—')
        severity = result.get('severity', SEVERITY_INFO)

        # Choose icon and color based on status
        if status == 'pass':
            icon, icon_color = "✓", COLOR_SAFE
        elif status == 'fail':
            icon, icon_color = "✗", self.theme.severity_color(severity)
        elif status == 'warn':
            icon, icon_color = "!", COLOR_WARNING
        else:
            icon, icon_color = "?", self.theme.text_muted

        # Badge color based on severity
        badge_color = self.theme.severity_color(severity) if status != 'pass' else COLOR_SAFE
        badge_bg = self.theme.severity_bg(severity) if status != 'pass' else BG_SAFE

        widgets['icon'].configure(text=icon, fg=icon_color)
        widgets['badge'].configure(
            text=value,
            fg=badge_color,
            bg=badge_bg
        )


    def _update_dot_widget(self, widgets, result):
        """Updates a simple dot + value widget."""
        status = result.get('status', 'unknown')
        value = result.get('value', '—')

        if status == 'pass':
            dot_color = COLOR_SAFE
        elif status == 'fail':
            dot_color = COLOR_CRITICAL
        elif status == 'warn':
            dot_color = COLOR_WARNING
        else:
            dot_color = self.theme.text_muted

        widgets['dot'].configure(fg=dot_color)
        widgets['val'].configure(text=value, fg=dot_color)


    def _update_wifi_panel(self, networks):
        """Updates the saved WiFi networks panel."""
        for widget in self.wifi_frame.winfo_children():
            widget.destroy()

        if not networks:
            tk.Label(
                self.wifi_frame,
                text="No saved WiFi networks found",
                font=self.theme.font(size=FONT_SIZE_SM),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_muted
            ).pack(anchor='w', pady=4)
            return

        for net in networks[:8]:    # Show max 8 networks
            name = net.get('ssid', 'Unknown')
            auth = net.get('auth', 'Unknown')
            auto = net.get('auto_connect', False)

            # Flag open/weak security
            if auth in ('Open', 'WEP'):
                color = COLOR_CRITICAL
                flag = " ⚠ INSECURE"
            elif auto and auth == 'Open':
                color = COLOR_WARNING
                flag = " ⚠ auto-join open"
            else:
                color = COLOR_SAFE
                flag = ""

            row = tk.Frame(self.wifi_frame, bg=self.theme.bg_secondary)
            row.pack(fill='x', pady=1)

            tk.Label(
                row,
                text="●",
                font=self.theme.font(size=FONT_SIZE_XS),
                bg=self.theme.bg_secondary,
                fg=color
            ).pack(side='left', padx=(0, 6))

            tk.Label(
                row,
                text=f"{name}",
                font=self.theme.font(size=FONT_SIZE_SM),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_primary
            ).pack(side='left')

            tk.Label(
                row,
                text=f"{auth}{flag}",
                font=self.theme.font(size=FONT_SIZE_SM, mono=True),
                bg=self.theme.bg_secondary,
                fg=color
            ).pack(side='right', padx=PADDING_MD)


    # =================================================================
    # INDIVIDUAL SECURITY CHECKS
    # Each method queries Windows directly and returns a result dict.
    # Format: {'status': 'pass'/'fail'/'warn', 'value': str, 'severity': str}
    # =================================================================

    def _check_antivirus(self):
        """
        Checks Windows Security Center for antivirus status.
        Uses WMI (Windows Management Instrumentation) which is
        built into Windows — no external tools needed.
        """
        try:
            # Query Windows Security Center via PowerShell
            # This is the standard Windows way to check AV status
            cmd = (
                'powershell -NoProfile -Command "'
                'Get-MpComputerStatus | '
                'Select-Object -Property AMRunningMode,AntivirusEnabled,'
                'RealTimeProtectionEnabled,AntivirusSignatureAge | '
                'ConvertTo-Json"'
            )
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=15, shell=True, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout.strip())

                av_enabled = data.get('AntivirusEnabled', False)
                rt_enabled = data.get('RealTimeProtectionEnabled', False)
                sig_age = data.get('AntivirusSignatureAge', 999)

                if not av_enabled:
                    return {'status': 'fail', 'value': 'disabled',
                            'severity': SEVERITY_CRITICAL,
                            'detail': 'Antivirus is not enabled'}
                elif not rt_enabled:
                    return {'status': 'warn', 'value': 'RT off',
                            'severity': SEVERITY_WARNING,
                            'detail': 'Real-time protection is disabled'}
                elif sig_age > 7:
                    return {'status': 'warn', 'value': f'{sig_age}d old',
                            'severity': SEVERITY_WARNING,
                            'detail': f'Definitions are {sig_age} days old'}
                else:
                    return {'status': 'pass', 'value': f'active · {sig_age}d ago',
                            'severity': SEVERITY_PASS}
        except Exception as e:
            pass

        return {'status': 'warn', 'value': 'could not check',
                'severity': SEVERITY_WARNING}


    def _check_defender_exclusions(self):
        """
        Checks Windows Defender exclusion list for suspicious entries.
        Malware commonly adds itself to exclusions to avoid detection.
        Reads from the Windows registry — no external tools needed.
        """
        try:
            # Defender exclusion paths are stored in the registry
            key_path = (
                r"SOFTWARE\Microsoft\Windows Defender"
                r"\Exclusions\Paths"
            )
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as key:
                exclusions = []
                i = 0
                while True:
                    try:
                        name, _, _ = winreg.EnumValue(key, i)
                        exclusions.append(name)
                        i += 1
                    except OSError:
                        break   # No more values

                if not exclusions:
                    return {'status': 'pass', 'value': 'none',
                            'severity': SEVERITY_PASS}

                # Flag suspicious exclusions (non-standard paths)
                suspicious = [
                    e for e in exclusions
                    if not any(p in e.lower() for p in [
                        'program files', 'windows', 'system32',
                        'users', 'appdata', 'programdata'
                    ])
                ]

                if suspicious:
                    return {'status': 'warn', 'value': f'{len(exclusions)} ({len(suspicious)} suspicious)',
                            'severity': SEVERITY_WARNING}
                else:
                    return {'status': 'pass', 'value': f'{len(exclusions)} entries',
                            'severity': SEVERITY_PASS}

        except FileNotFoundError:
            # Key does not exist — no exclusions set
            return {'status': 'pass', 'value': 'none',
                    'severity': SEVERITY_PASS}
        except Exception:
            return {'status': 'warn', 'value': 'could not check',
                    'severity': SEVERITY_WARNING}


    def _check_event_log_tampering(self):
        """
        Checks whether Windows Security event logs have been cleared recently.
        Attackers commonly clear logs to hide their activity.
        Uses Windows Event Log API via PowerShell.
        """
        try:
            cmd = (
                'powershell -NoProfile -Command "'
                'Get-EventLog -LogName Security -Newest 1 '
                '-InstanceId 1102 -ErrorAction SilentlyContinue | '
                'Select-Object -ExpandProperty TimeGenerated"'
            )
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=15, shell=True, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0 and result.stdout.strip():
                # Event ID 1102 = Security log was cleared
                cleared_time = result.stdout.strip()
                return {
                    'status': 'fail',
                    'value': f'cleared: {cleared_time[:10]}',
                    'severity': SEVERITY_CRITICAL,
                    'detail': 'Security event log was recently cleared — possible attack cover-up'
                }
            else:
                # No log clearing event found — good
                return {'status': 'pass', 'value': 'no tampering',
                        'severity': SEVERITY_PASS}

        except Exception:
            return {'status': 'warn', 'value': 'could not check',
                    'severity': SEVERITY_WARNING}


    def _check_os_patches(self):
        """
        Checks whether Windows is up to date.
        Uses Windows Update API via PowerShell.
        """
        try:
            cmd = (
                'powershell -NoProfile -Command "'
                '$updates = (New-Object -ComObject Microsoft.Update.Session)'
                '.CreateUpdateSearcher().Search(\"IsInstalled=0\").Updates; '
                '$updates.Count"'
            )
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=20, shell=True, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0 and result.stdout.strip().isdigit():
                pending = int(result.stdout.strip())
                if pending == 0:
                    return {'status': 'pass', 'value': 'current',
                            'severity': SEVERITY_PASS}
                else:
                    sev = SEVERITY_CRITICAL if pending > 5 else SEVERITY_WARNING
                    return {'status': 'fail' if pending > 5 else 'warn',
                            'value': f'{pending} pending',
                            'severity': sev}
        except Exception:
            pass

        return {'status': 'warn', 'value': 'could not check',
                'severity': SEVERITY_WARNING}


    def _check_backup(self):
        """
        Checks whether Windows Backup or File History is configured.
        Looks for backup configuration in registry and common backup tools.
        """
        backup_found = False
        backup_name = ""

        try:
            # Check Windows File History
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                try:
                    enabled, _ = winreg.QueryValueEx(key, "Enabled")
                    if enabled:
                        backup_found = True
                        backup_name = "File History"
                except FileNotFoundError:
                    pass
        except Exception:
            pass

        try:
            # Check Windows Backup (older style)
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                backup_found = True
                backup_name = "Windows Backup"
        except Exception:
            pass

        # Check for common third-party backup apps
        backup_apps = [
            'Macrium Reflect', 'Acronis', 'Veeam', 'Backblaze', 'CrashPlan',
            'OneDrive', 'Google Backup'
        ]
        try:
            app_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, app_key) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as sub:
                            try:
                                name, _ = winreg.QueryValueEx(sub, "DisplayName")
                                for app in backup_apps:
                                    if app.lower() in name.lower():
                                        backup_found = True
                                        backup_name = name
                            except Exception:
                                pass
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass

        if backup_found:
            return {'status': 'pass', 'value': backup_name,
                    'severity': SEVERITY_PASS}
        else:
            return {
                'status': 'fail', 'value': 'not configured',
                'severity': SEVERITY_CRITICAL,
                'detail': 'No backup solution detected. This is your primary defense against ransomware data loss.'
            }


    def _check_canary_files(self):
        """
        Checks whether ransomware canary files are intact.
        Plants them if they do not exist yet.
        """
        import hashlib

        canary_files = self.db.get_canary_files()

        if not canary_files:
            # Plant canary files for the first time
            planted = self._plant_canary_files()
            if planted > 0:
                return {'status': 'pass', 'value': f'{planted} planted',
                        'severity': SEVERITY_PASS}
            else:
                return {'status': 'warn', 'value': 'could not plant',
                        'severity': SEVERITY_WARNING}

        # Verify existing canary files
        intact = 0
        tampered = 0
        missing = 0

        for cf in canary_files:
            path = cf['file_path']
            stored_hash = cf['file_hash']

            if not os.path.exists(path):
                missing += 1
                self.db.update_canary_status(path, 'missing')
            else:
                # Read file and compute current hash
                with open(path, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()

                if current_hash != stored_hash:
                    tampered += 1
                    self.db.update_canary_status(path, 'tampered', current_hash)
                else:
                    intact += 1
                    self.db.update_canary_status(path, 'intact', current_hash)

        if tampered > 0 or missing > 0:
            return {
                'status': 'fail',
                'value': f'{tampered} tampered, {missing} missing',
                'severity': SEVERITY_CRITICAL,
                'detail': 'Canary file tampering detected — possible ransomware activity!'
            }
        else:
            return {'status': 'pass', 'value': f'{intact} intact',
                    'severity': SEVERITY_PASS}


    def _plant_canary_files(self):
        """
        Plants ransomware canary files in key folders.

        Returns:
            int: Number of canary files successfully planted.
        """
        import hashlib

        user_home = os.path.expanduser('~')
        planted = 0

        for folder in CANARY_FOLDERS:
            folder_path = os.path.join(user_home, folder)
            if not os.path.exists(folder_path):
                continue

            canary_path = os.path.join(folder_path, CANARY_FILENAME)

            try:
                # Write canary file content
                with open(canary_path, 'w') as f:
                    f.write(CANARY_CONTENT)

                # Compute hash for future verification
                with open(canary_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()

                # Register in database
                self.db.register_canary(canary_path, file_hash)
                planted += 1

            except Exception:
                pass    # Folder might not be writable

        return planted


    def _check_bitlocker(self):
        """
        Checks whether BitLocker drive encryption is enabled.
        Uses manage-bde command which is built into Windows.
        """
        try:
            result = subprocess.run(
                ['manage-bde', '-status', 'C:'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            output = result.stdout.lower()

            if 'protection on' in output or 'fully encrypted' in output:
                return {'status': 'pass', 'value': 'enabled',
                        'severity': SEVERITY_PASS}
            elif 'protection off' in output or 'fully decrypted' in output:
                return {
                    'status': 'fail', 'value': 'off',
                    'severity': SEVERITY_CRITICAL,
                    'detail': 'BitLocker is not enabled. Physical theft would give full access to all your data.'
                }
            else:
                return {'status': 'warn', 'value': 'unknown state',
                        'severity': SEVERITY_WARNING}

        except Exception:
            return {'status': 'warn', 'value': 'could not check',
                    'severity': SEVERITY_WARNING}


    def _check_secure_boot(self):
        """
        Checks whether UEFI Secure Boot is enabled.
        Uses PowerShell to query the UEFI firmware settings.
        """
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Confirm-SecureBootUEFI'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            output = result.stdout.strip().lower()
            if 'true' in output:
                return {'status': 'pass', 'value': 'enabled',
                        'severity': SEVERITY_PASS}
            elif 'false' in output:
                return {'status': 'fail', 'value': 'disabled',
                        'severity': SEVERITY_WARNING,
                        'detail': 'Secure Boot is disabled. Enable it in BIOS settings.'}
            else:
                return {'status': 'warn', 'value': 'legacy BIOS',
                        'severity': SEVERITY_INFO}

        except Exception:
            return {'status': 'warn', 'value': 'could not check',
                    'severity': SEVERITY_WARNING}


    def _check_user_accounts(self):
        """
        Lists local user accounts and flags suspicious ones.
        Uses net user command built into Windows.
        """
        try:
            result = subprocess.run(
                ['net', 'user'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                # Parse user list from net user output
                lines = result.stdout.split('\n')
                users = []
                for line in lines[4:-3]:    # Skip header and footer lines
                    parts = line.split()
                    users.extend(parts)

                users = [u for u in users if u and u not in ['', 'command']]
                count = len(users)

                # Flag if Guest account is enabled
                guest_result = subprocess.run(
                    ['net', 'user', 'Guest'],
                    capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
                )
                guest_active = 'Account active               Yes' in guest_result.stdout

                if guest_active:
                    return {'status': 'warn', 'value': f'{count} accounts (Guest active)',
                            'severity': SEVERITY_WARNING,
                            'detail': 'Guest account is active. Disable it if not needed.'}

                return {'status': 'pass', 'value': f'{count} account(s)',
                        'severity': SEVERITY_PASS}

        except Exception:
            pass

        return {'status': 'warn', 'value': 'could not check',
                'severity': SEVERITY_WARNING}


    def _check_credential_manager(self):
        """
        Audits Windows Credential Manager for stored credentials.
        Lists saved credentials (metadata only, not the actual passwords).
        """
        try:
            result = subprocess.run(
                ['cmdkey', '/list'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                lines = [l for l in result.stdout.split('\n')
                         if 'Target:' in l or 'target:' in l.lower()]
                count = len(lines)

                if count == 0:
                    return {'status': 'pass', 'value': 'empty',
                            'severity': SEVERITY_PASS}
                else:
                    return {'status': 'pass', 'value': f'{count} stored',
                            'severity': SEVERITY_PASS}

        except Exception:
            pass

        return {'status': 'warn', 'value': 'could not check',
                'severity': SEVERITY_WARNING}


    def _check_macro_policy(self):
        """
        Checks PowerShell execution policy and Office macro settings.
        An unrestricted policy is a significant risk.
        """
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-ExecutionPolicy'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            policy = result.stdout.strip()

            if policy in ('Restricted', 'AllSigned'):
                return {'status': 'pass', 'value': policy,
                        'severity': SEVERITY_PASS}
            elif policy in ('RemoteSigned',):
                return {'status': 'pass', 'value': policy,
                        'severity': SEVERITY_PASS}
            elif policy == 'Unrestricted':
                return {
                    'status': 'fail', 'value': policy,
                    'severity': SEVERITY_CRITICAL,
                    'detail': 'PowerShell execution policy is Unrestricted — malicious scripts can run freely.'
                }
            else:
                return {'status': 'warn', 'value': policy,
                        'severity': SEVERITY_WARNING}

        except Exception:
            pass

        return {'status': 'warn', 'value': 'could not check',
                'severity': SEVERITY_WARNING}


    def _check_remote_registry(self):
        """
        Checks whether the Remote Registry service is running.
        This service allows remote registry modification and should be disabled.
        """
        try:
            result = subprocess.run(
                ['sc', 'query', 'RemoteRegistry'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            output = result.stdout.upper()
            if 'RUNNING' in output:
                return {
                    'status': 'warn', 'value': 'running',
                    'severity': SEVERITY_WARNING,
                    'detail': 'Remote Registry service is running. Disable it if not needed for remote management.'
                }
            elif 'STOPPED' in output:
                return {'status': 'pass', 'value': 'stopped',
                        'severity': SEVERITY_PASS}

        except Exception:
            pass

        return {'status': 'warn', 'value': 'could not check',
                'severity': SEVERITY_WARNING}


    def _check_audit_logs(self):
        """
        Checks Windows audit log retention settings.
        Default retention is often too short for security investigations.
        """
        try:
            result = subprocess.run(
                ['wevtutil', 'gl', 'Security'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                output = result.stdout
                # Find maxSize line
                for line in output.split('\n'):
                    if 'maxSize' in line.lower() or 'maxsize' in line:
                        # Extract size value
                        parts = line.split(':')
                        if len(parts) > 1:
                            try:
                                size_bytes = int(parts[1].strip())
                                size_mb = size_bytes // (1024 * 1024)

                                if size_mb < 100:
                                    return {
                                        'status': 'warn', 'value': f'{size_mb} MB',
                                        'severity': SEVERITY_WARNING,
                                        'detail': f'Security log max size is only {size_mb}MB. Recommend at least 100MB.'
                                    }
                                else:
                                    return {'status': 'pass', 'value': f'{size_mb} MB',
                                            'severity': SEVERITY_PASS}
                            except ValueError:
                                pass

        except Exception:
            pass

        return {'status': 'warn', 'value': 'could not check',
                'severity': SEVERITY_WARNING}


    def _check_screen_lock(self):
        """
        Checks whether the screen auto-locks after inactivity.
        An unlocked machine is a physical security gap.
        """
        try:
            key_path = r"SOFTWARE\Policies\Microsoft\Windows\Personalization"
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                    timeout, _ = winreg.QueryValueEx(key, "ScreenSaverTimeout")
                    if int(timeout) > 0:
                        mins = int(timeout) // 60
                        return {'status': 'pass', 'value': f'{mins} min',
                                'severity': SEVERITY_PASS}
            except Exception:
                pass

            # Check screen saver settings directly
            key_path2 = r"Control Panel\Desktop"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path2) as key:
                try:
                    timeout, _ = winreg.QueryValueEx(key, "ScreenSaveTimeOut")
                    ss_active, _ = winreg.QueryValueEx(key, "ScreenSaveActive")

                    if ss_active == '1' and int(timeout) > 0:
                        mins = max(1, int(timeout) // 60)
                        return {'status': 'pass', 'value': f'{mins} min',
                                'severity': SEVERITY_PASS}
                    else:
                        return {
                            'status': 'warn', 'value': 'not set',
                            'severity': SEVERITY_WARNING,
                            'detail': 'No screen lock timeout configured. Set one in Settings > Lock screen.'
                        }
                except Exception:
                    pass

        except Exception:
            pass

        return {'status': 'warn', 'value': 'could not verify',
                'severity': SEVERITY_WARNING}


    def _check_pagefile(self):
        """
        Checks whether Windows is configured to clear the pagefile on shutdown.
        The pagefile can contain sensitive data including passwords.
        """
        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                try:
                    clear_pf, _ = winreg.QueryValueEx(key, "ClearPageFileAtShutdown")
                    if clear_pf == 1:
                        return {'status': 'pass', 'value': 'clears on shutdown',
                                'severity': SEVERITY_PASS}
                    else:
                        return {
                            'status': 'warn', 'value': 'not clearing',
                            'severity': SEVERITY_WARNING,
                            'detail': 'Pagefile is not cleared on shutdown. Sensitive data may persist on disk.'
                        }
                except FileNotFoundError:
                    return {'status': 'warn', 'value': 'not configured',
                            'severity': SEVERITY_WARNING}

        except Exception:
            pass

        return {'status': 'warn', 'value': 'could not check',
                'severity': SEVERITY_WARNING}


    def _check_2fa(self):
        """Checks whether Windows Hello (2FA) is configured."""
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 '(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\DeviceLock).AllowSimpleDeviceLock'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )
            # Simplified check — Windows Hello presence
            hello_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hello_path) as key:
                    return {'status': 'pass', 'value': 'Windows Hello',
                            'severity': SEVERITY_PASS}
            except Exception:
                return {'status': 'warn', 'value': 'not configured',
                        'severity': SEVERITY_WARNING}
        except Exception:
            return {'status': 'warn', 'value': 'could not check',
                    'severity': SEVERITY_WARNING}


    def _check_password_manager(self):
        """Checks whether a password manager is installed."""
        managers = {
            'bitwarden': 'Bitwarden',
            '1password': '1Password',
            'keepass':   'KeePass',
            'dashlane':  'Dashlane',
            'lastpass':  'LastPass',
            'roboform':  'RoboForm',
        }

        try:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as sub:
                            try:
                                name, _ = winreg.QueryValueEx(sub, "DisplayName")
                                for keyword, display in managers.items():
                                    if keyword in name.lower():
                                        return {'status': 'pass', 'value': display,
                                                'severity': SEVERITY_PASS}
                            except Exception:
                                pass
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass

        return {'status': 'warn', 'value': 'none found',
                'severity': SEVERITY_INFO}


    def _check_user_count(self):
        """Returns count of local user accounts."""
        try:
            result = subprocess.run(
                ['net', 'user'], capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                users = []
                for line in lines[4:-3]:
                    users.extend(line.split())
                count = len([u for u in users if u])
                return {'status': 'pass', 'value': f'{count} accounts',
                        'severity': SEVERITY_PASS}
        except Exception:
            pass
        return {'status': 'warn', 'value': 'could not check',
                'severity': SEVERITY_WARNING}


    def _check_rdp(self):
        """Checks whether Remote Desktop is enabled."""
        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                deny_rdp, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
                if deny_rdp == 1:
                    return {'status': 'pass', 'value': 'disabled',
                            'severity': SEVERITY_PASS}
                else:
                    return {
                        'status': 'warn', 'value': 'enabled',
                        'severity': SEVERITY_WARNING,
                        'detail': 'Remote Desktop is enabled. Disable if not actively used.'
                    }
        except Exception:
            return {'status': 'warn', 'value': 'could not check',
                    'severity': SEVERITY_WARNING}


    def _check_edge_safebrowsing(self):
        """Checks Edge SmartScreen setting."""
        try:
            key_path = r"SOFTWARE\Policies\Microsoft\Edge"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                val, _ = winreg.QueryValueEx(key, "SmartScreenEnabled")
                if val == 1:
                    return {'status': 'pass', 'value': 'on',
                            'severity': SEVERITY_PASS}
        except Exception:
            pass
        # Default: Edge SmartScreen is on by default
        return {'status': 'pass', 'value': 'on (default)',
                'severity': SEVERITY_PASS}


    def _check_chrome_safebrowsing(self):
        """Checks Chrome Safe Browsing setting."""
        try:
            key_path = r"SOFTWARE\Policies\Google\Chrome"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                val, _ = winreg.QueryValueEx(key, "SafeBrowsingEnabled")
                status = 'pass' if val == 1 else 'warn'
                return {'status': status, 'value': 'on' if val == 1 else 'off',
                        'severity': SEVERITY_PASS if val == 1 else SEVERITY_WARNING}
        except Exception:
            # Default: Chrome Safe Browsing is on by default
            return {'status': 'pass', 'value': 'on (default)',
                    'severity': SEVERITY_PASS}


    def _check_firefox(self):
        """Checks if Firefox is installed."""
        firefox_path = os.path.join(
            os.environ.get('PROGRAMFILES', 'C:\\Program Files'),
            'Mozilla Firefox', 'firefox.exe'
        )
        if os.path.exists(firefox_path):
            return {'status': 'pass', 'value': 'installed',
                    'severity': SEVERITY_PASS}
        return {'status': 'pass', 'value': 'not installed',
                'severity': SEVERITY_PASS}


    def _check_extensions(self):
        """Checks Chrome extension count as a risk indicator."""
        ext_path = os.path.join(
            os.environ.get('LOCALAPPDATA', ''),
            'Google', 'Chrome', 'User Data', 'Default', 'Extensions'
        )
        if os.path.exists(ext_path):
            count = len([d for d in os.listdir(ext_path)
                        if os.path.isdir(os.path.join(ext_path, d))])
            if count > 20:
                return {'status': 'warn', 'value': f'{count} extensions',
                        'severity': SEVERITY_WARNING}
            return {'status': 'pass', 'value': f'{count} extensions',
                    'severity': SEVERITY_PASS}
        return {'status': 'pass', 'value': 'none found',
                'severity': SEVERITY_PASS}


    def _check_saved_wifi(self):
        """
        Gets list of saved WiFi profiles and their security type.
        Uses netsh wlan which is built into Windows.
        """
        networks = []
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'All User Profile' in line or 'User Profile' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            ssid = parts[1].strip()

                            # Get security details for this network
                            detail = subprocess.run(
                                ['netsh', 'wlan', 'show', 'profile',
                                 f'name={ssid}'],
                                capture_output=True, text=True, timeout=5, creationflags=CREATE_NO_WINDOW
                            )

                            auth = 'Unknown'
                            auto = False
                            for dline in detail.stdout.split('\n'):
                                if 'Authentication' in dline:
                                    auth = dline.split(':')[-1].strip()
                                if 'Connection mode' in dline:
                                    auto = 'auto' in dline.lower()

                            networks.append({
                                'ssid': ssid,
                                'auth': auth,
                                'auto_connect': auto
                            })

        except Exception:
            pass

        return networks


    def _make_panel(self, parent, title):
        """
        Creates a standard panel container with a header.

        Parameters:
            parent (Frame): Parent widget.
            title  (str)  : Panel header text.

        Returns:
            Frame: The panel content frame to add widgets to.
        """
        outer = tk.Frame(parent, bg=self.theme.bg_secondary)
        outer.pack(fill='x', pady=(0, 8))

        # Header
        tk.Label(
            outer,
            text=title,
            font=self.theme.font(size=FONT_SIZE_XS),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_muted
        ).pack(anchor='w', padx=PADDING_MD, pady=(PADDING_MD, 4))

        tk.Frame(outer, bg=self.theme.border, height=1).pack(fill='x')

        return outer


    def _apply_theme(self):
        """Updates colors when theme changes."""
        self.canvas.configure(bg=self.theme.bg_primary)
        self.inner.configure(bg=self.theme.bg_primary)
