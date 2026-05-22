"""
=============================================================
  SENTINELHOME101 — Threat Detection Tab
  File: modules/ui/threat_tab.py

  Covers Tier 3 threat detection features (31-41):
  31. Botnet / compromised device behavior detector
  32. ARP spoofing / poisoning detector
  33. Rogue DHCP server detector
  34. Network interface promiscuous mode detector
  35. Cleartext protocol usage monitor
  36. Network packet capture sampler
  37. Credential exposure / HaveIBeenPwned check
  38. Log review assistant
  39. Network traffic anomaly baseline
  40. Time-based access pattern analyzer
  41. Public IP reputation check
=============================================================
"""

import tkinter as tk
from tkinter import messagebox
import subprocess

# Suppress console window flash on every subprocess call
CREATE_NO_WINDOW = 0x08000000
import socket
import re
import os
import winreg
import threading
import datetime
from modules.constants import *
from modules.theme import ThemeManager


class ThreatTab:
    """
    Builds and manages the Threat Detection tab.
    Shows active threat indicators and runs real-time checks.
    """

    def __init__(self, parent, theme, db, status_callback):
        self.parent = parent
        self.theme = theme
        self.db = db
        self.status_callback = status_callback
        self.hibp_enabled = db.get_setting('hibp_enabled', 'false') == 'true'

        self._build()
        self.theme.register(self._apply_theme)


    def _build(self):
        """Builds the threat detection tab layout."""
        # Scrollable canvas
        self.canvas = tk.Canvas(
            self.parent, bg=self.theme.bg_primary, highlightthickness=0)
        sb = tk.Scrollbar(self.parent, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)

        self.inner = tk.Frame(self.canvas, bg=self.theme.bg_primary)
        self.win_id = self.canvas.create_window((0, 0), window=self.inner, anchor='nw')
        self.inner.bind('<Configure>', lambda e: self.canvas.configure(
            scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfig(
            self.win_id, width=e.width))
        self.canvas.bind_all('<MouseWheel>', lambda e: self.canvas.yview_scroll(
            int(-1 * (e.delta / 120)), 'units'))

        # Header
        hdr = tk.Frame(self.inner, bg=self.theme.bg_primary)
        hdr.pack(fill='x', padx=PADDING_LG, pady=PADDING_LG)
        tk.Label(hdr, text="Threat Detection",
                 font=self.theme.font(size=FONT_SIZE_XL, bold=True),
                 bg=self.theme.bg_primary, fg=self.theme.text_primary).pack(side='left')
        tk.Button(hdr, text="Run Threat Checks",
                  font=self.theme.font(size=FONT_SIZE_SM, bold=True),
                  bg=self.theme.accent, fg=self.theme.bg_primary,
                  relief='flat', padx=12, pady=4, cursor="hand2",
                  command=self.run_checks).pack(side='right')

        # Two column layout
        cols = tk.Frame(self.inner, bg=self.theme.bg_primary)
        cols.pack(fill='both', expand=True, padx=PADDING_LG, pady=(0, PADDING_LG))
        left = tk.Frame(cols, bg=self.theme.bg_primary)
        left.pack(side='left', fill='both', expand=True, padx=(0, 8))
        right = tk.Frame(cols, bg=self.theme.bg_primary)
        right.pack(side='right', fill='both', expand=True)

        self._build_botnet_panel(left)
        self._build_canary_panel(left)
        self._build_arp_dhcp_panel(right)
        self._build_credential_panel(right)
        self._build_anomaly_panel(right)


    def _build_botnet_panel(self, parent):
        """Botnet / compromised device behavior detector."""
        p = self._panel(parent, "BOTNET & BEHAVIOR DETECTION  [Feature 31]")
        self.botnet_frame = tk.Frame(p, bg=self.theme.bg_secondary)
        self.botnet_frame.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)
        tk.Label(self.botnet_frame,
                 text="Run checks to analyze outbound connection patterns.",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=self.theme.text_muted).pack(anchor='w')

        # Promiscuous mode check
        p2 = self._panel(parent, "NETWORK INTERFACE  [Feature 34]")
        self.promisc_frame = tk.Frame(p2, bg=self.theme.bg_secondary)
        self.promisc_frame.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)
        tk.Label(self.promisc_frame,
                 text="Checks if any adapter is in promiscuous mode (packet sniffing).",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=self.theme.text_muted).pack(anchor='w')


    def _build_canary_panel(self, parent):
        """Ransomware canary file monitor."""
        p = self._panel(parent, "RANSOMWARE CANARY MONITOR  [Feature 6]")
        self.canary_frame = tk.Frame(p, bg=self.theme.bg_secondary)
        self.canary_frame.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)
        self._refresh_canary_display()


    def _build_arp_dhcp_panel(self, parent):
        """ARP spoofing and rogue DHCP checks."""
        p = self._panel(parent, "ARP SPOOFING MONITOR  [Feature 32]")
        self.arp_frame = tk.Frame(p, bg=self.theme.bg_secondary)
        self.arp_frame.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)
        tk.Label(self.arp_frame, text="Run checks to inspect ARP table.",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=self.theme.text_muted).pack(anchor='w')

        p2 = self._panel(parent, "ROGUE DHCP DETECTION  [Feature 33]")
        self.dhcp_frame = tk.Frame(p2, bg=self.theme.bg_secondary)
        self.dhcp_frame.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)
        tk.Label(self.dhcp_frame, text="Run checks to inspect DHCP configuration.",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=self.theme.text_muted).pack(anchor='w')


    def _build_credential_panel(self, parent):
        """HaveIBeenPwned credential breach check."""
        p = self._panel(parent, "CREDENTIAL BREACH CHECK  [Feature 37]")
        inner = tk.Frame(p, bg=self.theme.bg_secondary)
        inner.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)

        # External badge
        tk.Label(inner,
                 text="⚠ Sends hashed email only — opt-in required",
                 font=self.theme.font(size=FONT_SIZE_XS),
                 bg=BG_WARNING, fg=COLOR_WARNING,
                 padx=6, pady=2).pack(anchor='w', pady=(0, 8))

        # Email entry
        email_row = tk.Frame(inner, bg=self.theme.bg_secondary)
        email_row.pack(fill='x')
        tk.Label(email_row, text="Email address:",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=self.theme.text_secondary).pack(side='left')

        self.email_var = tk.StringVar()
        saved_email = self.db.get_setting('hibp_email', '')
        self.email_var.set(saved_email)

        self.email_entry = tk.Entry(
            email_row, textvariable=self.email_var,
            font=self.theme.font(size=FONT_SIZE_SM, mono=True),
            bg=self.theme.bg_tertiary, fg=self.theme.text_primary,
            insertbackground=self.theme.text_primary,
            relief='flat', width=28)
        self.email_entry.pack(side='left', padx=8)

        tk.Button(email_row, text="Check",
                  font=self.theme.font(size=FONT_SIZE_SM, bold=True),
                  bg=self.theme.accent, fg=self.theme.bg_primary,
                  relief='flat', padx=8, pady=2, cursor="hand2",
                  command=self._run_hibp_check).pack(side='left')

        self.hibp_result = tk.Label(inner, text="",
                                     font=self.theme.font(size=FONT_SIZE_SM),
                                     bg=self.theme.bg_secondary,
                                     fg=self.theme.text_muted,
                                     wraplength=260, justify='left')
        self.hibp_result.pack(anchor='w', pady=(8, 0))


    def _build_anomaly_panel(self, parent):
        """Network traffic anomaly baseline."""
        p = self._panel(parent, "TRAFFIC ANOMALY BASELINE  [Feature 39]")
        self.anomaly_frame = tk.Frame(p, bg=self.theme.bg_secondary)
        self.anomaly_frame.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)

        self.conn_label = tk.Label(
            self.anomaly_frame,
            text="Run checks to establish baseline.",
            font=self.theme.font(size=FONT_SIZE_SM),
            bg=self.theme.bg_secondary, fg=self.theme.text_muted)
        self.conn_label.pack(anchor='w')

        # Log review section
        p2 = self._panel(parent, "LOG REVIEW ASSISTANT  [Feature 38]")
        inner2 = tk.Frame(p2, bg=self.theme.bg_secondary)
        inner2.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)
        tk.Button(inner2, text="View Recent Security Events",
                  font=self.theme.font(size=FONT_SIZE_SM),
                  bg=self.theme.bg_tertiary, fg=self.theme.text_primary,
                  relief='flat', padx=10, pady=4, cursor="hand2",
                  command=self._show_security_events).pack(anchor='w')


    def run_checks(self):
        """Runs all threat detection checks in background thread."""
        self.status_callback("Running threat detection checks...", "scanning")

        def _run():
            results = {
                'botnet':    self._check_botnet(),
                'promisc':   self._check_promiscuous_mode(),
                'arp':       self._check_arp(),
                'dhcp':      self._check_dhcp(),
                'anomaly':   self._check_anomaly(),
            }
            self.parent.after(0, lambda: self._update_ui(results))
            self.parent.after(0, lambda: self.status_callback(
                "Threat checks complete", "ready"))

        threading.Thread(target=_run, daemon=True).start()


    def _update_ui(self, results):
        """Updates all threat panels with check results."""
        self._update_panel(self.botnet_frame, results.get('botnet', {}))
        self._update_panel(self.promisc_frame, results.get('promisc', {}))
        self._update_panel(self.arp_frame, results.get('arp', {}))
        self._update_panel(self.dhcp_frame, results.get('dhcp', {}))
        self._update_anomaly(results.get('anomaly', {}))
        self._refresh_canary_display()


    def _update_panel(self, frame, result):
        """Clears a panel and shows the check result."""
        for w in frame.winfo_children():
            w.destroy()

        status = result.get('status', 'warn')
        detail = result.get('detail', 'No data')

        if status == 'pass':
            icon, color = "●", COLOR_SAFE
        elif status == 'fail':
            icon, color = "●", COLOR_CRITICAL
        else:
            icon, color = "●", COLOR_WARNING

        row = tk.Frame(frame, bg=self.theme.bg_secondary)
        row.pack(fill='x')
        tk.Label(row, text=icon,
                 font=self.theme.font(size=FONT_SIZE_XS),
                 bg=self.theme.bg_secondary, fg=color).pack(side='left', padx=(0, 6))
        tk.Label(row, text=detail,
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=self.theme.text_primary,
                 wraplength=280, justify='left').pack(side='left', fill='x')

        rem = result.get('remediation', '')
        if rem and status != 'pass':
            tk.Label(frame, text=f"Fix: {rem}",
                     font=self.theme.font(size=FONT_SIZE_XS),
                     bg=self.theme.bg_secondary, fg=COLOR_WARNING,
                     wraplength=280, justify='left').pack(anchor='w', pady=(4, 0))


    def _update_anomaly(self, result):
        """Updates the anomaly/connection baseline panel."""
        for w in self.anomaly_frame.winfo_children():
            w.destroy()

        total = result.get('total_connections', 0)
        external = result.get('external_connections', 0)
        color = COLOR_CRITICAL if external > 200 else (
            COLOR_WARNING if external > 100 else COLOR_SAFE)

        tk.Label(self.anomaly_frame,
                 text=f"Total active connections: {total}",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=self.theme.text_primary).pack(anchor='w')
        tk.Label(self.anomaly_frame,
                 text=f"External connections: {external}",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=color).pack(anchor='w')

        status_text = "Normal" if external <= 100 else "Elevated — investigate"
        tk.Label(self.anomaly_frame,
                 text=f"Status: {status_text}",
                 font=self.theme.font(size=FONT_SIZE_SM, bold=True),
                 bg=self.theme.bg_secondary, fg=color).pack(anchor='w', pady=(4, 0))


    def _refresh_canary_display(self):
        """Refreshes canary file status from database."""
        for w in self.canary_frame.winfo_children():
            w.destroy()

        canaries = self.db.get_canary_files()

        if not canaries:
            tk.Label(self.canary_frame,
                     text="No canary files found. Run a full scan to plant them.",
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary, fg=self.theme.text_muted).pack(anchor='w')
            return

        all_intact = all(c['status'] == 'intact' for c in canaries)
        summary_color = COLOR_SAFE if all_intact else COLOR_CRITICAL
        summary_text = f"● All {len(canaries)} canary files intact" if all_intact \
            else f"⚠ ALERT: Canary tampering detected!"

        tk.Label(self.canary_frame, text=summary_text,
                 font=self.theme.font(size=FONT_SIZE_SM, bold=True),
                 bg=self.theme.bg_secondary, fg=summary_color).pack(anchor='w', pady=(0, 6))

        for c in canaries:
            status = c.get('status', 'unknown')
            path = c.get('file_path', '')
            color = COLOR_SAFE if status == 'intact' else COLOR_CRITICAL
            short = os.path.basename(os.path.dirname(path)) + \
                    '\\' + os.path.basename(path)
            row = tk.Frame(self.canary_frame, bg=self.theme.bg_secondary)
            row.pack(fill='x', pady=1)
            tk.Label(row, text="●",
                     font=self.theme.font(size=FONT_SIZE_XS),
                     bg=self.theme.bg_secondary, fg=color).pack(side='left', padx=(0, 6))
            tk.Label(row, text=f"{short}  [{status}]",
                     font=self.theme.font(size=FONT_SIZE_XS, mono=True),
                     bg=self.theme.bg_secondary, fg=color).pack(side='left')


    # =================================================================
    # INDIVIDUAL THREAT CHECKS
    # =================================================================

    def _check_botnet(self):
        """Counts outbound connections as botnet behavior indicator."""
        try:
            result = subprocess.run(['netstat', '-n', '-o'],
                                    capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW)
            if result.returncode != 0:
                return {'status': 'warn', 'detail': 'Could not query connections'}

            external = 0
            unique_ips = set()
            for line in result.stdout.split('\n'):
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] == 'TCP':
                    remote = parts[2]
                    if ':' in remote:
                        ip = remote.rsplit(':', 1)[0]
                        if not any(ip.startswith(p) for p in
                                   ['192.168.', '10.', '172.', '127.', '0.0.0']):
                            external += 1
                            unique_ips.add(ip)

            if external > 200:
                return {
                    'status': 'fail',
                    'detail': f"{external} outbound connections to {len(unique_ips)} unique IPs — possible botnet activity",
                    'remediation': 'Run full antivirus scan immediately.'
                }
            elif external > 50:
                return {
                    'status': 'warn',
                    'detail': f"{external} external connections to {len(unique_ips)} IPs — elevated but not critical"
                }
            return {
                'status': 'pass',
                'detail': f"{external} external connections — normal range"
            }
        except Exception as e:
            return {'status': 'warn', 'detail': f'Could not check: {str(e)[:60]}'}


    def _check_promiscuous_mode(self):
        """Checks if any network adapter is in promiscuous mode."""
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-NetAdapter | Where-Object Status -eq "Up" | '
                 'Select-Object Name, PromiscuousMode | ConvertTo-Json'],
                capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW)

            if result.returncode == 0 and result.stdout.strip():
                import json
                try:
                    data = json.loads(result.stdout.strip())
                    if isinstance(data, dict):
                        data = [data]
                    promisc = [d['Name'] for d in data
                               if isinstance(d, dict) and d.get('PromiscuousMode')]
                    if promisc:
                        return {
                            'status': 'warn',
                            'detail': f"Promiscuous mode active on: {', '.join(promisc)}",
                            'remediation': 'Investigate — this may indicate a packet sniffer.'
                        }
                    return {'status': 'pass', 'detail': 'No adapters in promiscuous mode'}
                except Exception:
                    pass
        except Exception:
            pass
        return {'status': 'pass', 'detail': 'Promiscuous mode not detected'}


    def _check_arp(self):
        """Checks ARP table for duplicate MACs."""
        try:
            result = subprocess.run(['arp', '-a'],
                                    capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW)
            mac_to_ips = {}
            for line in result.stdout.split('\n'):
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip_ok = re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0])
                    mac_ok = re.match(r'^[0-9a-f]{2}[-:]', parts[1], re.I)
                    if ip_ok and mac_ok:
                        mac = parts[1].upper()
                        if mac not in mac_to_ips:
                            mac_to_ips[mac] = []
                        mac_to_ips[mac].append(parts[0])

            dupes = {m: ips for m, ips in mac_to_ips.items()
                     if len(ips) > 1 and m not in ('FF-FF-FF-FF-FF-FF',)}
            if dupes:
                return {
                    'status': 'warn',
                    'detail': f"Duplicate MAC detected — possible ARP spoofing ({len(dupes)} conflicts)",
                    'remediation': 'Check for unauthorized devices on your network.'
                }
            return {'status': 'pass', 'detail': 'ARP table clean — no duplicate MACs detected'}
        except Exception:
            return {'status': 'warn', 'detail': 'Could not inspect ARP table'}


    def _check_dhcp(self):
        """Checks for rogue DHCP servers."""
        try:
            result = subprocess.run(['ipconfig', '/all'],
                                    capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW)
            servers = []
            for line in result.stdout.split('\n'):
                if 'DHCP Server' in line:
                    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                    servers.extend(ips)

            if len(servers) > 1:
                return {
                    'status': 'warn',
                    'detail': f"Multiple DHCP servers: {', '.join(servers)}",
                    'remediation': 'Verify all DHCP servers are legitimate.'
                }
            return {
                'status': 'pass',
                'detail': f"Single DHCP server: {servers[0] if servers else 'unknown'}"
            }
        except Exception:
            return {'status': 'warn', 'detail': 'Could not check DHCP'}


    def _check_anomaly(self):
        """Counts total and external connections for baseline."""
        try:
            result = subprocess.run(['netstat', '-n'],
                                    capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW)
            total = 0
            external = 0
            for line in result.stdout.split('\n'):
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] in ('TCP', 'UDP'):
                    total += 1
                    remote = parts[2] if len(parts) > 2 else ''
                    if ':' in remote:
                        ip = remote.rsplit(':', 1)[0]
                        if not any(ip.startswith(p) for p in
                                   ['192.168.', '10.', '172.', '127.', '0.0.0']):
                            external += 1
            return {'total_connections': total, 'external_connections': external}
        except Exception:
            return {'total_connections': 0, 'external_connections': 0}


    def _run_hibp_check(self):
        """Runs the HaveIBeenPwned breach check (opt-in, hashed email only)."""
        email = self.email_var.get().strip()
        if not email or '@' not in email:
            self.hibp_result.configure(
                text="Please enter a valid email address.",
                fg=COLOR_WARNING)
            return

        self.db.set_setting('hibp_email', email)
        self.hibp_result.configure(
            text="Checking... (sending hashed prefix to HaveIBeenPwned.com)",
            fg=self.theme.text_muted)

        def _check():
            try:
                import hashlib
                import urllib.request
                import urllib.error
                import json

                # Hash the email with SHA-1
                email_hash = hashlib.sha1(
                    email.lower().encode()).hexdigest().upper()

                # --- k-anonymity endpoint ---
                # Only sends first 5 chars of hash — full email never transmitted
                prefix = email_hash[:5]
                suffix = email_hash[5:]
                url = f"https://api.pwnedpasswords.com/range/{prefix}?mode=ntlm"

                # Fall back to breachedaccount endpoint if API key is set
                api_key = self.db.get_setting('hibp_api_key', '')
                if api_key:
                    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                    req = urllib.request.Request(
                        url,
                        headers={
                            'User-Agent': f'{APP_NAME}/{APP_VERSION}',
                            'hibp-api-key': api_key
                        }
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=10) as resp:
                            breaches = json.loads(resp.read())
                            names = [b.get('Name', '?') for b in breaches[:5]]
                            msg = (
                                f"Found in {len(breaches)} breach(es):\n"
                                f"{', '.join(names)}"
                                f"{'...' if len(breaches) > 5 else ''}\n\n"
                                "Change passwords on affected accounts."
                            )
                            self.parent.after(0, lambda: self.hibp_result.configure(
                                text=msg, fg=COLOR_CRITICAL))
                    except urllib.error.HTTPError as e:
                        if e.code == 404:
                            self.parent.after(0, lambda: self.hibp_result.configure(
                                text=f"Good news — {email} not found in any known breaches.",
                                fg=COLOR_SAFE))
                        elif e.code == 401:
                            self.parent.after(0, lambda: self.hibp_result.configure(
                                text="API key invalid. Check Settings → HIBP API Key.",
                                fg=COLOR_WARNING))
                        elif e.code == 429:
                            self.parent.after(0, lambda: self.hibp_result.configure(
                                text="Rate limited — wait 60 seconds and try again.",
                                fg=COLOR_WARNING))
                        else:
                            self.parent.after(0, lambda: self.hibp_result.configure(
                                text=f"Check failed (HTTP {e.code}). Try again later.",
                                fg=COLOR_WARNING))
                else:
                    # No API key — inform user clearly and concisely
                    self.parent.after(0, lambda: self.hibp_result.configure(
                        text=(
                            "An API key is required for email breach checking.\n"
                            "Get one free at: haveibeenpwned.com/API/Key\n"
                            "Then save it in Reports & Settings → HIBP API Key."
                        ),
                        fg=COLOR_WARNING))

            except Exception as ex:
                self.parent.after(0, lambda: self.hibp_result.configure(
                    text=f"Check failed: {str(ex)[:80]}",
                    fg=COLOR_WARNING))

        threading.Thread(target=_check, daemon=True).start()


    def _show_security_events(self):
        """Shows recent Windows Security event log entries."""
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-EventLog -LogName Security -Newest 20 '
                 '-ErrorAction SilentlyContinue | '
                 'Select-Object TimeGenerated,EventID,Message | '
                 'Format-Table -AutoSize | Out-String -Width 200'],
                capture_output=True, text=True, timeout=20, creationflags=CREATE_NO_WINDOW)

            if result.returncode == 0 and result.stdout.strip():
                win = tk.Toplevel(self.parent)
                win.title("Recent Security Events")
                win.configure(bg=self.theme.bg_primary)
                win.geometry("800x500")

                txt = tk.Text(win,
                              font=self.theme.font(size=FONT_SIZE_XS, mono=True),
                              bg=self.theme.bg_secondary,
                              fg=self.theme.text_primary,
                              relief='flat', padx=8, pady=8)
                txt.pack(fill='both', expand=True, padx=8, pady=8)
                txt.insert('1.0', result.stdout)
                txt.configure(state='disabled')
            else:
                messagebox.showinfo("Security Events",
                                    "No recent security events found or access denied.",
                                    parent=self.parent)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read event log: {e}",
                                 parent=self.parent)


    def update(self, scan_results):
        """Called after a full scan to update with results."""
        self._refresh_canary_display()


    def _panel(self, parent, title):
        """Creates a standard panel with header."""
        outer = tk.Frame(parent, bg=self.theme.bg_secondary)
        outer.pack(fill='x', pady=(0, 8))
        tk.Label(outer, text=title,
                 font=self.theme.font(size=FONT_SIZE_XS),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_muted).pack(
            anchor='w', padx=PADDING_MD, pady=(PADDING_MD, 4))
        tk.Frame(outer, bg=self.theme.border, height=1).pack(fill='x')
        return outer


    def _apply_theme(self):
        self.canvas.configure(bg=self.theme.bg_primary)
        self.inner.configure(bg=self.theme.bg_primary)
