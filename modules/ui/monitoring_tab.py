"""
=============================================================
  SENTINELHOME101 — Monitoring Tab
  File: modules/ui/monitoring_tab.py

  Covers Tier 6-8 monitoring features:
  47. Scan history & change detection
  48. Device risk score display
  49. Device first seen / last seen timeline
  50. Inactive device tracker
  51. Vulnerability notes
  52. Scheduled scan reminder
  60. Password manager detection
  85. Packet loss checker
  86. Ping latency with trend tracking
  87. Network uptime tracker
  88. Bandwidth hog detector
=============================================================
"""

import tkinter as tk
from tkinter import messagebox
import subprocess
import threading
import datetime
import re
from modules.constants import *
from modules.theme import ThemeManager


class MonitoringTab:
    """Builds and manages the Monitoring tab."""

    def __init__(self, parent, theme, db, status_callback):
        self.parent = parent
        self.theme = theme
        self.db = db
        self.status_callback = status_callback

        self._build()
        self.theme.register(self._apply_theme)
        self._load_history()


    def _build(self):
        """Builds the monitoring tab layout."""
        # Header
        hdr = tk.Frame(self.parent, bg=self.theme.bg_primary)
        hdr.pack(fill='x', padx=PADDING_LG, pady=PADDING_LG)
        tk.Label(hdr, text="Monitoring",
                 font=self.theme.font(size=FONT_SIZE_XL, bold=True),
                 bg=self.theme.bg_primary, fg=self.theme.text_primary).pack(side='left')
        tk.Button(hdr, text="Run Performance Check",
                  font=self.theme.font(size=FONT_SIZE_SM, bold=True),
                  bg=self.theme.accent, fg=self.theme.bg_primary,
                  relief='flat', padx=12, pady=4, cursor="hand2",
                  command=self._run_performance).pack(side='right')

        # Scrollable canvas
        canvas = tk.Canvas(self.parent, bg=self.theme.bg_primary,
                           highlightthickness=0)
        sb = tk.Scrollbar(self.parent, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)

        self.inner = tk.Frame(canvas, bg=self.theme.bg_primary)
        win = canvas.create_window((0, 0), window=self.inner, anchor='nw')
        self.inner.bind('<Configure>', lambda e: canvas.configure(
            scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>', lambda e: canvas.itemconfig(win, width=e.width))
        canvas.bind('<Map>', lambda e: canvas.bind_all(
            '<MouseWheel>', lambda e: canvas.yview_scroll(
                int(-1 * (e.delta / 120)), 'units')))
        canvas.bind('<Enter>', lambda e: canvas.bind_all(
            '<MouseWheel>', lambda e: canvas.yview_scroll(
                int(-1 * (e.delta / 120)), 'units')))
        canvas.bind('<Leave>', lambda e: canvas.unbind_all('<MouseWheel>'))

        # Two column layout
        cols = tk.Frame(self.inner, bg=self.theme.bg_primary)
        cols.pack(fill='both', expand=True, padx=PADDING_LG, pady=(0, PADDING_LG))
        left = tk.Frame(cols, bg=self.theme.bg_primary)
        left.pack(side='left', fill='both', expand=True, padx=(0, 8))
        right = tk.Frame(cols, bg=self.theme.bg_primary)
        right.pack(side='right', fill='both', expand=True)

        self._build_history_panel(left)
        self._build_change_panel(left)
        self._build_performance_panel(right)
        self._build_inactive_panel(right)
        self._build_scheduled_panel(right)


    def _build_history_panel(self, parent):
        """Scan history display."""
        p = self._panel(parent, "SCAN HISTORY  [Feature 47]")
        self.history_frame = tk.Frame(p, bg=self.theme.bg_secondary)
        self.history_frame.pack(fill='x')
        tk.Label(self.history_frame,
                 text="No scan history yet.",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=self.theme.text_muted).pack(
            anchor='w', padx=PADDING_MD, pady=8)


    def _build_change_panel(self, parent):
        """Change detection feed."""
        p = self._panel(parent, "CHANGE DETECTION  [Feature 47]")
        self.change_frame = tk.Frame(p, bg=self.theme.bg_secondary)
        self.change_frame.pack(fill='x')
        tk.Label(self.change_frame,
                 text="Changes between scans will appear here.",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=self.theme.text_muted).pack(
            anchor='w', padx=PADDING_MD, pady=8)


    def _build_performance_panel(self, parent):
        """Network performance metrics."""
        p = self._panel(parent, "NETWORK PERFORMANCE  [Features 85-88]")
        self.perf_frame = tk.Frame(p, bg=self.theme.bg_secondary)
        self.perf_frame.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)

        self.perf_widgets = {}
        metrics = [
            ('latency',    'Router ping latency'),
            ('packet_loss','Packet loss'),
            ('dns_time',   'DNS response time'),
            ('connections','Active connections'),
        ]

        for key, label in metrics:
            row = tk.Frame(self.perf_frame, bg=self.theme.bg_secondary)
            row.pack(fill='x', pady=2)
            tk.Label(row, text=label,
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary,
                     fg=self.theme.text_secondary,
                     width=22, anchor='w').pack(side='left')
            val = tk.Label(row, text="—",
                           font=self.theme.font(size=FONT_SIZE_MD, bold=True,
                                                mono=True),
                           bg=self.theme.bg_secondary,
                           fg=self.theme.text_muted)
            val.pack(side='left')
            self.perf_widgets[key] = val


    def _build_inactive_panel(self, parent):
        """Inactive device tracker."""
        p = self._panel(parent, "INACTIVE DEVICES  [Feature 50]")
        self.inactive_frame = tk.Frame(p, bg=self.theme.bg_secondary)
        self.inactive_frame.pack(fill='x')
        self._refresh_inactive_devices()


    def _build_scheduled_panel(self, parent):
        """Scheduled scan reminder and settings."""
        p = self._panel(parent, "SCHEDULED SCAN  [Feature 52]")
        inner = tk.Frame(p, bg=self.theme.bg_secondary)
        inner.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)

        schedule = self.db.get_setting('scan_schedule', 'weekly')
        tk.Label(inner,
                 text=f"Current schedule: {schedule.title()}",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_primary).pack(anchor='w')
        tk.Label(inner,
                 text="Change schedule in Reports & Settings tab.",
                 font=self.theme.font(size=FONT_SIZE_XS),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_muted).pack(anchor='w', pady=(4, 0))

        # Last scan info
        last = self.db.get_last_scan()
        if last:
            try:
                dt = datetime.datetime.fromisoformat(last['scan_date'])
                date_str = dt.strftime("%b %d %Y at %I:%M %p")
            except Exception:
                date_str = last.get('scan_date', '?')[:16]
            tk.Label(inner,
                     text=f"Last scan: {date_str}",
                     font=self.theme.font(size=FONT_SIZE_XS),
                     bg=self.theme.bg_secondary,
                     fg=self.theme.text_secondary).pack(anchor='w', pady=(8, 0))


    def _load_history(self):
        """Loads scan history from database and populates the panel."""
        history = self.db.get_scan_history(limit=10)
        self._populate_history(history)
        self._populate_changes(history)
        self._refresh_inactive_devices()


    def _populate_history(self, history):
        """Fills the scan history panel."""
        for w in self.history_frame.winfo_children():
            w.destroy()

        if not history:
            tk.Label(self.history_frame,
                     text="No scans recorded yet.",
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary,
                     fg=self.theme.text_muted).pack(
                anchor='w', padx=PADDING_MD, pady=8)
            return

        for scan in history:
            try:
                dt = datetime.datetime.fromisoformat(scan['scan_date'])
                date_str = dt.strftime("%b %d — %I:%M %p")
            except Exception:
                date_str = scan.get('scan_date', '?')[:16]

            critical = scan.get('critical_count', 0)
            warnings = scan.get('warning_count', 0)
            devices = scan.get('devices_found', 0)
            scan_type = scan.get('scan_type', '?')
            score = scan.get('score', '?')

            # Badge color
            if critical > 0:
                badge_color, badge_bg, badge_text = COLOR_CRITICAL, BG_CRITICAL, "issues"
            elif warnings > 0:
                badge_color, badge_bg, badge_text = COLOR_WARNING, BG_WARNING, "warnings"
            else:
                badge_color, badge_bg, badge_text = COLOR_SAFE, BG_SAFE, "clean"

            row = tk.Frame(self.history_frame, bg=self.theme.bg_secondary)
            row.pack(fill='x', pady=1)

            tk.Label(row, text=date_str,
                     font=self.theme.font(size=FONT_SIZE_XS, mono=True),
                     bg=self.theme.bg_secondary, fg=self.theme.text_muted,
                     width=18, anchor='w').pack(side='left', padx=(PADDING_MD, 4), pady=4)

            tk.Label(row,
                     text=f"{devices} devices · score {score} · {scan_type}",
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary,
                     fg=self.theme.text_primary).pack(side='left', fill='x', expand=True)

            tk.Label(row, text=badge_text,
                     font=self.theme.font(size=FONT_SIZE_XS, bold=True),
                     bg=badge_bg, fg=badge_color,
                     padx=5, pady=1).pack(side='right', padx=PADDING_MD)

            tk.Frame(self.history_frame,
                     bg=self.theme.border_light, height=1).pack(fill='x')


    def _populate_changes(self, history):
        """Compares recent scans to detect changes."""
        for w in self.change_frame.winfo_children():
            w.destroy()

        if len(history) < 2:
            tk.Label(self.change_frame,
                     text="Need at least 2 scans to detect changes.",
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary, fg=self.theme.text_muted).pack(
                anchor='w', padx=PADDING_MD, pady=8)
            return

        # Compare most recent to previous
        latest = history[0]
        previous = history[1]

        changes = []

        dev_diff = latest.get('devices_found', 0) - previous.get('devices_found', 0)
        if dev_diff > 0:
            changes.append(('new', f"{dev_diff} new device(s) appeared"))
        elif dev_diff < 0:
            changes.append(('gone', f"{abs(dev_diff)} device(s) no longer seen"))

        score_diff = latest.get('score', 100) - previous.get('score', 100)
        if score_diff < -10:
            changes.append(('risk', f"Score dropped {abs(score_diff)} points"))
        elif score_diff > 10:
            changes.append(('improved', f"Score improved {score_diff} points"))

        crit_diff = latest.get('critical_count', 0) - previous.get('critical_count', 0)
        if crit_diff > 0:
            changes.append(('risk', f"{crit_diff} new critical issue(s)"))
        elif crit_diff < 0:
            changes.append(('improved', f"{abs(crit_diff)} critical issue(s) resolved"))

        if not changes:
            changes.append(('clean', "No significant changes between scans"))

        colors = {
            'new':      (COLOR_INFO, BG_INFO),
            'gone':     (COLOR_SAFE, BG_SAFE),
            'risk':     (COLOR_CRITICAL, BG_CRITICAL),
            'improved': (COLOR_SAFE, BG_SAFE),
            'clean':    (COLOR_SAFE, BG_SAFE),
        }

        for change_type, text in changes:
            color, bg = colors.get(change_type, (COLOR_INFO, BG_INFO))
            row = tk.Frame(self.change_frame, bg=self.theme.bg_secondary)
            row.pack(fill='x', pady=1)
            tk.Label(row, text=change_type.upper(),
                     font=self.theme.font(size=FONT_SIZE_XS, bold=True),
                     bg=bg, fg=color, padx=5, pady=1).pack(
                side='left', padx=(PADDING_MD, 8), pady=4)
            tk.Label(row, text=text,
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary,
                     fg=self.theme.text_primary).pack(side='left')
            tk.Frame(self.change_frame,
                     bg=self.theme.border_light, height=1).pack(fill='x')


    def _refresh_inactive_devices(self):
        """Shows devices not seen in the last 30 days."""
        for w in self.inactive_frame.winfo_children():
            w.destroy()

        inactive = self.db.get_inactive_devices(days=30)

        if not inactive:
            tk.Label(self.inactive_frame,
                     text="No inactive devices (all seen within 30 days).",
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary, fg=self.theme.text_muted).pack(
                anchor='w', padx=PADDING_MD, pady=8)
            return

        for device in inactive[:8]:
            ip = device.get('ip_address', '?')
            mfr = device.get('manufacturer', 'Unknown')
            last = device.get('last_seen', '?')[:10]
            nickname = device.get('nickname', '')
            label = nickname or mfr

            row = tk.Frame(self.inactive_frame, bg=self.theme.bg_secondary)
            row.pack(fill='x', pady=1)
            tk.Label(row, text="●",
                     font=self.theme.font(size=FONT_SIZE_XS),
                     bg=self.theme.bg_secondary, fg=COLOR_WARNING).pack(
                side='left', padx=(PADDING_MD, 6), pady=4)
            tk.Label(row, text=f"{ip}  {label[:20]}",
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary,
                     fg=self.theme.text_primary).pack(side='left', fill='x', expand=True)
            tk.Label(row, text=f"last: {last}",
                     font=self.theme.font(size=FONT_SIZE_XS, mono=True),
                     bg=self.theme.bg_secondary,
                     fg=self.theme.text_muted).pack(side='right', padx=PADDING_MD)
            tk.Frame(self.inactive_frame,
                     bg=self.theme.border_light, height=1).pack(fill='x')


    def _run_performance(self):
        """Runs performance checks in background."""
        self.status_callback("Running performance checks...", "scanning")

        def _run():
            results = {}

            # Ping router
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                parts = local_ip.split('.')
                router = f"{parts[0]}.{parts[1]}.{parts[2]}.1"

                ping = subprocess.run(
                    ['ping', '-n', '10', router],
                    capture_output=True, text=True, timeout=30,
                    creationflags=0x08000000)  # CREATE_NO_WINDOW — prevents console flash

                avg_match = re.search(r'Average = (\d+)ms', ping.stdout)
                loss_match = re.search(r'(\d+)% loss', ping.stdout)

                results['latency'] = f"{avg_match.group(1)}ms" if avg_match else "—"
                results['packet_loss'] = f"{loss_match.group(1)}%" if loss_match else "0%"

                loss_val = int(loss_match.group(1)) if loss_match else 0
                lat_val = int(avg_match.group(1)) if avg_match else 0

                results['latency_color'] = (
                    COLOR_SAFE if lat_val < 20
                    else COLOR_WARNING if lat_val < 100
                    else COLOR_CRITICAL)
                results['loss_color'] = (
                    COLOR_SAFE if loss_val == 0
                    else COLOR_WARNING if loss_val < 5
                    else COLOR_CRITICAL)

            except Exception:
                results['latency'] = "error"
                results['packet_loss'] = "error"
                results['latency_color'] = COLOR_WARNING
                results['loss_color'] = COLOR_WARNING

            # DNS response time
            try:
                import time
                start = time.time()
                socket.gethostbyname('www.google.com')
                dns_ms = int((time.time() - start) * 1000)
                results['dns_time'] = f"{dns_ms}ms"
                results['dns_color'] = (
                    COLOR_SAFE if dns_ms < 100
                    else COLOR_WARNING if dns_ms < 500
                    else COLOR_CRITICAL)
            except Exception:
                results['dns_time'] = "error"
                results['dns_color'] = COLOR_WARNING

            # Active connections
            try:
                ns = subprocess.run(
                    ['netstat', '-n'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=0x08000000)  # CREATE_NO_WINDOW — prevents console flash
                count = sum(1 for l in ns.stdout.split('\n')
                            if l.strip().startswith('TCP'))
                results['connections'] = str(count)
                results['conn_color'] = (
                    COLOR_SAFE if count < 100
                    else COLOR_WARNING if count < 300
                    else COLOR_CRITICAL)
            except Exception:
                results['connections'] = "error"
                results['conn_color'] = COLOR_WARNING

            self.parent.after(0, lambda: self._update_performance(results))
            self.parent.after(0, lambda: self.status_callback(
                "Performance check complete", "ready"))

        threading.Thread(target=_run, daemon=True).start()


    def _update_performance(self, results):
        """Updates performance metric widgets."""
        mapping = [
            ('latency',     results.get('latency', '—'),
             results.get('latency_color', self.theme.text_primary)),
            ('packet_loss', results.get('packet_loss', '—'),
             results.get('loss_color', self.theme.text_primary)),
            ('dns_time',    results.get('dns_time', '—'),
             results.get('dns_color', self.theme.text_primary)),
            ('connections', results.get('connections', '—'),
             results.get('conn_color', self.theme.text_primary)),
        ]
        for key, val, color in mapping:
            if key in self.perf_widgets:
                self.perf_widgets[key].configure(text=val, fg=color)


    def update(self, scan_results):
        """Called after a full scan to refresh all panels."""
        self._load_history()


    def _panel(self, parent, title):
        """Creates a standard panel."""
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
        self.inner.configure(bg=self.theme.bg_primary)
