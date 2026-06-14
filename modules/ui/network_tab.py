"""
=============================================================
  SENTINELHOME101 — Network Tab
  File: modules/ui/network_tab.py

  Covers Tier 4 device and network exposure features:
  - Device inventory with risk scores
  - Open port details per device
  - Network health checks (WiFi, DNS, router, firewall)
  - Guest network and IoT isolation
  - Visual network summary
=============================================================
"""

import tkinter as tk
from tkinter import messagebox
import threading
import subprocess
import re
from modules.constants import *
from modules.theme import ThemeManager


class NetworkTab:
    """Builds and manages the Network tab."""

    def __init__(self, parent, theme, db, status_callback, run_scan_callback):
        self.parent = parent
        self.theme = theme
        self.db = db
        self.status_callback = status_callback
        self.run_scan_callback = run_scan_callback
        self.devices = []
        self.network_checks = {}
        self._selected_device = None

        self._build()
        self.theme.register(self._apply_theme)


    def _build(self):
        """Builds the network tab layout."""
        # Header
        hdr = tk.Frame(self.parent, bg=self.theme.bg_primary)
        hdr.pack(fill='x', padx=PADDING_LG, pady=PADDING_LG)
        tk.Label(hdr, text="Network",
                 font=self.theme.font(size=FONT_SIZE_XL, bold=True),
                 bg=self.theme.bg_primary, fg=self.theme.text_primary).pack(side='left')
        tk.Button(hdr, text="Run Network Scan",
                  font=self.theme.font(size=FONT_SIZE_SM, bold=True),
                  bg=self.theme.accent, fg=self.theme.bg_primary,
                  relief='flat', padx=12, pady=4, cursor="hand2",
                  command=self.run_scan_callback).pack(side='right')

        # Pill selector: Devices / Health
        pill_row = tk.Frame(self.parent, bg=self.theme.bg_primary)
        pill_row.pack(fill='x', padx=PADDING_LG)

        self.pill_var = tk.StringVar(value='devices')

        for label, val in [('Devices', 'devices'), ('Network Health', 'health')]:
            tk.Radiobutton(
                pill_row, text=label, variable=self.pill_var, value=val,
                font=self.theme.font(size=FONT_SIZE_SM),
                bg=self.theme.bg_primary, fg=self.theme.text_secondary,
                selectcolor=self.theme.bg_tertiary,
                activebackground=self.theme.bg_primary,
                activeforeground=self.theme.text_primary,
                indicatoron=False, relief='flat', padx=12, pady=4,
                cursor="hand2",
                command=self._switch_pane
            ).pack(side='left', padx=(0, 4), pady=(0, PADDING_MD))

        # Content frame that switches between panes
        self.content = tk.Frame(self.parent, bg=self.theme.bg_primary)
        self.content.pack(fill='both', expand=True,
                          padx=PADDING_LG, pady=(0, PADDING_LG))

        self._build_devices_pane()
        self._build_health_pane()
        self._switch_pane()


    def _build_devices_pane(self):
        """Builds the device inventory pane."""
        self.devices_pane = tk.Frame(self.content, bg=self.theme.bg_primary)

        # Left: device list — fixed width
        left = tk.Frame(self.devices_pane, bg=self.theme.bg_secondary, width=220)
        left.pack(side='left', fill='y')
        left.pack_propagate(False)

        tk.Label(left, text="DEVICES FOUND",
                 font=self.theme.font(size=FONT_SIZE_XS),
                 bg=self.theme.bg_secondary, fg=self.theme.text_muted).pack(
            anchor='w', padx=PADDING_MD, pady=(PADDING_MD, 4))
        tk.Frame(left, bg=self.theme.border, height=1).pack(fill='x')

        # Scrollable device list inside left panel
        list_canvas = tk.Canvas(left, bg=self.theme.bg_secondary,
                                highlightthickness=0)
        list_sb = tk.Scrollbar(left, orient='vertical',
                               command=list_canvas.yview)
        list_canvas.configure(yscrollcommand=list_sb.set)
        list_sb.pack(side='right', fill='y')
        list_canvas.pack(side='left', fill='both', expand=True)

        self.device_list_frame = tk.Frame(list_canvas, bg=self.theme.bg_secondary)
        list_win = list_canvas.create_window(
            (0, 0), window=self.device_list_frame, anchor='nw')
        self.device_list_frame.bind('<Configure>', lambda e: list_canvas.configure(
            scrollregion=list_canvas.bbox('all')))
        list_canvas.bind('<Configure>', lambda e: list_canvas.itemconfig(
            list_win, width=e.width))

        tk.Label(self.device_list_frame,
                 text="Run a scan to\ndiscover devices.",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=self.theme.text_muted,
                 justify='center').pack(expand=True, pady=20)

        # Right: device detail — takes remaining space
        self.device_detail = tk.Frame(
            self.devices_pane, bg=self.theme.bg_secondary)
        self.device_detail.pack(
            side='right', fill='both', expand=True, padx=(8, 0))

        # Default empty state
        tk.Label(self.device_detail,
                 text="Select a device to see details.",
                 font=self.theme.font(size=FONT_SIZE_MD),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_muted).pack(expand=True)


    def _build_health_pane(self):
        """Builds the network health checks pane."""
        self.health_pane = tk.Frame(self.content, bg=self.theme.bg_primary)

        # Scrollable
        canvas = tk.Canvas(self.health_pane, bg=self.theme.bg_primary,
                           highlightthickness=0)
        sb = tk.Scrollbar(self.health_pane, orient='vertical',
                          command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)

        inner = tk.Frame(canvas, bg=self.theme.bg_primary)
        win = canvas.create_window((0, 0), window=inner, anchor='nw')
        inner.bind('<Configure>', lambda e: canvas.configure(
            scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>', lambda e: canvas.itemconfig(win, width=e.width))
        canvas.bind('<Map>', lambda e: canvas.bind_all(
            '<MouseWheel>', lambda e: canvas.yview_scroll(
                int(-1 * (e.delta / 120)), 'units')))
        canvas.bind('<Enter>', lambda e: canvas.bind_all(
            '<MouseWheel>', lambda e: canvas.yview_scroll(
                int(-1 * (e.delta / 120)), 'units')))
        canvas.bind('<Leave>', lambda e: canvas.unbind_all('<MouseWheel>'))

        # Two column grid
        left = tk.Frame(inner, bg=self.theme.bg_primary)
        left.pack(side='left', fill='both', expand=True, padx=(0, 8))
        right = tk.Frame(inner, bg=self.theme.bg_primary)
        right.pack(side='right', fill='both', expand=True)

        self.health_widgets = {}
        self._build_health_section(left, "WIFI SECURITY", [
            ('wifi_protocol',    'WiFi protocol'),
            ('wifi_band',        'Band'),
            ('wifi_ssid',        'SSID'),
            ('dns_servers',      'DNS servers'),
            ('dns_doh',          'DNS over HTTPS'),
            ('dns_hijack',       'DNS hijacking'),
        ])
        self._build_health_section(left, "ROUTER", [
            ('router_creds',     'Default credentials'),
            ('router_firmware',  'Firmware version'),
            ('upnp',             'UPnP status'),
            ('wps',              'WPS status'),
        ])
        self._build_health_section(right, "FIREWALL & ENCRYPTION", [
            ('firewall',         'Windows Firewall'),
            ('tls_version',      'TLS version'),
            ('https_downgrade',  'HTTPS downgrade'),
            ('ntp_sync',         'NTP time sync'),
        ])
        self._build_health_section(right, "NETWORK EXPOSURE", [
            ('arp_spoof',        'ARP spoofing'),
            ('rogue_dhcp',       'Rogue DHCP'),
            ('mdns',             'mDNS exposure'),
            ('open_shares',      'Open file shares'),
            ('wake_on_lan',      'Wake-on-LAN'),
            ('ipv6',             'IPv6 status'),
        ])

        # Run health checks button
        btn_frame = tk.Frame(inner, bg=self.theme.bg_primary)
        btn_frame.pack(fill='x', pady=PADDING_MD)
        tk.Button(btn_frame, text="Run Network Health Checks",
                  font=self.theme.font(size=FONT_SIZE_SM, bold=True),
                  bg=self.theme.accent, fg=self.theme.bg_primary,
                  relief='flat', padx=12, pady=6, cursor="hand2",
                  command=self._run_health_checks).pack()


    def _build_health_section(self, parent, title, items):
        """Builds a health check section with rows."""
        outer = tk.Frame(parent, bg=self.theme.bg_secondary)
        outer.pack(fill='x', pady=(0, 8))
        tk.Label(outer, text=title,
                 font=self.theme.font(size=FONT_SIZE_XS),
                 bg=self.theme.bg_secondary, fg=self.theme.text_muted).pack(
            anchor='w', padx=PADDING_MD, pady=(PADDING_MD, 4))
        tk.Frame(outer, bg=self.theme.border, height=1).pack(fill='x')

        for key, label in items:
            row = tk.Frame(outer, bg=self.theme.bg_secondary)
            row.pack(fill='x', pady=1)

            dot = tk.Label(row, text="●",
                           font=self.theme.font(size=FONT_SIZE_XS),
                           bg=self.theme.bg_secondary, fg=self.theme.text_muted)
            dot.pack(side='left', padx=(PADDING_MD, 6), pady=5)

            tk.Label(row, text=label,
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary, fg=self.theme.text_primary,
                     anchor='w').pack(side='left', fill='x', expand=True)

            val = tk.Label(row, text="—",
                           font=self.theme.font(size=FONT_SIZE_SM, mono=True),
                           bg=self.theme.bg_secondary, fg=self.theme.text_muted,
                           padx=PADDING_MD)
            val.pack(side='right')

            self.health_widgets[key] = {'dot': dot, 'val': val}
            tk.Frame(outer, bg=self.theme.border_light, height=1).pack(fill='x')


    def _switch_pane(self):
        """Switches between Devices and Health panes."""
        pane = self.pill_var.get()
        if pane == 'devices':
            self.health_pane.pack_forget()
            self.devices_pane.pack(fill='both', expand=True)
        else:
            self.devices_pane.pack_forget()
            self.health_pane.pack(fill='both', expand=True)


    def _run_health_checks(self):
        """Runs network health checks in background."""
        self.status_callback("Running network health checks...", "scanning")

        def _run():
            from modules.network_checks import NetworkChecker
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
            except Exception:
                local_ip = None

            checker = NetworkChecker(local_ip=local_ip)
            results = checker.run_all_checks()
            self.parent.after(0, lambda: self._apply_health_results(results))
            self.parent.after(0, lambda: self.status_callback(
                "Network health checks complete", "ready"))

        threading.Thread(target=_run, daemon=True).start()


    def _apply_health_results(self, results):
        """Updates health widget values from check results."""

        def _set(key, value, status):
            if key not in self.health_widgets:
                return
            w = self.health_widgets[key]
            color = (COLOR_SAFE if status == 'pass' else
                     COLOR_CRITICAL if status == 'fail' else COLOR_WARNING)
            w['dot'].configure(fg=color)
            w['val'].configure(text=str(value)[:30], fg=color)

        wifi = results.get('wifi_security', {})
        _set('wifi_protocol', wifi.get('auth', '—'), wifi.get('status', 'warn'))
        _set('wifi_band',     wifi.get('band', '—'),  'pass')
        _set('wifi_ssid',     wifi.get('ssid', '—'),  'pass')

        dns = results.get('dns_security', {})
        servers = dns.get('dns_servers', [])
        _set('dns_servers',  ', '.join(servers[:2]) if servers else '—',
             dns.get('status', 'warn'))
        _set('dns_hijack',
             'DETECTED' if dns.get('hijacked') else 'not detected',
             'fail' if dns.get('hijacked') else 'pass')

        doh = results.get('dns_over_https', {})
        _set('dns_doh', 'enabled' if doh.get('status') == 'pass' else 'not set',
             doh.get('status', 'warn'))

        router = results.get('router_credentials', {})
        _set('router_creds',
             'possible default' if router.get('default_likely') else 'changed',
             'warn' if router.get('default_likely') else 'pass')

        fw_ver = results.get('router_firmware', {})
        _set('router_firmware', fw_ver.get('version', '—')[:25], 'pass')

        upnp = results.get('upnp', {})
        _set('upnp',
             'enabled' if upnp.get('enabled') else 'disabled',
             'warn' if upnp.get('enabled') else 'pass')

        _set('wps', 'check router manually', 'warn')

        fw = results.get('firewall', {})
        _set('firewall', fw.get('detail', '—')[:25], fw.get('status', 'warn'))

        tls = results.get('tls_version', {})
        _set('tls_version', tls.get('version', '—'), tls.get('status', 'warn'))

        https = results.get('https_downgrade', {})
        _set('https_downgrade',
             'issue detected' if https.get('status') == 'fail' else 'ok',
             https.get('status', 'pass'))

        ntp = results.get('ntp_sync', {})
        _set('ntp_sync',
             f"offset {ntp.get('offset_secs', 0):.1f}s",
             ntp.get('status', 'warn'))

        arp = results.get('arp_spoofing', {})
        _set('arp_spoof',
             'suspicious' if arp.get('status') == 'warn' else 'clean',
             arp.get('status', 'pass'))

        dhcp = results.get('rogue_dhcp', {})
        _set('rogue_dhcp',
             'multiple servers' if dhcp.get('status') == 'warn' else 'clean',
             dhcp.get('status', 'pass'))

        mdns = results.get('mdns_exposure', {})
        _set('mdns',
             'broadcasting' if mdns.get('status') == 'warn' else 'quiet',
             mdns.get('status', 'pass'))

        shares = results.get('open_shares', {})
        share_list = shares.get('shares', [])
        _set('open_shares',
             f"{len(share_list)} found" if share_list else 'none',
             'warn' if share_list else 'pass')

        wol = results.get('wake_on_lan', {})
        _set('wake_on_lan',
             'enabled' if wol.get('status') == 'warn' else 'disabled',
             wol.get('status', 'pass'))

        ipv6 = results.get('ipv6_readiness', {})
        _set('ipv6',
             'active' if ipv6.get('has_ipv6') else 'not active',
             ipv6.get('status', 'warn'))


    def update(self, scan_results):
        """Called after a full scan to update device list."""
        self.devices = scan_results.get('devices', [])
        self.network_checks = scan_results.get('network_checks', {})
        self._populate_device_list()
        if self.network_checks:
            self._apply_health_results(self.network_checks)


    def _populate_device_list(self):
        """Populates the device list from scan results."""
        for w in self.device_list_frame.winfo_children():
            w.destroy()

        if not self.devices:
            tk.Label(self.device_list_frame,
                     text="No devices found.\nRun a scan.",
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary, fg=self.theme.text_muted,
                     justify='center').pack(expand=True, pady=20)
            return

        for device in self.devices:
            self._build_device_row(device)


    def _build_device_row(self, device):
        """Builds a clickable device row in the device list."""
        ip = device.get('ip', '?')
        mfr = device.get('manufacturer', 'Unknown')
        ports = device.get('open_ports', [])

        # Risk colour based on high-risk ports
        has_risk = any(p['port'] in self.high_risk_ports() for p in ports)
        dot_color = COLOR_CRITICAL if has_risk else COLOR_SAFE

        row = tk.Frame(self.device_list_frame, bg=self.theme.bg_secondary,
                       cursor="hand2")
        row.pack(fill='x', pady=1)

        dot = tk.Label(row, text="●",
                 font=self.theme.font(size=FONT_SIZE_XS),
                 bg=self.theme.bg_secondary, fg=dot_color,
                 cursor="hand2")
        dot.pack(side='left', padx=(PADDING_MD, 4), pady=6)

        info = tk.Frame(row, bg=self.theme.bg_secondary, cursor="hand2")
        info.pack(side='left', fill='x', expand=True)

        ip_lbl = tk.Label(info, text=ip,
                 font=self.theme.font(size=FONT_SIZE_SM, mono=True),
                 bg=self.theme.bg_secondary, fg=self.theme.text_primary,
                 anchor='w', cursor="hand2")
        ip_lbl.pack(anchor='w')

        mfr_lbl = tk.Label(info, text=mfr[:22],
                 font=self.theme.font(size=FONT_SIZE_XS),
                 bg=self.theme.bg_secondary, fg=self.theme.text_muted,
                 anchor='w', cursor="hand2")
        mfr_lbl.pack(anchor='w')

        tk.Frame(self.device_list_frame,
                 bg=self.theme.border_light, height=1).pack(fill='x')

        # Bind click on every widget in the row so clicking anywhere works
        click_handler = lambda e, d=device: self._show_device_detail(d)
        for widget in [row, dot, info, ip_lbl, mfr_lbl]:
            widget.bind('<Button-1>', click_handler)


    def _show_device_detail(self, device):
        """Shows full detail for a selected device."""
        for w in self.device_detail.winfo_children():
            w.destroy()

        ip = device.get('ip', '?')
        mac = device.get('mac', 'Unknown')
        mfr = device.get('manufacturer', 'Unknown')
        hostname = device.get('hostname', 'Unknown')
        ports = device.get('open_ports', [])

        # Header
        hdr = tk.Frame(self.device_detail, bg=self.theme.bg_secondary)
        hdr.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)
        tk.Label(hdr, text=f"{mfr} — {ip}",
                 font=self.theme.font(size=FONT_SIZE_MD, bold=True),
                 bg=self.theme.bg_secondary, fg=self.theme.text_primary).pack(anchor='w')

        meta = f"MAC: {mac}   Hostname: {hostname}"
        tk.Label(hdr, text=meta,
                 font=self.theme.font(size=FONT_SIZE_XS, mono=True),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_muted).pack(anchor='w', pady=(2, 0))

        tk.Frame(self.device_detail, bg=self.theme.border, height=1).pack(fill='x')

        # DB info
        db_devices = self.db.get_all_devices()
        db_rec = next((d for d in db_devices if d.get('mac_address') == mac), None)
        if db_rec:
            first = db_rec.get('first_seen', '?')[:10]
            last = db_rec.get('last_seen', '?')[:10]
            nickname = db_rec.get('nickname', '')
            info_frame = tk.Frame(self.device_detail, bg=self.theme.bg_secondary)
            info_frame.pack(fill='x', padx=PADDING_MD, pady=(8, 4))
            tk.Label(info_frame,
                     text=f"First seen: {first}   Last seen: {last}",
                     font=self.theme.font(size=FONT_SIZE_XS),
                     bg=self.theme.bg_secondary,
                     fg=self.theme.text_muted).pack(anchor='w')

        # Ports section
        tk.Label(self.device_detail,
                 text="OPEN PORTS",
                 font=self.theme.font(size=FONT_SIZE_XS),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_muted).pack(
            anchor='w', padx=PADDING_MD, pady=(8, 4))
        tk.Frame(self.device_detail,
                 bg=self.theme.border_light, height=1).pack(fill='x')

        if not ports:
            tk.Label(self.device_detail,
                     text="No open ports detected",
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary,
                     fg=self.theme.text_muted).pack(
                padx=PADDING_MD, pady=8, anchor='w')
        else:
            for p in ports:
                port_num = p.get('port', '?')
                desc = p.get('description', '')
                high_risk = p.get('high_risk', False)
                banner = p.get('banner', '')

                color = COLOR_CRITICAL if high_risk else COLOR_WARNING \
                    if port_num in (80, 8080, 1883) else COLOR_SAFE

                row = tk.Frame(self.device_detail,
                               bg=self.theme.bg_primary)
                row.pack(fill='x', padx=PADDING_MD, pady=2)
                tk.Label(row, text=str(port_num),
                         font=self.theme.font(size=FONT_SIZE_SM, mono=True),
                         bg=self.theme.bg_primary, fg=color,
                         width=6).pack(side='left')
                tk.Label(row, text=desc,
                         font=self.theme.font(size=FONT_SIZE_SM),
                         bg=self.theme.bg_primary,
                         fg=self.theme.text_primary).pack(side='left', fill='x', expand=True)
                if high_risk:
                    tk.Label(row, text="HIGH RISK",
                             font=self.theme.font(size=FONT_SIZE_XS, bold=True),
                             bg=BG_CRITICAL, fg=COLOR_CRITICAL,
                             padx=4).pack(side='right')


    def high_risk_ports(self):
        return {23, 21, 3389, 5900, 49152}


    def _apply_theme(self):
        pass
