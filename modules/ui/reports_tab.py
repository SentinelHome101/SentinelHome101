"""
=============================================================
  SENTINELHOME101 — Reports & Settings Tab
  File: modules/ui/reports_tab.py

  Covers Tier 10 reporting and usability features:
  97. Exportable HTML report
  98. One-click remediation links
  99. Help / glossary panel
  100. Dark / light mode toggle
  Plus all app settings and preferences.
=============================================================
"""

import tkinter as tk                      # Main GUI library
from tkinter import filedialog, messagebox # File dialogs and message boxes
import os                                  # File path operations
import datetime                            # Date and time for report naming
import webbrowser                          # Opens reports in browser
from modules.constants import *            # App-wide constants (colors, fonts, etc.)
from modules.theme import ThemeManager     # Theme switching support


class ReportsTab:
    """Builds and manages the Reports & Settings tab."""

    def __init__(self, parent, theme, db, toggle_theme_callback, status_callback):
        self.parent = parent                                    # Parent widget this tab lives in
        self.theme = theme                                      # Theme manager for colors and fonts
        self.db = db                                            # Database for settings and scan data
        self.toggle_theme_callback = toggle_theme_callback      # Callback to switch dark/light mode
        self.status_callback = status_callback                  # Callback to update status bar
        self.last_scan_results = None                           # Stores most recent scan results

        self._build()                           # Build the tab UI
        self.theme.register(self._apply_theme)  # Register for theme change notifications


    def _build(self):
        """Builds the reports and settings tab layout."""
        # Scrollable canvas so content can scroll if it exceeds window height
        self.canvas = tk.Canvas(
            self.parent, bg=self.theme.bg_primary, highlightthickness=0)
        sb = tk.Scrollbar(self.parent, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=sb.set)            # Link scrollbar to canvas
        sb.pack(side='right', fill='y')                         # Scrollbar on right edge
        self.canvas.pack(side='left', fill='both', expand=True) # Canvas fills remaining space

        self.inner = tk.Frame(self.canvas, bg=self.theme.bg_primary)  # Inner frame holds all content
        self.win_id = self.canvas.create_window(
            (0, 0), window=self.inner, anchor='nw')             # Embed inner frame in canvas
        self.inner.bind('<Configure>', lambda e: self.canvas.configure(
            scrollregion=self.canvas.bbox('all')))              # Update scroll region when content changes
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfig(
            self.win_id, width=e.width))                        # Stretch inner frame to canvas width
        self.canvas.bind('<Map>', lambda e: self.canvas.bind_all(
            '<MouseWheel>', lambda e: self.canvas.yview_scroll(
                int(-1 * (e.delta / 120)), 'units')))
        self.canvas.bind('<Enter>', lambda e: self.canvas.bind_all(
            '<MouseWheel>', lambda e: self.canvas.yview_scroll(
                int(-1 * (e.delta / 120)), 'units')))
        self.canvas.bind('<Leave>', lambda e: self.canvas.unbind_all('<MouseWheel>'))                # Enable mouse wheel scrolling

        # Header row with tab title
        hdr = tk.Frame(self.inner, bg=self.theme.bg_primary)
        hdr.pack(fill='x', padx=PADDING_LG, pady=PADDING_LG)
        tk.Label(hdr, text="Reports & Settings",
                 font=self.theme.font(size=FONT_SIZE_XL, bold=True),
                 bg=self.theme.bg_primary,
                 fg=self.theme.text_primary).pack(side='left')

        # Two column layout — left for reports, right for settings
        cols = tk.Frame(self.inner, bg=self.theme.bg_primary)
        cols.pack(fill='both', expand=True,
                  padx=PADDING_LG, pady=(0, PADDING_LG))
        left = tk.Frame(cols, bg=self.theme.bg_primary)
        left.pack(side='left', fill='both', expand=True, padx=(0, 8))  # Left column with gap
        right = tk.Frame(cols, bg=self.theme.bg_primary)
        right.pack(side='right', fill='both', expand=True)              # Right column

        self._build_export_panel(left)      # Export buttons in left column
        self._build_report_history(left)    # Report history in left column
        self._build_settings_panel(right)   # Settings toggles in right column
        self._build_help_panel(right)       # Help glossary in right column


    def _build_export_panel(self, parent):
        """Export reports section."""
        p = self._panel(parent, "EXPORT REPORTS  [Feature 97]")
        inner = tk.Frame(p, bg=self.theme.bg_secondary)
        inner.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)

        # List of export buttons with their labels and handler functions
        buttons = [
            ("Export HTML Report (dark theme)",    self._export_html_dark),
            ("Export HTML Report (light theme)",   self._export_html_light),
            ("Export Plain Text (.txt)",           self._export_txt),
            ("Export Device Data (.csv)",          self._export_csv),
        ]

        for label, cmd in buttons:                          # Create one button per export type
            btn = tk.Button(
                inner, text=label,
                font=self.theme.font(size=FONT_SIZE_SM),
                bg=self.theme.bg_tertiary, fg=self.theme.text_primary,
                relief='flat', padx=10, pady=6,
                cursor="hand2", anchor='w',
                command=cmd)
            btn.pack(fill='x', pady=2)                      # Stack buttons vertically


    def _build_report_history(self, parent):
        """Shows previously saved reports."""
        p = self._panel(parent, "REPORT HISTORY")
        self.history_frame = tk.Frame(p, bg=self.theme.bg_secondary)
        self.history_frame.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)
        self._refresh_report_history()                      # Populate with existing report files


    def _build_settings_panel(self, parent):
        """All app settings and toggles."""
        p = self._panel(parent, "SETTINGS")
        inner = tk.Frame(p, bg=self.theme.bg_secondary)
        inner.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)

        # Network name setting row
        self._setting_row(inner, "Network name",
                          self.db.get_setting('network_name', 'Home Network'),
                          self._edit_network_name)

        # Default scan profile setting row
        self._setting_row(inner, "Default scan profile",
                          self.db.get_setting('scan_profile', DEFAULT_SCAN_PROFILE).title(),
                          self._change_scan_profile)

        # Dark mode toggle row
        theme_row = tk.Frame(inner, bg=self.theme.bg_secondary)
        theme_row.pack(fill='x', pady=4)
        tk.Label(theme_row, text="Dark mode",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_primary).pack(side='left')

        self.theme_btn = tk.Button(
            theme_row,
            text="ON" if self.theme.is_dark else "OFF",
            font=self.theme.font(size=FONT_SIZE_XS, bold=True),
            bg=COLOR_SAFE if self.theme.is_dark else self.theme.bg_tertiary,
            fg=self.theme.bg_primary if self.theme.is_dark else self.theme.text_secondary,
            relief='flat', padx=8, pady=2,
            cursor="hand2",
            command=self._toggle_theme)
        self.theme_btn.pack(side='right')
        tk.Frame(inner, bg=self.theme.border_light, height=1).pack(fill='x', pady=4)  # Divider

        # Speed test opt-in toggle
        self._toggle_setting(inner,
                             "Internet speed test",
                             "Connects to Speedtest.net — opt-in",
                             'speedtest_enabled',
                             external=True)

        # HIBP credential breach check opt-in toggle
        self._toggle_setting(inner,
                             "Credential breach check",
                             "Sends hashed email to HaveIBeenPwned.com — opt-in",
                             'hibp_enabled',
                             external=True)

        # HIBP API key entry row
        hibp_key_row = tk.Frame(inner, bg=self.theme.bg_secondary)  # Row container for API key setting
        hibp_key_row.pack(fill='x', pady=4)                         # Pack with vertical padding

        tk.Label(                                           # Label on the left side of the row
            hibp_key_row,
            text="HIBP API key",                           # Setting name shown to user
            font=self.theme.font(size=FONT_SIZE_SM),       # Standard small font
            bg=self.theme.bg_secondary,                    # Match panel background
            fg=self.theme.text_primary                     # Primary text color
        ).pack(side='left')                                # Left-align the label

        current_key = self.db.get_setting('hibp_api_key', '')  # Read current key from database
        key_status = "Set" if current_key else "Not set"       # Show status not actual key value

        self.hibp_key_status = tk.Label(                   # Status label shows Set or Not set
            hibp_key_row,
            text=key_status,                               # Current status text
            font=self.theme.font(size=FONT_SIZE_XS),       # Smaller font for status
            bg=self.theme.bg_secondary,                    # Match panel background
            fg=COLOR_SAFE if current_key else self.theme.text_muted  # Green if set, muted if not
        )
        self.hibp_key_status.pack(side='right', padx=(0, 8))  # Right-align with small gap

        tk.Button(                                          # Edit button opens the key entry dialog
            hibp_key_row,
            text="Edit",                                    # Button label
            font=self.theme.font(size=FONT_SIZE_XS),       # Small font matching other setting buttons
            bg=self.theme.bg_tertiary,                     # Tertiary background for secondary actions
            fg=self.theme.text_secondary,                  # Secondary text color
            relief='flat',                                 # No border
            padx=8, pady=2,                               # Internal padding
            cursor="hand2",                                # Hand cursor on hover
            command=self._edit_hibp_key                    # Opens the key entry dialog
        ).pack(side='right')                               # Right-align button before status label

        tk.Frame(inner, bg=self.theme.border_light, height=1).pack(fill='x', pady=4)  # Divider line

        # Weekly scan reminder toggle
        self._toggle_setting(inner,
                             "Weekly scheduled scan reminder",
                             "Shows reminder when app launches after 7 days",
                             'scan_schedule_enabled')

        # About section panel
        about_p = self._panel(parent, "ABOUT")
        about_inner = tk.Frame(about_p, bg=self.theme.bg_secondary)
        about_inner.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)

        # App info lines with different colors for hierarchy
        for line, color in [
            (f"{APP_NAME}", self.theme.accent),
            (f"Version {APP_VERSION}", self.theme.text_primary),
            (f"101-point home network security audit", self.theme.text_secondary),
            (f"Support: {APP_SUPPORT}", self.theme.text_muted),
        ]:
            tk.Label(about_inner, text=line,
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary, fg=color).pack(anchor='w')


    def _build_help_panel(self, parent):
        """Help and glossary panel — Feature 99."""
        p = self._panel(parent, "HELP & GLOSSARY  [Feature 99]")
        inner = tk.Frame(p, bg=self.theme.bg_secondary)
        inner.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)

        # Each tuple is (topic title, explanation body)
        topics = [
            ("What is UPnP?",
             "Universal Plug and Play. A protocol that lets devices automatically "
             "open ports in your router's firewall. Convenient but dangerous — "
             "malware can use UPnP to open ports for remote access without your knowledge. "
             "Recommendation: disable UPnP in your router settings."),

            ("What is ARP spoofing?",
             "A network attack where an attacker sends fake ARP (Address Resolution Protocol) "
             "messages to link their MAC address with your router's IP address. "
             "This causes all your traffic to flow through the attacker's machine. "
             "Detection: SentinelHome101 checks the ARP table for duplicate MAC addresses."),

            ("What is BitLocker?",
             "Windows full-disk encryption. If BitLocker is enabled and someone steals "
             "your computer, they cannot access your data without your password. "
             "Enable it: Settings → System → Device encryption, or search BitLocker."),

            ("What is DNS hijacking?",
             "An attack where your DNS queries (website lookups) are redirected to a "
             "malicious server that returns wrong answers, sending you to fake websites. "
             "SentinelHome101 detects this by verifying known domain lookups return "
             "expected IP addresses."),

            ("What is WPA3?",
             "The latest WiFi security protocol. WPA3 is stronger than WPA2 and "
             "protects against brute-force password attacks. Most routers made after "
             "2020 support WPA3. Enable it in your router's wireless settings."),

            ("What is a ransomware canary?",
             "A hidden file planted in key folders. Ransomware always modifies files "
             "before you notice anything wrong. If a canary file is changed or deleted, "
             "SentinelHome101 alerts you immediately — often catching ransomware before "
             "it has time to encrypt your important files."),

            ("What is the 3-2-1 backup rule?",
             "3 copies of your data, on 2 different media types, with 1 copy offsite. "
             "Example: files on your PC (1) + external drive (2) + cloud backup (3). "
             "This is your primary defense against ransomware data loss."),

            ("What is DNS over HTTPS?",
             "Encrypts your DNS queries so your ISP cannot see which websites you visit. "
             "Without DoH, your DNS lookups travel in plain text. Enable DoH in "
             "Windows Settings → Network & Internet → DNS → Encrypted DNS protocol."),

            ("What is lateral movement?",
             "When an attacker who has compromised one device on your network uses it as "
             "a stepping stone to access other devices. Example: a compromised smart TV "
             "scanning for and attacking your main PC. Network segmentation (separate "
             "guest/IoT networks) limits lateral movement."),

            ("What is a network risk score?",
             f"{APP_NAME} starts every scan at 100 and deducts points for findings. "
             "Critical issues cost 15 points each. Warnings cost 5 points. "
             "A score above 80 is good. 50-79 is fair. Below 50 needs attention."),
        ]

        for title, body in topics:          # Build one collapsible item per topic
            self._help_item(inner, title, body)


    def _help_item(self, parent, title, body):
        """Builds a collapsible help item."""
        item_frame = tk.Frame(parent, bg=self.theme.bg_secondary)
        item_frame.pack(fill='x', pady=2)

        expanded = tk.BooleanVar(value=False)           # Tracks whether this item is expanded
        body_frame = tk.Frame(item_frame, bg=self.theme.bg_secondary)  # Hidden body frame

        def toggle():
            """Shows or hides the body text when the title is clicked."""
            if expanded.get():
                body_frame.pack_forget()                # Hide body
                expanded.set(False)
                btn.configure(text=f"▶  {title}")      # Reset to collapsed arrow
            else:
                body_frame.pack(fill='x', padx=8, pady=(0, 6))  # Show body
                expanded.set(True)
                btn.configure(text=f"▼  {title}")      # Change to expanded arrow

        btn = tk.Button(
            item_frame, text=f"▶  {title}",
            font=self.theme.font(size=FONT_SIZE_SM),
            bg=self.theme.bg_secondary, fg=self.theme.text_primary,
            relief='flat', anchor='w', cursor="hand2",
            command=toggle)
        btn.pack(fill='x')

        tk.Label(body_frame, text=body,
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary, fg=self.theme.text_secondary,
                 wraplength=280, justify='left').pack(anchor='w', padx=8)

        tk.Frame(parent, bg=self.theme.border_light, height=1).pack(fill='x')  # Divider between items


    def _setting_row(self, parent, label, value, command):
        """Builds a setting row with label, current value, and change button."""
        row = tk.Frame(parent, bg=self.theme.bg_secondary)
        row.pack(fill='x', pady=4)
        tk.Label(row, text=label,
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_primary).pack(side='left')          # Setting name on left
        tk.Button(row, text="Change",
                  font=self.theme.font(size=FONT_SIZE_XS),
                  bg=self.theme.bg_tertiary, fg=self.theme.text_secondary,
                  relief='flat', padx=6, pady=1,
                  cursor="hand2", command=command).pack(side='right')   # Change button on right
        tk.Label(row, text=value,
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_secondary).pack(side='right', padx=8)  # Current value next to button
        tk.Frame(parent, bg=self.theme.border_light, height=1).pack(fill='x')  # Divider


    def _toggle_setting(self, parent, label, subtitle, setting_key, external=False):
        """Builds a toggle switch for a boolean setting stored in the database."""
        row = tk.Frame(parent, bg=self.theme.bg_secondary)
        row.pack(fill='x', pady=4)

        left = tk.Frame(row, bg=self.theme.bg_secondary)
        left.pack(side='left', fill='x', expand=True)

        lbl_row = tk.Frame(left, bg=self.theme.bg_secondary)
        lbl_row.pack(anchor='w')
        tk.Label(lbl_row, text=label,
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_primary).pack(side='left')          # Setting label
        if external:                                                    # Show warning badge for opt-in features
            tk.Label(lbl_row, text=" ⚠ external",
                     font=self.theme.font(size=FONT_SIZE_XS),
                     bg=BG_WARNING, fg=COLOR_WARNING,
                     padx=4).pack(side='left', padx=4)

        tk.Label(left, text=subtitle,
                 font=self.theme.font(size=FONT_SIZE_XS),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_muted).pack(anchor='w')             # Subtitle below label

        current = self.db.get_setting(setting_key, 'false') == 'true'  # Read current value from database
        var = tk.BooleanVar(value=current)                              # Bind to checkbox

        def on_toggle():
            """Saves the new toggle value to the database and updates the button appearance."""
            new_val = var.get()
            self.db.set_setting(setting_key, 'true' if new_val else 'false')  # Persist to database
            btn.configure(
                text="ON" if new_val else "OFF",
                bg=COLOR_SAFE if new_val else self.theme.bg_tertiary,
                fg=self.theme.bg_primary if new_val else self.theme.text_secondary)

        btn = tk.Checkbutton(
            row, variable=var, command=on_toggle,
            text="ON" if current else "OFF",
            font=self.theme.font(size=FONT_SIZE_XS, bold=True),
            bg=COLOR_SAFE if current else self.theme.bg_tertiary,
            fg=self.theme.bg_primary if current else self.theme.text_secondary,
            selectcolor=COLOR_SAFE,
            relief='flat', padx=8, pady=2,
            indicatoron=False, cursor="hand2")
        btn.pack(side='right')

        tk.Frame(parent, bg=self.theme.border_light, height=1).pack(fill='x')  # Divider


    # =================================================================
    # EXPORT METHODS
    # =================================================================

    def _export_html_dark(self):
        """Exports a dark-theme HTML report."""
        self._export_html(dark=True)


    def _export_html_light(self):
        """Exports a light-theme HTML report."""
        self._export_html(dark=False)


    def _export_html(self, dark=True):
        """Generates and saves an HTML security report."""
        filename = filedialog.asksaveasfilename(        # Ask user where to save the file
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=f"sentinelhome101_report_{datetime.date.today()}.html",
            title="Save HTML Report"
        )
        if not filename:                                # User cancelled the dialog
            return

        try:
            html = self._generate_html_report(dark=dark)    # Generate report content
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)                               # Write to disk

            self.db.set_setting(f'report_{datetime.date.today()}', filename)  # Save to history
            self._refresh_report_history()                  # Update history panel

            if messagebox.askyesno(                         # Offer to open in browser
                "Report Saved",
                f"Report saved to:\n{filename}\n\nOpen in browser now?",
                parent=self.parent
            ):
                webbrowser.open(f"file:///{filename.replace(os.sep, '/')}")

            self.status_callback("Report exported successfully", "ready")

        except Exception as e:
            messagebox.showerror(
                "Export Failed", f"Could not save report:\n{str(e)}",
                parent=self.parent)


    def _generate_html_report(self, dark=True):
        """Generates the full HTML report content as a string."""
        # Color palette based on dark or light mode
        bg = "#0d1117" if dark else "#ffffff"
        text = "#e6edf3" if dark else "#0d1117"
        secondary = "#161b22" if dark else "#f8fafc"
        border = "#30363d" if dark else "#e2e8f0"
        muted = "#8b949e" if dark else "#64748b"
        accent = "#f1f5f9"

        last = self.db.get_last_scan()          # Most recent scan record
        findings = []
        devices = self.db.get_all_devices()     # All discovered network devices

        if last:
            findings = self.db.get_findings_for_scan(last['id'])  # Findings for last scan

        network_name = self.db.get_setting('network_name', 'Home Network')
        score = last.get('score', '—') if last else '—'
        scan_date = last.get('scan_date', '?')[:10] if last else '—'

        # Build findings HTML section
        findings_html = ""
        if findings:
            for f in findings:
                sev = f.get('severity', 'info')
                sev_colors = {
                    'critical': ('#f85149', '#3a1010'),
                    'warning':  ('#d29922', '#3a2000'),
                    'info':     ('#378add', '#0d1a2e'),
                    'pass':     ('#3fb950', '#0d2818'),
                }
                fc, fb = sev_colors.get(sev, ('#8b949e', '#21262d'))
                findings_html += f"""
                <div style="border-left:3px solid {fc};padding:10px 14px;
                     margin-bottom:8px;background:{fb};border-radius:4px;">
                  <span style="background:{fb};color:{fc};
                       font-size:10px;font-weight:bold;padding:2px 6px;
                       border-radius:3px;margin-right:8px;">{sev.upper()}</span>
                  <strong style="color:{text}">{f.get('title', '')}</strong>
                  <div style="color:{muted};font-size:12px;margin-top:4px;">
                    {f.get('detail', '')}</div>
                  {"<div style='color:#d29922;font-size:11px;margin-top:4px;'>Fix: " + f.get('remediation','') + "</div>" if f.get('remediation') else ''}
                </div>"""
        else:
            findings_html = f'<p style="color:{muted}">No findings recorded. Run a scan first.</p>'

        # Build devices table HTML section
        devices_html = ""
        for d in devices[:20]:                  # Limit to 20 devices in report
            devices_html += f"""
            <tr>
              <td style="font-family:monospace">{d.get('ip_address','?')}</td>
              <td>{d.get('manufacturer','Unknown')}</td>
              <td style="font-family:monospace;font-size:11px">{d.get('mac_address','?')}</td>
              <td>{d.get('nickname','')}</td>
              <td>{d.get('last_seen','?')[:10]}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_NAME} Security Report — {scan_date}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:{bg}; color:{text}; font-family:'Segoe UI',system-ui,sans-serif;
         padding:40px 32px; max-width:960px; margin:0 auto; }}
  h1 {{ font-size:24px; font-weight:600; margin-bottom:4px; color:{accent}; }}
  h2 {{ font-size:14px; font-weight:600; color:{muted}; text-transform:uppercase;
        letter-spacing:.08em; margin:32px 0 12px; padding-bottom:8px;
        border-bottom:1px solid {border}; }}
  .meta {{ font-size:12px; color:{muted}; margin-bottom:32px; }}
  .score {{ font-size:48px; font-weight:700; color:{'#3fb950' if isinstance(score, int) and score >= 80 else '#d29922' if isinstance(score, int) and score >= 50 else '#f85149'}; }}
  .cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:24px; }}
  .card {{ background:{secondary}; border:1px solid {border}; border-radius:8px;
           padding:14px 16px; }}
  .card-num {{ font-size:28px; font-weight:700; font-family:monospace; }}
  .card-lbl {{ font-size:10px; color:{muted}; text-transform:uppercase;
               letter-spacing:.06em; margin-top:2px; }}
  table {{ width:100%; border-collapse:collapse; font-size:12px; }}
  th {{ text-align:left; padding:8px 12px; background:{secondary};
        color:{muted}; font-weight:500; border-bottom:1px solid {border}; }}
  td {{ padding:8px 12px; border-bottom:1px solid {border}; color:{text}; }}
  tr:hover td {{ background:{secondary}; }}
  .footer {{ margin-top:48px; padding-top:16px; border-top:1px solid {border};
             font-size:11px; color:{muted}; text-align:center; }}
</style>
</head>
<body>
<h1>{APP_NAME}</h1>
<div class="meta">
  Security Report — {network_name} — Generated {datetime.datetime.now().strftime('%B %d, %Y at %I:%M %p')}
</div>

<div class="cards">
  <div class="card">
    <div class="card-num" style="color:{'#d29922' if score != '—' else '#8b949e'}">{score}</div>
    <div class="card-lbl">Network Score</div>
  </div>
  <div class="card">
    <div class="card-num" style="color:#f85149">
      {sum(1 for f in findings if f.get('severity')=='critical')}
    </div>
    <div class="card-lbl">Critical</div>
  </div>
  <div class="card">
    <div class="card-num" style="color:#d29922">
      {sum(1 for f in findings if f.get('severity')=='warning')}
    </div>
    <div class="card-lbl">Warnings</div>
  </div>
  <div class="card">
    <div class="card-num">{len(devices)}</div>
    <div class="card-lbl">Devices</div>
  </div>
</div>

<h2>Security Findings</h2>
{findings_html}

<h2>Network Devices ({len(devices)})</h2>
<table>
  <tr>
    <th>IP Address</th><th>Manufacturer</th>
    <th>MAC Address</th><th>Nickname</th><th>Last Seen</th>
  </tr>
  {devices_html if devices_html else f'<tr><td colspan="5" style="color:{muted}">No devices recorded</td></tr>'}
</table>

<div class="footer">
  {APP_NAME} v{APP_VERSION} — {APP_SUPPORT} — All data collected locally on your machine
</div>
</body>
</html>"""

        return html


    def _export_txt(self):
        """Exports a plain text report."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"sentinelhome101_report_{datetime.date.today()}.txt",
            title="Save Text Report"
        )
        if not filename:
            return

        try:
            last = self.db.get_last_scan()
            findings = self.db.get_findings_for_scan(last['id']) if last else []
            network_name = self.db.get_setting('network_name', 'Home Network')

            lines = [
                f"{APP_NAME} v{APP_VERSION} — Security Report",
                f"Network: {network_name}",
                f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
                f"Score: {last.get('score', '?') if last else '?'}/100",
                "=" * 60,
                "",
                "FINDINGS:",
                ""
            ]

            for f in findings:
                lines.append(
                    f"[{f.get('severity','?').upper()}] {f.get('title','')}")
                if f.get('detail'):
                    lines.append(f"  {f.get('detail','')}")
                if f.get('remediation'):
                    lines.append(f"  Fix: {f.get('remediation','')}")
                lines.append("")

            with open(filename, 'w', encoding='utf-8') as fl:
                fl.write('\n'.join(lines))

            self.status_callback("Text report exported", "ready")
            messagebox.showinfo("Saved", f"Report saved to:\n{filename}",
                                parent=self.parent)
        except Exception as e:
            messagebox.showerror("Export Failed", str(e), parent=self.parent)


    def _export_csv(self):
        """Exports device data as CSV."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"sentinelhome101_devices_{datetime.date.today()}.csv",
            title="Save Device CSV"
        )
        if not filename:
            return

        try:
            devices = self.db.get_all_devices()
            lines = ["IP Address,MAC Address,Manufacturer,Hostname,Nickname,First Seen,Last Seen,Trusted"]

            for d in devices:
                # Guard every field against None — use empty string as fallback
                ip       = str(d.get('ip_address') or '')
                mac      = str(d.get('mac_address') or '')
                mfr      = str(d.get('manufacturer') or '').replace('"', "'")
                hostname = str(d.get('hostname') or '')
                nickname = str(d.get('nickname') or '')
                first    = str(d.get('first_seen') or '')[:10]
                last     = str(d.get('last_seen') or '')[:10]
                trusted  = 'Yes' if d.get('trusted') else 'No'

                lines.append(','.join([
                    ip,
                    mac,
                    f'"{mfr}"',
                    hostname,
                    nickname,
                    first,
                    last,
                    trusted
                ]))

            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))

            self.status_callback("CSV exported", "ready")
            messagebox.showinfo("Saved", f"Device data saved to:\n{filename}",
                                parent=self.parent)
        except Exception as e:
            messagebox.showerror("Export Failed", str(e), parent=self.parent)


    def _refresh_report_history(self):
        """Shows recently saved report files in the history panel."""
        for w in self.history_frame.winfo_children():
            w.destroy()                             # Clear existing entries

        reports_dir = self.db.app_data_dir          # Reports saved in AppData folder
        try:
            report_files = [
                f for f in os.listdir(reports_dir)
                if f.endswith('.html') or f.endswith('.txt')
            ]
            report_files.sort(reverse=True)         # Most recent first
        except Exception:
            report_files = []

        if not report_files:
            tk.Label(self.history_frame,
                     text="No reports saved yet.",
                     font=self.theme.font(size=FONT_SIZE_SM),
                     bg=self.theme.bg_secondary,
                     fg=self.theme.text_muted).pack(anchor='w', pady=8)
            return

        for fname in report_files[:5]:              # Show up to 5 most recent reports
            row = tk.Frame(self.history_frame, bg=self.theme.bg_secondary)
            row.pack(fill='x', pady=1)
            tk.Label(row, text=fname[:40],          # Truncate long filenames
                     font=self.theme.font(size=FONT_SIZE_SM, mono=True),
                     bg=self.theme.bg_secondary,
                     fg=self.theme.text_primary).pack(
                side='left', padx=(PADDING_MD, 0), pady=4)
            full_path = os.path.join(reports_dir, fname)
            tk.Button(row, text="Open",
                      font=self.theme.font(size=FONT_SIZE_XS),
                      bg=self.theme.bg_tertiary,
                      fg=self.theme.text_secondary,
                      relief='flat', padx=6, cursor="hand2",
                      command=lambda p=full_path: webbrowser.open(
                          f"file:///{p.replace(os.sep, '/')}")
                      ).pack(side='right', padx=PADDING_MD)
            tk.Frame(self.history_frame,
                     bg=self.theme.border_light, height=1).pack(fill='x')


    # =================================================================
    # SETTINGS ACTIONS
    # =================================================================

    def _toggle_theme(self):
        """Toggles dark/light mode and updates the button appearance."""
        self.toggle_theme_callback()                # Call the app-level theme toggle
        is_dark = self.theme.is_dark
        self.theme_btn.configure(
            text="ON" if is_dark else "OFF",
            bg=COLOR_SAFE if is_dark else self.theme.bg_tertiary,
            fg=self.theme.bg_primary if is_dark else self.theme.text_secondary)


    def _edit_network_name(self):
        """Opens a dialog to change the network name."""
        dialog = tk.Toplevel(self.parent)
        dialog.title("Edit Network Name")
        dialog.configure(bg=self.theme.bg_primary)
        dialog.resizable(False, False)
        dialog.geometry("360x140")
        dialog.grab_set()                           # Block main window while dialog is open

        tk.Label(dialog, text="Network name:",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_primary,
                 fg=self.theme.text_primary).pack(padx=20, pady=(20, 4), anchor='w')

        var = tk.StringVar(value=self.db.get_setting('network_name', 'Home Network'))
        entry = tk.Entry(dialog, textvariable=var,
                         font=self.theme.font(size=FONT_SIZE_SM),
                         bg=self.theme.bg_tertiary,
                         fg=self.theme.text_primary,
                         insertbackground=self.theme.text_primary,
                         relief='flat')
        entry.pack(fill='x', padx=20, pady=4)
        entry.focus_set()                           # Put cursor in field immediately

        def save():
            self.db.set_setting('network_name', var.get())  # Persist to database
            dialog.destroy()

        tk.Button(dialog, text="Save",
                  font=self.theme.font(size=FONT_SIZE_SM, bold=True),
                  bg=self.theme.accent, fg=self.theme.bg_primary,
                  relief='flat', padx=16, pady=4,
                  cursor="hand2", command=save).pack(pady=12)

        dialog.bind('<Return>', lambda e: save())   # Enter key triggers save


    def _edit_hibp_key(self):
        """
        Opens a dialog for the user to enter or update their HIBP API key.

        The key is stored locally in the database only.
        It is never transmitted anywhere — it is only used as a header
        in requests the user explicitly initiates from the Threat tab.
        Get a free key at: haveibeenpwned.com/API/Key
        """
        dialog = tk.Toplevel(self.parent)           # Create a new popup window
        dialog.title("HIBP API Key")                # Window title bar text
        dialog.configure(bg=self.theme.bg_primary)  # Match app background color
        dialog.resizable(False, False)              # Fixed size — no resize handles
        dialog.geometry("420x180")                  # Width x height in pixels
        dialog.grab_set()                           # Block main window while dialog is open

        tk.Label(                                   # Instruction label at top of dialog
            dialog,
            text="Enter your HaveIBeenPwned API key:",   # User-facing instruction
            font=self.theme.font(size=FONT_SIZE_SM),     # Standard small font
            bg=self.theme.bg_primary,                    # Match dialog background
            fg=self.theme.text_primary                   # Primary text color
        ).pack(padx=20, pady=(20, 4), anchor='w')        # Left-aligned with padding

        tk.Label(                                   # Helper text showing where to get a key
            dialog,
            text="Get a free key at: haveibeenpwned.com/API/Key",  # Where to get the key
            font=self.theme.font(size=FONT_SIZE_XS),               # Smaller font for helper text
            bg=self.theme.bg_primary,                              # Match dialog background
            fg=self.theme.text_muted                               # Muted color for secondary info
        ).pack(padx=20, pady=(0, 8), anchor='w')    # Left-aligned below instruction

        var = tk.StringVar(                         # String variable bound to the entry field
            value=self.db.get_setting('hibp_api_key', '')  # Pre-fill with current saved key
        )

        entry = tk.Entry(                           # Text entry field for the API key
            dialog,
            textvariable=var,                       # Bound to the string variable above
            font=self.theme.font(size=FONT_SIZE_SM, mono=True),  # Monospace for key readability
            bg=self.theme.bg_tertiary,              # Slightly lighter background for input field
            fg=self.theme.text_primary,             # Primary text color
            insertbackground=self.theme.text_primary,   # Cursor color matches text
            relief='flat',                          # No border style
            width=40                                # Wide enough for a typical HIBP key
        )
        entry.pack(fill='x', padx=20, pady=4)      # Full width with side padding
        entry.focus_set()                           # Put cursor in field immediately on open

        def save():
            """Saves the API key to the database and updates the status label."""
            key = var.get().strip()                         # Get trimmed key value
            self.db.set_setting('hibp_api_key', key)        # Save to database
            status = "Set" if key else "Not set"            # Determine new status text
            color = COLOR_SAFE if key else self.theme.text_muted   # Green if set, muted if not
            self.hibp_key_status.configure(text=status, fg=color)  # Update status label in settings
            dialog.destroy()                                # Close the dialog

        tk.Button(                                  # Save button
            dialog,
            text="Save",                            # Button label
            font=self.theme.font(size=FONT_SIZE_SM, bold=True),  # Bold small font
            bg=self.theme.accent,                   # Accent color for primary action
            fg=self.theme.bg_primary,               # Dark text on accent background
            relief='flat',                          # No border
            padx=16, pady=4,                        # Internal padding
            cursor="hand2",                         # Hand cursor on hover
            command=save                            # Call save function on click
        ).pack(pady=12)                             # Vertical padding below entry field

        dialog.bind('<Return>', lambda e: save())   # Enter key triggers save


    def _change_scan_profile(self):
        """Opens a dialog to change the default scan profile."""
        dialog = tk.Toplevel(self.parent)
        dialog.title("Scan Profile")
        dialog.configure(bg=self.theme.bg_primary)
        dialog.resizable(False, False)
        dialog.geometry("360x200")
        dialog.grab_set()                           # Block main window while dialog is open

        tk.Label(dialog, text="Default scan profile:",
                 font=self.theme.font(size=FONT_SIZE_SM),
                 bg=self.theme.bg_primary,
                 fg=self.theme.text_primary).pack(padx=20, pady=(20, 8), anchor='w')

        var = tk.StringVar(value=self.db.get_setting('scan_profile', 'quick'))

        for key, info in SCAN_PROFILES.items():     # One radio button per scan profile
            tk.Radiobutton(
                dialog, text=f"{info['label']} — {info['duration']}",
                variable=var, value=key,
                font=self.theme.font(size=FONT_SIZE_SM),
                bg=self.theme.bg_primary, fg=self.theme.text_primary,
                selectcolor=self.theme.bg_tertiary,
                activebackground=self.theme.bg_primary
            ).pack(anchor='w', padx=20, pady=2)

        def save():
            self.db.set_setting('scan_profile', var.get())  # Persist selection to database
            dialog.destroy()

        tk.Button(dialog, text="Save",
                  font=self.theme.font(size=FONT_SIZE_SM, bold=True),
                  bg=self.theme.accent, fg=self.theme.bg_primary,
                  relief='flat', padx=16, pady=4,
                  cursor="hand2", command=save).pack(pady=12)


    def update(self, scan_results):
        """Called after a scan completes to refresh the report history panel."""
        self.last_scan_results = scan_results   # Store for potential export use
        self._refresh_report_history()          # Refresh report list in case new report was saved


    def _panel(self, parent, title):
        """Creates a standard titled panel container used throughout this tab."""
        outer = tk.Frame(parent, bg=self.theme.bg_secondary)
        outer.pack(fill='x', pady=(0, 8))
        tk.Label(outer, text=title,
                 font=self.theme.font(size=FONT_SIZE_XS),
                 bg=self.theme.bg_secondary,
                 fg=self.theme.text_muted).pack(
            anchor='w', padx=PADDING_MD, pady=(PADDING_MD, 4))
        tk.Frame(outer, bg=self.theme.border, height=1).pack(fill='x')  # Divider under panel title
        return outer


    def _apply_theme(self):
        """Called by theme manager when the user switches dark/light mode."""
        self.canvas.configure(bg=self.theme.bg_primary)    # Update canvas background
        self.inner.configure(bg=self.theme.bg_primary)     # Update inner frame background
