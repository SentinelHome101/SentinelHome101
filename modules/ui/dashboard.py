"""
=============================================================
  SENTINELHOME101 — Dashboard Tab
  File: modules/ui/dashboard.py

  The first tab the user sees. Shows:
  - Five stat cards (critical, warnings, devices, checks, score)
  - Prioritized findings feed with Fix This buttons
  - Network score gauge (canvas-drawn circular arc)
  - Ransomware canary status panel
  - Last scan summary and Run Scan button
=============================================================
"""

import tkinter as tk
from tkinter import ttk
import math
from modules.constants import *
from modules.theme import ThemeManager


class DashboardTab:
    """
    Builds and manages the Dashboard tab content.

    The dashboard is the home screen — it gives the user
    a complete picture of their security posture at a glance
    without needing to click into any specific tab.
    """

    def __init__(self, parent, theme, db, run_scan_callback):
        """
        Initializes the Dashboard tab.

        Parameters:
            parent           : The parent Frame this tab lives inside.
            theme            : ThemeManager instance for colors/fonts.
            db               : Database instance for reading scan data.
            run_scan_callback: Function to call when Run Scan is clicked.
        """
        self.parent = parent
        self.theme = theme
        self.db = db
        self.run_scan_callback = run_scan_callback

        # Current scan data (populated after a scan runs)
        self.current_findings = []
        self.current_score = 100
        self.current_stats = {
            'critical': 0,
            'warnings': 0,
            'devices': 0,
            'checks': 0,
            'score': 100
        }

        # Build the UI
        self._build()

        # Register for theme updates
        self.theme.register(self._apply_theme)

        # Load last scan data if available
        self._load_last_scan()


    def _build(self):
        """Builds the complete dashboard layout."""

        # --- Outer scrollable container ---
        # The dashboard can have a lot of content so we make it scrollable
        self.canvas = tk.Canvas(
            self.parent,
            bg=self.theme.bg_primary,
            highlightthickness=0        # No border around canvas
        )
        self.scrollbar = tk.Scrollbar(
            self.parent,
            orient='vertical',
            command=self.canvas.yview   # Link scrollbar to canvas
        )
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)

        # Inner frame that holds all content
        self.inner = tk.Frame(self.canvas, bg=self.theme.bg_primary)
        self.canvas_window = self.canvas.create_window(
            (0, 0), window=self.inner, anchor='nw'
        )

        # Update scroll region when content changes size
        self.inner.bind('<Configure>', self._on_frame_configure)
        self.canvas.bind('<Configure>', self._on_canvas_configure)

        # Mouse wheel scrolling
        self.canvas.bind('<Map>', lambda e: self.canvas.bind_all('<MouseWheel>', self._on_mousewheel))
        self.canvas.bind('<Enter>', lambda e: self.canvas.bind_all('<MouseWheel>', self._on_mousewheel))
        self.canvas.bind('<Leave>', lambda e: self.canvas.unbind_all('<MouseWheel>'))

        # Build all sections with padding
        pad = PADDING_LG
        self._build_stat_cards(pad)
        self._build_main_content(pad)


    def _build_stat_cards(self, pad):
        """
        Builds the five stat cards at the top of the dashboard.

        Cards: Critical | Warnings | Devices | Checks Run | Score
        """
        card_row = tk.Frame(self.inner, bg=self.theme.bg_primary)
        card_row.pack(fill='x', padx=pad, pady=(pad, 0))

        self.stat_cards = {}

        # Card definitions: (key, label, default_value, color)
        cards = [
            ('critical', 'Critical',   '0',   COLOR_CRITICAL),
            ('warnings', 'Warnings',   '0',   COLOR_WARNING),
            ('devices',  'Devices',    '0',   self.theme.text_primary),
            ('checks',   'Checks Run', '0',   self.theme.text_primary),
            ('score',    'Score',      '100', COLOR_WARNING),
        ]

        for i, (key, label, default, color) in enumerate(cards):
            # Card frame
            card = tk.Frame(
                card_row,
                bg=self.theme.bg_secondary,
                relief='flat',
                padx=PADDING_MD,
                pady=PADDING_MD
            )
            card.grid(row=0, column=i, padx=(0, 8) if i < 4 else 0, sticky='ew')
            card_row.columnconfigure(i, weight=1)

            # Number label
            num_lbl = tk.Label(
                card,
                text=default,
                font=self.theme.font(size=FONT_SIZE_3XL, bold=True),
                bg=self.theme.bg_secondary,
                fg=color
            )
            num_lbl.pack(anchor='w')

            # Text label
            txt_lbl = tk.Label(
                card,
                text=label.upper(),
                font=self.theme.font(size=FONT_SIZE_XS),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_muted
            )
            txt_lbl.pack(anchor='w')

            # Store references for updating
            self.stat_cards[key] = {
                'frame': card,
                'num': num_lbl,
                'txt': txt_lbl,
                'color': color
            }


    def _build_main_content(self, pad):
        """
        Builds the two-column main content area.

        Left column (wider): Findings feed
        Right column: Score gauge + canary status + last scan info
        """
        content_row = tk.Frame(self.inner, bg=self.theme.bg_primary)
        content_row.pack(fill='both', expand=True, padx=pad, pady=pad)

        # Left column — findings feed (takes 60% of width)
        left_col = tk.Frame(content_row, bg=self.theme.bg_primary)
        left_col.pack(side='left', fill='both', expand=True, padx=(0, 8))

        # Right column — score + status panels (takes 40%)
        right_col = tk.Frame(content_row, bg=self.theme.bg_primary, width=300)
        right_col.pack(side='right', fill='y')
        right_col.pack_propagate(False)

        self._build_findings_feed(left_col)
        self._build_score_panel(right_col)
        self._build_canary_panel(right_col)
        self._build_last_scan_panel(right_col)


    def _build_findings_feed(self, parent):
        """
        Builds the prioritized findings feed.

        Shows all current findings ordered by severity,
        each with a Fix This button that opens guidance.
        """
        # Panel frame
        panel = tk.Frame(
            parent,
            bg=self.theme.bg_secondary,
            relief='flat'
        )
        panel.pack(fill='both', expand=True)

        # Panel header
        header = tk.Frame(panel, bg=self.theme.bg_secondary)
        header.pack(fill='x', padx=PADDING_MD, pady=(PADDING_MD, 8))

        tk.Label(
            header,
            text="FINDINGS FEED",
            font=self.theme.font(size=FONT_SIZE_XS),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_muted
        ).pack(side='left')

        tk.Label(
            header,
            text="Most critical first",
            font=self.theme.font(size=FONT_SIZE_XS),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_muted
        ).pack(side='right')

        # Divider line
        tk.Frame(panel, bg=self.theme.border, height=1).pack(fill='x')

        # Scrollable findings area
        self.findings_frame = tk.Frame(panel, bg=self.theme.bg_secondary)
        self.findings_frame.pack(fill='both', expand=True, padx=2)

        # Default empty state message
        self.empty_label = tk.Label(
            self.findings_frame,
            text="No scan data yet.\nRun a scan to see your security findings.",
            font=self.theme.font(size=FONT_SIZE_MD),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_muted,
            justify='center'
        )
        self.empty_label.pack(expand=True, pady=40)


    def _build_score_panel(self, parent):
        """
        Builds the circular score gauge panel.

        Draws a circular arc using Tkinter Canvas.
        The arc fills based on the score (0=red arc, 100=full green).
        """
        panel = tk.Frame(
            parent,
            bg=self.theme.bg_secondary,
            relief='flat'
        )
        panel.pack(fill='x', pady=(0, 8))

        tk.Label(
            panel,
            text="NETWORK SCORE",
            font=self.theme.font(size=FONT_SIZE_XS),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_muted
        ).pack(padx=PADDING_MD, pady=(PADDING_MD, 4), anchor='w')

        tk.Frame(panel, bg=self.theme.border, height=1).pack(fill='x')

        # Canvas for the gauge arc
        gauge_size = 130
        self.gauge_canvas = tk.Canvas(
            panel,
            width=gauge_size,
            height=gauge_size,
            bg=self.theme.bg_secondary,
            highlightthickness=0
        )
        self.gauge_canvas.pack(pady=PADDING_MD)

        # Score number on top of gauge
        self.score_text_id = None
        self.score_label_id = None

        # Draw initial gauge
        self._draw_gauge(100)

        # Score interpretation
        self.score_desc = tk.Label(
            panel,
            text="No scan data",
            font=self.theme.font(size=FONT_SIZE_SM),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_muted
        )
        self.score_desc.pack(pady=(0, PADDING_MD))


    def _draw_gauge(self, score):
        """
        Draws the circular score gauge on the canvas.

        Parameters:
            score (int): The score value 0-100 to display.
        """
        self.gauge_canvas.delete('all')     # Clear previous drawing

        size = 130
        cx, cy = size // 2, size // 2      # Center point
        r = 52                              # Radius of arc
        lw = 10                             # Line width of arc

        # Background arc (grey track)
        self.gauge_canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=135,                      # Start at 135 degrees
            extent=270,                     # Sweep 270 degrees
            style='arc',
            outline=self.theme.bg_tertiary,
            width=lw
        )

        # Score arc color based on value
        if score >= 80:
            arc_color = COLOR_SAFE          # Green — good
        elif score >= 50:
            arc_color = COLOR_WARNING       # Amber — fair
        else:
            arc_color = COLOR_CRITICAL      # Red — poor

        # Filled arc proportional to score
        extent = (score / 100) * 270        # Scale score to degrees
        if extent > 0:
            self.gauge_canvas.create_arc(
                cx - r, cy - r, cx + r, cy + r,
                start=135,
                extent=extent,
                style='arc',
                outline=arc_color,
                width=lw
            )

        # Score number in center
        self.gauge_canvas.create_text(
            cx, cy - 8,
            text=str(score),
            font=(FONT_UI, FONT_SIZE_HUGE, 'bold'),
            fill=arc_color
        )

        # "/ 100" label below score
        self.gauge_canvas.create_text(
            cx, cy + 18,
            text="/ 100",
            font=(FONT_UI, FONT_SIZE_SM),
            fill=self.theme.text_muted
        )


    def _build_canary_panel(self, parent):
        """
        Builds the ransomware canary file status panel.

        Shows whether canary files are intact or have been tampered.
        """
        panel = tk.Frame(
            parent,
            bg=self.theme.bg_secondary,
            relief='flat'
        )
        panel.pack(fill='x', pady=(0, 8))

        tk.Label(
            panel,
            text="RANSOMWARE CANARY",
            font=self.theme.font(size=FONT_SIZE_XS),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_muted
        ).pack(padx=PADDING_MD, pady=(PADDING_MD, 4), anchor='w')

        tk.Frame(panel, bg=self.theme.border, height=1).pack(fill='x')

        self.canary_frame = tk.Frame(panel, bg=self.theme.bg_secondary)
        self.canary_frame.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)

        # Default status
        self.canary_status_label = tk.Label(
            self.canary_frame,
            text="● Canary files not yet planted",
            font=self.theme.font(size=FONT_SIZE_SM),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_muted
        )
        self.canary_status_label.pack(anchor='w')


    def _build_last_scan_panel(self, parent):
        """
        Builds the last scan info panel with Run Scan button.
        """
        panel = tk.Frame(
            parent,
            bg=self.theme.bg_secondary,
            relief='flat'
        )
        panel.pack(fill='x')

        tk.Label(
            panel,
            text="LAST SCAN",
            font=self.theme.font(size=FONT_SIZE_XS),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_muted
        ).pack(padx=PADDING_MD, pady=(PADDING_MD, 4), anchor='w')

        tk.Frame(panel, bg=self.theme.border, height=1).pack(fill='x')

        inner = tk.Frame(panel, bg=self.theme.bg_secondary)
        inner.pack(fill='x', padx=PADDING_MD, pady=PADDING_MD)

        self.last_scan_label = tk.Label(
            inner,
            text="No scans run yet",
            font=self.theme.font(size=FONT_SIZE_SM),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_muted
        )
        self.last_scan_label.pack(anchor='w', pady=(0, 8))

        # Run Scan button
        tk.Button(
            inner,
            text="Run Scan",
            font=self.theme.font(size=FONT_SIZE_SM, bold=True),
            bg=self.theme.accent,
            fg=self.theme.bg_primary,
            relief='flat',
            padx=12, pady=6,
            cursor="hand2",
            command=self.run_scan_callback
        ).pack(fill='x')


    def update(self, scan_results):
        """
        Updates the dashboard with new scan results.

        Called after a scan completes. Updates all panels
        with the latest data.

        Parameters:
            scan_results (dict): Contains keys:
                - findings   : list of finding dicts
                - score      : int 0-100
                - stats      : dict with critical/warnings/devices/checks
                - scan_info  : dict with date/type/duration
                - canary     : list of canary file statuses
        """
        findings = scan_results.get('findings', [])
        score = scan_results.get('score', 100)
        stats = scan_results.get('stats', {})
        scan_info = scan_results.get('scan_info', {})
        canary = scan_results.get('canary', [])

        # Store current data
        self.current_findings = findings
        self.current_score = score
        self.current_stats = stats

        # Update stat cards
        self._update_stat_cards(stats, score)

        # Update score gauge
        self._draw_gauge(score)
        self._update_score_description(score)

        # Update findings feed
        self._update_findings_feed(findings)

        # Update canary status
        self._update_canary_status(canary)

        # Update last scan info
        self._update_last_scan_info(scan_info)


    def _update_stat_cards(self, stats, score):
        """Updates the five stat card values."""
        updates = {
            'critical': (str(stats.get('critical', 0)), COLOR_CRITICAL),
            'warnings': (str(stats.get('warnings', 0)), COLOR_WARNING),
            'devices':  (str(stats.get('devices', 0)),  self.theme.text_primary),
            'checks':   (str(stats.get('checks', 101)), self.theme.text_primary),
            'score':    (str(score), self._score_color(score)),
        }

        for key, (value, color) in updates.items():
            if key in self.stat_cards:
                self.stat_cards[key]['num'].configure(text=value, fg=color)


    def _score_color(self, score):
        """Returns the appropriate color for a given score."""
        if score >= 80:
            return COLOR_SAFE
        elif score >= 50:
            return COLOR_WARNING
        else:
            return COLOR_CRITICAL


    def _update_score_description(self, score):
        """Updates the score interpretation text."""
        if score >= 80:
            desc = "Good — minor issues only"
            color = COLOR_SAFE
        elif score >= 60:
            desc = "Fair — some issues need attention"
            color = COLOR_WARNING
        elif score >= 40:
            desc = "Poor — significant issues found"
            color = COLOR_WARNING
        else:
            desc = "Critical — immediate action needed"
            color = COLOR_CRITICAL

        self.score_desc.configure(text=desc, fg=color)


    def _update_findings_feed(self, findings):
        """
        Rebuilds the findings feed with current findings.

        Each finding gets a color-coded severity badge,
        a title, detail text, and a Fix This button.
        """
        # Clear existing findings
        for widget in self.findings_frame.winfo_children():
            widget.destroy()

        if not findings:
            # Show empty state
            tk.Label(
                self.findings_frame,
                text="No findings to show.\nRun a scan to see your security status.",
                font=self.theme.font(size=FONT_SIZE_MD),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_muted,
                justify='center'
            ).pack(expand=True, pady=40)
            return

        # Show each finding
        for i, finding in enumerate(findings[:15]):  # Show max 15 on dashboard
            self._build_finding_row(finding, i)


    def _build_finding_row(self, finding, index):
        """
        Builds a single finding row in the findings feed.

        Parameters:
            finding (dict): The finding data.
            index   (int) : Row index for alternating backgrounds.
        """
        severity = finding.get('severity', 'info')
        title = finding.get('title', 'Unknown finding')
        detail = finding.get('detail', '')
        remediation = finding.get('remediation', '')

        # Severity colors
        sev_color = self.theme.severity_color(severity)
        sev_bg = self.theme.severity_bg(severity)

        # Row frame
        row = tk.Frame(
            self.findings_frame,
            bg=self.theme.bg_secondary
        )
        row.pack(fill='x', pady=1)

        # Left colored bar (severity indicator)
        bar = tk.Frame(row, bg=sev_color, width=3)
        bar.pack(side='left', fill='y')

        # Content area
        content = tk.Frame(row, bg=self.theme.bg_secondary, padx=10, pady=8)
        content.pack(side='left', fill='both', expand=True)

        # Top row: badge + title
        top = tk.Frame(content, bg=self.theme.bg_secondary)
        top.pack(fill='x')

        # Severity badge
        badge = tk.Label(
            top,
            text=severity.upper(),
            font=self.theme.font(size=FONT_SIZE_XS, bold=True),
            bg=sev_bg,
            fg=sev_color,
            padx=5, pady=1
        )
        badge.pack(side='left', padx=(0, 8))

        # Finding title
        tk.Label(
            top,
            text=title,
            font=self.theme.font(size=FONT_SIZE_SM, bold=True),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_primary,
            anchor='w'
        ).pack(side='left', fill='x', expand=True)

        # Detail text (if provided)
        if detail:
            tk.Label(
                content,
                text=detail,
                font=self.theme.font(size=FONT_SIZE_XS),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_secondary,
                anchor='w',
                wraplength=400,
                justify='left'
            ).pack(fill='x', pady=(2, 0))

        # Fix This button (if remediation provided)
        if remediation:
            tk.Button(
                content,
                text="How to fix this →",
                font=self.theme.font(size=FONT_SIZE_XS),
                bg=self.theme.bg_secondary,
                fg=sev_color,
                relief='flat',
                cursor="hand2",
                command=lambda r=remediation, t=title: self._show_remediation(t, r)
            ).pack(anchor='w', pady=(4, 0))

        # Separator line between findings
        tk.Frame(
            self.findings_frame,
            bg=self.theme.border_light,
            height=1
        ).pack(fill='x')


    def _show_remediation(self, title, remediation):
        """
        Shows a remediation guidance popup for a finding.

        Parameters:
            title       (str): The finding title.
            remediation (str): Plain-English fix instructions.
        """
        import tkinter.messagebox as mb

        # Simple dialog for now — Phase 3 will have a nicer popup
        mb.showinfo(
            f"How to Fix: {title}",
            remediation,
            parent=self.parent
        )


    def _update_canary_status(self, canary_files):
        """Updates the canary file status display."""
        for widget in self.canary_frame.winfo_children():
            widget.destroy()

        if not canary_files:
            tk.Label(
                self.canary_frame,
                text="● Canary files not yet planted",
                font=self.theme.font(size=FONT_SIZE_SM),
                bg=self.theme.bg_secondary,
                fg=self.theme.text_muted
            ).pack(anchor='w')
            return

        # Check overall status
        all_intact = all(f.get('status') == 'intact' for f in canary_files)

        status_text = "● All canary files intact" if all_intact else "⚠ Canary file tampering detected!"
        status_color = COLOR_SAFE if all_intact else COLOR_CRITICAL

        tk.Label(
            self.canary_frame,
            text=status_text,
            font=self.theme.font(size=FONT_SIZE_SM, bold=True),
            bg=self.theme.bg_secondary,
            fg=status_color
        ).pack(anchor='w', pady=(0, 4))

        # Individual file statuses
        for f in canary_files:
            status = f.get('status', 'unknown')
            path = f.get('file_path', '')
            color = COLOR_SAFE if status == 'intact' else COLOR_CRITICAL
            short_path = path.split('\\')[-2] + '\\...' if '\\' in path else path

            tk.Label(
                self.canary_frame,
                text=f"  {short_path}  [{status}]",
                font=self.theme.font(size=FONT_SIZE_XS, mono=True),
                bg=self.theme.bg_secondary,
                fg=color
            ).pack(anchor='w')


    def _update_last_scan_info(self, scan_info):
        """Updates the last scan information text."""
        if not scan_info:
            self.last_scan_label.configure(text="No scans run yet")
            return

        scan_date = scan_info.get('scan_date', '')
        scan_type = scan_info.get('scan_type', '')
        duration = scan_info.get('duration_secs', 0)

        # Format the date nicely
        try:
            import datetime
            dt = datetime.datetime.fromisoformat(scan_date)
            date_str = dt.strftime("%b %d at %I:%M %p")
        except Exception:
            date_str = scan_date

        # Format duration
        if duration >= 60:
            dur_str = f"{duration // 60}m {duration % 60}s"
        else:
            dur_str = f"{duration}s"

        text = f"{date_str}\n{scan_type.title()} scan · {dur_str}"
        self.last_scan_label.configure(text=text, fg=self.theme.text_secondary)


    def _load_last_scan(self):
        """Loads the most recent scan from database on startup."""
        try:
            last = self.db.get_last_scan()
            if last:
                findings = self.db.get_findings_for_scan(last['id'])
                critical = sum(1 for f in findings if f['severity'] == 'critical')
                warnings = sum(1 for f in findings if f['severity'] == 'warning')

                self.update({
                    'findings': findings,
                    'score': last.get('score', 100),
                    'stats': {
                        'critical': critical,
                        'warnings': warnings,
                        'devices': last.get('devices_found', 0),
                        'checks': 101,
                    },
                    'scan_info': last,
                    'canary': self.db.get_canary_files()
                })
        except Exception:
            pass    # No scan data yet — show defaults


    def _on_frame_configure(self, event):
        """Updates scroll region when inner frame changes size."""
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))


    def _on_canvas_configure(self, event):
        """Makes inner frame match canvas width."""
        self.canvas.itemconfig(self.canvas_window, width=event.width)


    def _on_mousewheel(self, event):
        """Handles mouse wheel scrolling."""
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')


    def _apply_theme(self):
        """Updates all colors when theme changes."""
        self.canvas.configure(bg=self.theme.bg_primary)
        self.inner.configure(bg=self.theme.bg_primary)
        self._draw_gauge(self.current_score)
