"""
=============================================================
  SENTINELHOME101 — Main Application Class
  File: modules/app.py

  This is the heart of the application. It creates:
  - The main Tkinter window
  - The left icon sidebar for navigation
  - The six tab content areas
  - The persistent status bar at the bottom
  - The first-run disclosure screen (if needed)

  All other modules are imported and managed from here.
=============================================================
"""

# --- Standard library imports ---
import tkinter as tk                        # The main GUI framework
from tkinter import ttk, messagebox         # Themed widgets and dialogs
import os                                   # File path operations
import threading                            # For running scans in background
import datetime                             # For timestamps

# --- Our modules ---
from modules.constants import *             # All colors, fonts, sizes
from modules.database import Database       # Data persistence
from modules.theme import ThemeManager      # Dark/light mode management

# --- UI tab modules ---
from modules.ui.dashboard import DashboardTab
from modules.ui.host_tab import HostTab
from modules.ui.threat_tab import ThreatTab
from modules.ui.network_tab import NetworkTab
from modules.ui.monitoring_tab import MonitoringTab
from modules.ui.reports_tab import ReportsTab
from modules.scan_coordinator import ScanCoordinator


class SentinelHome101App:
    """
    The main application class for SentinelHome101.

    Creates and manages the entire application window,
    all navigation, and coordinates between the six tabs.

    Usage (from main.py):
        app = SentinelHome101App(app_data_dir)
        app.run()
    """

    def __init__(self, app_data_dir):
        """
        Initializes the application.

        Parameters:
            app_data_dir (str): Path to AppData/Roaming/SentinelHome101/
                                where the database and settings are stored.
        """
        # Store the data directory path
        self.app_data_dir = app_data_dir

        # --- Initialize the database ---
        # This creates the SQLite database file if it does not exist
        self.db = Database(app_data_dir)

        # --- Initialize the theme manager ---
        # Read saved theme preference, default to dark mode
        saved_theme = self.db.get_setting('theme', 'dark')
        is_dark = saved_theme == 'dark'
        self.theme = ThemeManager(is_dark=is_dark)

        # --- Load settings ---
        self.network_name = self.db.get_setting('network_name', 'Home Network')
        self.scan_profile = self.db.get_setting('scan_profile', DEFAULT_SCAN_PROFILE)

        # --- Create the main Tkinter window ---
        self.root = tk.Tk()
        self._configure_window()

        # --- Build the user interface ---
        self._build_ui()

        # --- Check if first run ---
        # If no settings exist, this is a fresh install
        first_run = self.db.get_setting('first_run_complete', 'false')
        if first_run != 'true':
            # Show the first-run disclosure screen
            # This runs after the main window is shown
            self.root.after(100, self._show_first_run_disclosure)

        # --- Initialize scan coordinator ---
        self.scanner = ScanCoordinator(
            db=self.db,
            app_data_dir=app_data_dir,
            progress_callback=self._on_scan_progress,
            complete_callback=self._on_scan_complete,
            status_callback=self.update_status
        )

        # --- Register window close handler ---
        # This saves window position before closing
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)


    def _configure_window(self):
        """
        Configures the main application window properties.

        Sets the title, size, position, minimum size,
        background color, and window icon.
        """
        # Set the window title
        self.root.title(f"{APP_NAME} v{APP_VERSION}")

        # Load saved window position and size from database
        state = self.db.get_window_state()

        # Apply the saved geometry (position and size)
        # Format is "WIDTHxHEIGHT+X+Y"
        self.root.geometry(
            f"{state['width']}x{state['height']}+{state['x']}+{state['y']}"
        )

        # Set minimum window dimensions
        # The app layout breaks below these sizes
        self.root.minsize(MIN_WIDTH, MIN_HEIGHT)

        # Set the background color to match the theme
        self.root.configure(bg=self.theme.bg_primary)

        # Try to set the window icon
        # The .ico file will be created during Phase 3 (packaging)
        icon_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'assets', 'icon.ico'
        )
        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)     # Set the taskbar icon
            except Exception:
                pass    # Ignore if icon file is missing or corrupt

        # Remove the default Tkinter title bar tearoff on Windows
        # and configure the overall look
        self.root.option_add('*tearOff', False)     # Disable menu tearoff


    def _build_ui(self):
        """
        Builds the complete user interface.

        Layout structure:
        ┌─────────────────────────────────────────┐
        │  [Sidebar 52px] [Content Area — flex]   │
        ├─────────────────────────────────────────┤
        │  [Status Bar — full width]              │
        └─────────────────────────────────────────┘
        """
        # --- Main container frame ---
        # Fills the entire window
        self.main_frame = tk.Frame(
            self.root,
            bg=self.theme.bg_primary
        )
        self.main_frame.pack(fill='both', expand=True)  # Fill all available space

        # --- Left sidebar ---
        self._build_sidebar()

        # --- Content area ---
        # Takes up all space to the right of the sidebar
        self.content_frame = tk.Frame(
            self.main_frame,
            bg=self.theme.bg_primary
        )
        self.content_frame.pack(
            side='left',        # To the right of the sidebar
            fill='both',        # Fill all remaining space
            expand=True         # Expand to take available space
        )

        # --- Build all six tab panels ---
        self._build_tabs()

        # --- Status bar at the bottom ---
        self._build_status_bar()

        # --- Show the default tab (Dashboard) ---
        self._show_tab(TAB_DASHBOARD)


    def _build_sidebar(self):
        """
        Builds the left icon navigation sidebar.

        The sidebar is a narrow strip (52px wide) containing
        one icon button per tab. Clicking a button switches
        to that tab. The active tab button is highlighted.

        Tooltip labels appear when hovering over each button.
        """
        # --- Sidebar container ---
        self.sidebar = tk.Frame(
            self.main_frame,
            bg=self.theme.bg_sidebar,
            width=SIDEBAR_WIDTH         # Fixed width — does not resize
        )
        self.sidebar.pack(side='left', fill='y')    # Fill full height
        self.sidebar.pack_propagate(False)          # Prevent width from shrinking

        # --- Right border line on sidebar ---
        sidebar_border = tk.Frame(
            self.sidebar,
            bg=self.theme.border,
            width=1                     # 1px border line
        )
        sidebar_border.pack(side='right', fill='y')

        # --- Tab button storage ---
        self.sidebar_buttons = {}       # Maps tab_id -> button widget
        self._active_tab = None         # Currently active tab ID

        # --- Unicode icons for each tab ---
        # Using Unicode characters since we cannot load image files
        # in this phase (icon images come in Phase 3)
        tab_icons = {
            TAB_DASHBOARD:  "⊞",        # Grid/dashboard icon
            TAB_HOST:       "⊡",        # Computer/device icon
            TAB_THREAT:     "⚠",        # Warning/threat icon
            TAB_NETWORK:    "⊙",        # Network/circle icon
            TAB_MONITORING: "⊘",        # Chart/monitoring icon
            TAB_REPORTS:    "≡",        # Settings/menu icon
        }

        # --- Create a button for each tab ---
        for tab_id in TAB_ORDER:
            btn_frame = tk.Frame(
                self.sidebar,
                bg=self.theme.bg_sidebar,
                height=44,
                width=SIDEBAR_WIDTH - 1
            )
            btn_frame.pack(pady=2)
            btn_frame.pack_propagate(False)

            btn = tk.Label(
                btn_frame,
                text=tab_icons.get(tab_id, "?"),
                font=(FONT_UI, 18),
                bg=self.theme.bg_sidebar,
                fg=self.theme.text_secondary,
                cursor="hand2",
                width=3
            )
            btn.pack(expand=True, fill='both')

            # --- Click handler ---
            btn.bind('<Button-1>', lambda e, t=tab_id: self._show_tab(t))

            # --- Combined Enter/Leave: hover highlight + tooltip ---
            # All bindings for <Enter> and <Leave> are set here in one place
            # so nothing overwrites anything else.
            self._bind_sidebar_button(btn, tab_id, TAB_LABELS.get(tab_id, tab_id))

            self.sidebar_buttons[tab_id] = btn

        self.theme.register(self._update_sidebar_theme)


    def _bind_sidebar_button(self, widget, tab_id, tooltip_text):
        """
        Binds hover highlight and tooltip to a sidebar button in one place.
        Keeping all <Enter> and <Leave> bindings here prevents any one
        bind() call from overwriting another.
        """
        tooltip = None
        after_id = None

        def on_enter(event):
            nonlocal after_id
            # Hover highlight
            if tab_id != self._active_tab:
                widget.configure(bg=self.theme.bg_tertiary, fg=self.theme.text_primary)
            # Schedule tooltip
            after_id = widget.after(600, _show_tooltip)

        def on_leave(event):
            nonlocal tooltip, after_id
            # Restore hover highlight
            if tab_id != self._active_tab:
                widget.configure(bg=self.theme.bg_sidebar, fg=self.theme.text_secondary)
            # Cancel pending tooltip
            if after_id is not None:
                widget.after_cancel(after_id)
                after_id = None
            # Destroy tooltip if visible
            if tooltip is not None:
                tooltip.destroy()
                tooltip = None

        def _show_tooltip():
            nonlocal tooltip, after_id
            after_id = None
            if not widget.winfo_exists():
                return
            tooltip = tk.Toplevel(widget)
            tooltip.wm_overrideredirect(True)
            x = widget.winfo_rootx() + SIDEBAR_WIDTH + 4
            y = widget.winfo_rooty() + widget.winfo_height() // 2 - 10
            tooltip.wm_geometry(f"+{x}+{y}")
            tk.Label(
                tooltip,
                text=tooltip_text,
                font=self.theme.font(size=FONT_SIZE_SM),
                bg=self.theme.bg_tertiary,
                fg=self.theme.text_primary,
                padx=8, pady=4,
                relief='flat'
            ).pack()

        widget.bind('<Enter>', on_enter)
        widget.bind('<Leave>', on_leave)


    def _sidebar_hover(self, button, tab_id, hovering):
        """
        Handles hover visual feedback on sidebar buttons.

        Parameters:
            button  : The Label widget being hovered.
            tab_id  : Which tab this button belongs to.
            hovering: True when mouse enters, False when it leaves.
        """
        # Do not change the active tab's appearance on hover
        if tab_id == self._active_tab:
            return

        if hovering:
            button.configure(
                bg=self.theme.bg_tertiary,      # Slightly lighter on hover
                fg=self.theme.text_primary       # Full brightness text
            )
        else:
            button.configure(
                bg=self.theme.bg_sidebar,        # Back to sidebar color
                fg=self.theme.text_secondary     # Back to dimmed text
            )


    def _add_tooltip(self, widget, text):
        """
        Adds a hover tooltip to a widget.

        Fix: track the pending after() call ID so it can be cancelled
        if the mouse leaves before the 500ms delay fires. Button-1 is
        NOT bound here — clicking is handled separately by the sidebar
        button bindings so tabs remain clickable.
        """
        tooltip = None
        after_id = None

        def show_tooltip():
            nonlocal tooltip, after_id
            after_id = None
            if not widget.winfo_exists():
                return
            tooltip = tk.Toplevel(widget)
            tooltip.wm_overrideredirect(True)

            x = widget.winfo_rootx() + SIDEBAR_WIDTH + 4
            y = widget.winfo_rooty() + widget.winfo_height() // 2 - 10
            tooltip.wm_geometry(f"+{x}+{y}")

            tk.Label(
                tooltip,
                text=text,
                font=self.theme.font(size=FONT_SIZE_SM),
                bg=self.theme.bg_tertiary,
                fg=self.theme.text_primary,
                padx=8, pady=4,
                relief='flat'
            ).pack()

        def on_enter(event):
            nonlocal after_id
            after_id = widget.after(500, show_tooltip)

        def on_leave(event):
            nonlocal tooltip, after_id
            # Cancel pending show if mouse left before delay fired
            if after_id is not None:
                widget.after_cancel(after_id)
                after_id = None
            # Destroy tooltip if currently visible
            if tooltip is not None:
                tooltip.destroy()
                tooltip = None

        widget.bind('<Enter>', on_enter)
        widget.bind('<Leave>', on_leave)


    def _build_tabs(self):
        """
        Creates the six tab content areas.
        Dashboard and Host tabs are fully implemented.
        Remaining tabs show status panels pending Phase 3.
        """
        self.tab_frames = {}
        self.tab_objects = {}   # Stores actual tab class instances

        for tab_id in TAB_ORDER:
            frame = tk.Frame(self.content_frame, bg=self.theme.bg_primary)
            self.tab_frames[tab_id] = frame

        # --- Dashboard tab ---
        self.tab_objects[TAB_DASHBOARD] = DashboardTab(
            parent=self.tab_frames[TAB_DASHBOARD],
            theme=self.theme,
            db=self.db,
            run_scan_callback=self._run_scan
        )

        # --- Host security tab ---
        self.tab_objects[TAB_HOST] = HostTab(
            parent=self.tab_frames[TAB_HOST],
            theme=self.theme,
            db=self.db,
            status_callback=self.update_status
        )

        # --- Threat detection tab ---
        self.tab_objects[TAB_THREAT] = ThreatTab(
            parent=self.tab_frames[TAB_THREAT],
            theme=self.theme,
            db=self.db,
            status_callback=self.update_status
        )

        # --- Network tab ---
        self.tab_objects[TAB_NETWORK] = NetworkTab(
            parent=self.tab_frames[TAB_NETWORK],
            theme=self.theme,
            db=self.db,
            status_callback=self.update_status,
            run_scan_callback=self._run_scan
        )

        # --- Monitoring tab ---
        self.tab_objects[TAB_MONITORING] = MonitoringTab(
            parent=self.tab_frames[TAB_MONITORING],
            theme=self.theme,
            db=self.db,
            status_callback=self.update_status
        )

        # --- Reports & Settings tab ---
        self.tab_objects[TAB_REPORTS] = ReportsTab(
            parent=self.tab_frames[TAB_REPORTS],
            theme=self.theme,
            db=self.db,
            toggle_theme_callback=self._toggle_theme,
            status_callback=self.update_status
        )


    def _build_placeholder_tab(self, frame, tab_id):
        """
        Builds a placeholder panel for a tab during Phase 1.

        Shows the tab name and a "coming soon" message.
        These will be completely replaced in Phase 2.

        Parameters:
            frame  : The tab's container Frame.
            tab_id : Which tab this placeholder is for.
        """
        # Center everything in the frame
        inner = tk.Frame(frame, bg=self.theme.bg_primary)
        inner.place(relx=0.5, rely=0.5, anchor='center')   # Center in frame

        # Tab name as large header
        tk.Label(
            inner,
            text=TAB_LABELS.get(tab_id, tab_id),
            font=self.theme.font(size=FONT_SIZE_3XL, bold=True),
            bg=self.theme.bg_primary,
            fg=self.theme.accent
        ).pack(pady=(0, 16))

        # Status message
        tk.Label(
            inner,
            text="Full tab content arrives in Phase 3",
            font=self.theme.font(size=FONT_SIZE_MD),
            bg=self.theme.bg_primary,
            fg=self.theme.text_secondary
        ).pack()

        # App version
        tk.Label(
            inner,
            text=f"{APP_NAME} v{APP_VERSION}",
            font=self.theme.font(size=FONT_SIZE_SM, mono=True),
            bg=self.theme.bg_primary,
            fg=self.theme.text_muted
        ).pack(pady=(24, 0))


    def _build_status_bar(self):
        """
        Builds the persistent status bar at the bottom of the window.

        The status bar shows:
        - Left: Current scan status and data privacy indicator
        - Right: Export and Run Scan buttons

        The status bar is always visible regardless of which tab is active.
        """
        # --- Status bar container ---
        self.status_bar = tk.Frame(
            self.root,                      # Attach to root, not content frame
            bg=self.theme.bg_secondary,
            height=36                       # Fixed height
        )
        self.status_bar.pack(
            side='bottom',                  # Always at the bottom
            fill='x'                        # Full width
        )
        self.status_bar.pack_propagate(False)   # Maintain fixed height

        # --- Top border line ---
        border = tk.Frame(
            self.status_bar,
            bg=self.theme.border,
            height=1
        )
        border.pack(side='top', fill='x')

        # --- Left side: status text ---
        left_frame = tk.Frame(self.status_bar, bg=self.theme.bg_secondary)
        left_frame.pack(side='left', padx=PADDING_LG, pady=6)

        # Green dot indicator
        self.status_dot = tk.Label(
            left_frame,
            text="●",
            font=self.theme.font(size=8),
            bg=self.theme.bg_secondary,
            fg=COLOR_SAFE               # Green dot = no data leaving network
        )
        self.status_dot.pack(side='left', padx=(0, 6))

        # Status text label
        self.status_label = tk.Label(
            left_frame,
            text="Ready — No data sent outside local network",
            font=self.theme.font(size=FONT_SIZE_SM),
            bg=self.theme.bg_secondary,
            fg=self.theme.text_secondary
        )
        self.status_label.pack(side='left')

        # --- Right side: action buttons ---
        right_frame = tk.Frame(self.status_bar, bg=self.theme.bg_secondary)
        right_frame.pack(side='right', padx=PADDING_LG, pady=5)

        # Export button
        export_btn = tk.Button(
            right_frame,
            text="Export Report",
            font=self.theme.font(size=FONT_SIZE_SM),
            bg=self.theme.bg_tertiary,
            fg=self.theme.text_secondary,
            relief='flat',
            padx=10, pady=2,
            cursor="hand2",
            command=self._export_report     # Will be implemented in Phase 2
        )
        export_btn.pack(side='left', padx=(0, 8))

        # Run Scan button (primary action)
        self.scan_btn = tk.Button(
            right_frame,
            text="Run Scan",
            font=self.theme.font(size=FONT_SIZE_SM, bold=True),
            bg=self.theme.accent,           # Ghost white — primary action
            fg=self.theme.bg_primary,       # Dark text on white button
            relief='flat',
            padx=10, pady=2,
            cursor="hand2",
            command=self._run_scan          # Will be implemented in Phase 2
        )
        self.scan_btn.pack(side='left')

        # Register status bar for theme updates
        self.theme.register(self._update_status_bar_theme)


    def _show_tab(self, tab_id):
        """
        Switches the visible tab to the specified tab.

        Hides all other tabs, shows the requested one,
        and updates the sidebar button highlighting.

        Parameters:
            tab_id (str): One of the TAB_* constants.
        """
        # --- Hide all tab frames ---
        for tid, frame in self.tab_frames.items():
            frame.pack_forget()     # Remove from layout (but keep in memory)

        # --- Show the requested tab ---
        self.tab_frames[tab_id].pack(
            fill='both',            # Fill all available space
            expand=True             # Expand to take available space
        )

        # --- Update sidebar button highlighting ---
        for tid, btn in self.sidebar_buttons.items():
            if tid == tab_id:
                # Active tab: accent color and bright text
                btn.configure(
                    bg=self.theme.bg_tertiary,  # Slightly highlighted background
                    fg=self.theme.accent         # Ghost white accent color
                )
            else:
                # Inactive tabs: standard sidebar color
                btn.configure(
                    bg=self.theme.bg_sidebar,
                    fg=self.theme.text_secondary
                )

        # Remember the active tab
        self._active_tab = tab_id


    def _show_first_run_disclosure(self):
        """
        Shows the first-run disclosure screen.

        This appears on the very first launch and explains:
        1. What the app does
        2. That it runs locally
        3. The two features that connect externally (opt-in)
        4. Support contact information

        The user must click Accept to proceed.
        Once accepted, this screen never appears again.

        Design fixes applied:
        - Resizable so users at high DPI can expand if needed
        - Scrollable content area so nothing is cut off
        - Accept button pinned OUTSIDE the scroll area so it is
          always visible regardless of window height
        - Window sized to 90% of screen height max so it fits
          on any monitor resolution
        """
        # Create a modal dialog window
        dialog = tk.Toplevel(self.root)
        dialog.title(f"{APP_NAME} — First Run Disclosure")
        dialog.configure(bg=self.theme.bg_primary)
        dialog.resizable(True, True)        # Allow resizing in case DPI clips content

        # Make it modal (blocks interaction with main window)
        dialog.grab_set()
        dialog.transient(self.root)

        # Size to fit screen — use 90% of screen height as max
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        dialog_width  = min(640, int(screen_w * 0.5))
        dialog_height = min(680, int(screen_h * 0.85))
        x = (screen_w - dialog_width)  // 2
        y = (screen_h - dialog_height) // 2
        dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
        dialog.minsize(500, 400)            # Minimum usable size

        # --- OUTER LAYOUT: scrollable top, fixed button bottom ---
        # This ensures the Accept button is ALWAYS visible
        # regardless of window height or content length.

        outer = tk.Frame(dialog, bg=self.theme.bg_primary)
        outer.pack(fill='both', expand=True)

        # --- BOTTOM: Accept button — packed FIRST so it is always visible ---
        # Packing bottom before top ensures button gets space first
        btn_area = tk.Frame(
            outer,
            bg=self.theme.bg_secondary,
            pady=12
        )
        btn_area.pack(side='bottom', fill='x')

        # Separator line above button
        tk.Frame(btn_area, bg=self.theme.border, height=1).pack(
            fill='x', pady=(0, 12)
        )

        def on_accept():
            """Marks first run complete and closes the dialog."""
            self.db.set_setting('first_run_complete', 'true')
            dialog.destroy()

        tk.Button(
            btn_area,
            text="I Understand — Launch SentinelHome101",
            font=self.theme.font(size=FONT_SIZE_MD, bold=True),
            bg=self.theme.accent,
            fg=self.theme.bg_primary,
            relief='flat',
            padx=20, pady=10,
            cursor="hand2",
            command=on_accept
        ).pack(padx=24)

        # --- TOP: Scrollable content area ---
        scroll_canvas = tk.Canvas(
            outer,
            bg=self.theme.bg_primary,
            highlightthickness=0
        )
        scrollbar = tk.Scrollbar(
            outer,
            orient='vertical',
            command=scroll_canvas.yview
        )
        scroll_canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side='right', fill='y')
        scroll_canvas.pack(side='left', fill='both', expand=True)

        # Inner frame inside the canvas
        content = tk.Frame(
            scroll_canvas,
            bg=self.theme.bg_primary,
            padx=28,
            pady=20
        )
        content_window = scroll_canvas.create_window(
            (0, 0), window=content, anchor='nw'
        )

        # Make inner frame match canvas width
        def on_canvas_resize(event):
            scroll_canvas.itemconfig(content_window, width=event.width)
        scroll_canvas.bind('<Configure>', on_canvas_resize)

        # Update scroll region when content changes
        def on_content_resize(event):
            scroll_canvas.configure(scrollregion=scroll_canvas.bbox('all'))
        content.bind('<Configure>', on_content_resize)

        # Mouse wheel scrolling
        def on_mousewheel(event):
            scroll_canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')
        scroll_canvas.bind_all('<MouseWheel>', on_mousewheel)

        # --- App name header ---
        tk.Label(
            content,
            text=APP_NAME,
            font=self.theme.font(size=FONT_SIZE_XL, bold=True),
            bg=self.theme.bg_primary,
            fg=self.theme.accent
        ).pack(anchor='w')

        tk.Label(
            content,
            text=f"Version {APP_VERSION}  ·  First Run Setup",
            font=self.theme.font(size=FONT_SIZE_SM),
            bg=self.theme.bg_primary,
            fg=self.theme.text_muted
        ).pack(anchor='w', pady=(2, 16))

        tk.Frame(content, bg=self.theme.border, height=1).pack(
            fill='x', pady=(0, 16)
        )

        # --- Disclosure sections ---
        sections = [
            ("What this application does",
             f"{APP_NAME} performs 101 security checks on your home network "
             "and computer. It scans for vulnerabilities, identifies connected "
             "devices, monitors for threats, and generates plain-English "
             "security reports."),

            ("Your data stays local",
             "All scans run entirely on this computer. No scan results, "
             "device information, IP addresses, or personal data are sent "
             "to any server or cloud service. Everything stays on your machine."),

            ("Two optional external connections",
             "Two features connect to external services and are DISABLED by "
             "default. You can enable them in Settings at any time:\n\n"
             "  Speed Test — connects to Speedtest.net to measure your "
             "connection speed.\n\n"
             "  Credential Breach Check — sends a hashed (one-way encrypted) "
             "version of your email address to HaveIBeenPwned.com to check "
             "if it appears in known data breaches."),

            ("Support",
             f"Questions or issues: {APP_SUPPORT}")
        ]

        wrap = dialog_width - 80    # Text wrap width based on dialog size

        for title, body in sections:
            tk.Label(
                content,
                text=title,
                font=self.theme.font(size=FONT_SIZE_MD, bold=True),
                bg=self.theme.bg_primary,
                fg=self.theme.text_primary,
                anchor='w'
            ).pack(anchor='w', pady=(14, 4))

            tk.Label(
                content,
                text=body,
                font=self.theme.font(size=FONT_SIZE_BASE),
                bg=self.theme.bg_primary,
                fg=self.theme.text_secondary,
                wraplength=wrap,
                justify='left',
                anchor='w'
            ).pack(anchor='w')

        # Spacer at bottom of content
        tk.Frame(content, bg=self.theme.bg_primary, height=16).pack()

        # Prevent closing the X button without accepting
        dialog.protocol("WM_DELETE_WINDOW", lambda: None)


    def _run_scan(self):
        """Starts a full security scan using the scan coordinator."""
        profile = self.db.get_setting('scan_profile', DEFAULT_SCAN_PROFILE)

        if self.scanner.is_scanning:
            self.update_status("Scan already in progress...", "scanning")
            return

        self.update_status(f"Starting {profile} scan...", "scanning")
        self.scan_btn.configure(state='disabled', text="Scanning...")
        self.scanner.start_scan(profile)


    def _on_scan_progress(self, message, percent):
        """Called from scan thread — schedules UI update on main thread."""
        self.root.after(0, lambda: self.update_status(message, "scanning"))


    def _on_scan_complete(self, results):
        """Called when scan finishes — updates all tabs with results."""
        self.root.after(0, lambda: self._apply_scan_results(results))


    def _toggle_theme(self):
        """Toggles between dark and light mode."""
        self.theme.toggle()
        self.root.configure(bg=self.theme.bg_primary)
        self.db.set_setting('theme', 'dark' if self.theme.is_dark else 'light')


    def _apply_scan_results(self, results):
        """Applies scan results to all tabs on the main thread."""
        # Re-enable scan button
        self.scan_btn.configure(state='normal', text="Run Scan")

        # Update all tabs that accept scan results
        for tab_id, tab_obj in self.tab_objects.items():
            if hasattr(tab_obj, 'update'):
                try:
                    tab_obj.update(results)
                except Exception:
                    pass

        # Switch to dashboard to show results
        self._show_tab(TAB_DASHBOARD)


    def _export_report(self):
        """Triggers HTML report export via the Reports tab."""
        if TAB_REPORTS in self.tab_objects:
            try:
                self.tab_objects[TAB_REPORTS]._export_html_dark()
            except Exception as e:
                from tkinter import messagebox
                messagebox.showerror(
                    "Export Failed",
                    f"Could not export report:\n{str(e)}",
                    parent=self.root
                )
        else:
            from tkinter import messagebox
            messagebox.showinfo(
                "No Data",
                "Run a scan first to generate a report.",
                parent=self.root
            )


    def update_status(self, message, state="ready"):
        """
        Updates the status bar message and indicator dot color.

        Parameters:
            message (str): The status message to display.
            state   (str): 'ready', 'scanning', 'warning', or 'error'
        """
        # Choose dot color based on state
        dot_colors = {
            "ready":    COLOR_SAFE,         # Green — all good
            "scanning": COLOR_INFO,         # Blue — working
            "warning":  COLOR_WARNING,      # Amber — attention needed
            "error":    COLOR_CRITICAL      # Red — problem
        }
        dot_color = dot_colors.get(state, COLOR_SAFE)

        # Update the status label and dot
        self.status_label.configure(text=message)
        self.status_dot.configure(fg=dot_color)


    def _update_sidebar_theme(self):
        """Updates sidebar colors when theme changes."""
        self.sidebar.configure(bg=self.theme.bg_sidebar)
        for tab_id, btn in self.sidebar_buttons.items():
            if tab_id == self._active_tab:
                btn.configure(bg=self.theme.bg_tertiary, fg=self.theme.accent)
            else:
                btn.configure(bg=self.theme.bg_sidebar, fg=self.theme.text_secondary)


    def _update_status_bar_theme(self):
        """Updates status bar colors when theme changes."""
        self.status_bar.configure(bg=self.theme.bg_secondary)
        self.status_label.configure(
            bg=self.theme.bg_secondary,
            fg=self.theme.text_secondary
        )
        self.status_dot.configure(bg=self.theme.bg_secondary)


    def _on_close(self):
        """
        Called when the user closes the application window.

        Saves the current window position and size to the database
        so they are restored on next launch, then exits.
        """
        # Get current window geometry
        x = self.root.winfo_x()         # Current X position on screen
        y = self.root.winfo_y()         # Current Y position on screen
        width = self.root.winfo_width()  # Current width
        height = self.root.winfo_height()# Current height

        # Save to database for next launch
        self.db.save_window_state(x, y, width, height)

        # Save the current theme preference
        self.db.set_setting('theme', 'dark' if self.theme.is_dark else 'light')

        # Destroy the window and exit
        self.root.destroy()


    def run(self):
        """
        Starts the Tkinter main event loop.

        This call blocks until the user closes the window.
        The event loop processes all user interactions —
        clicks, keyboard input, window resizing, etc.
        """
        self.root.mainloop()    # Start the GUI event loop
