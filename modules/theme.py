"""
=============================================================
  SENTINELHOME101 — Theme Manager
  File: modules/theme.py

  Manages dark and light mode across the entire application.
  All widgets register themselves with the ThemeManager so
  that when the user toggles dark/light mode in settings,
  every widget updates instantly without restarting the app.
=============================================================
"""

from modules.constants import *     # Import all color and font constants


class ThemeManager:
    """
    Central theme manager for SentinelHome101.

    Widgets register a callback function with the ThemeManager.
    When the theme changes, the ThemeManager calls all registered
    callbacks so every widget can update its colors immediately.

    Usage:
        theme = ThemeManager(is_dark=True)
        theme.register(my_widget.apply_theme)
        theme.toggle()  # Switches all widgets at once
    """

    def __init__(self, is_dark=True):
        """
        Initializes the theme manager.

        Parameters:
            is_dark (bool): True = dark mode (default), False = light mode.
        """
        self._is_dark = is_dark             # Current theme state
        self._callbacks = []                # List of registered update functions


    def register(self, callback):
        """
        Registers a callback function to be called when theme changes.

        Parameters:
            callback (callable): A function that takes no arguments.
                                 Called whenever the theme toggles.

        Example:
            theme.register(lambda: my_label.configure(bg=theme.bg_primary))
        """
        self._callbacks.append(callback)    # Add to the callback list


    def toggle(self):
        """
        Switches between dark and light mode and updates all widgets.
        """
        self._is_dark = not self._is_dark   # Flip the boolean
        self._notify_all()                  # Tell all widgets to update


    def set_dark(self, is_dark):
        """
        Sets the theme to a specific mode.

        Parameters:
            is_dark (bool): True = dark mode, False = light mode.
        """
        if self._is_dark != is_dark:        # Only update if actually changing
            self._is_dark = is_dark
            self._notify_all()


    def _notify_all(self):
        """
        Calls all registered callback functions.
        Each callback is responsible for updating its own widget.
        """
        for callback in self._callbacks:
            try:
                callback()                  # Call the update function
            except Exception:
                pass                        # Ignore errors in individual widgets


    @property
    def is_dark(self):
        """Returns True if currently in dark mode."""
        return self._is_dark


    # =================================================================
    # COLOR PROPERTIES
    # These return the correct color for the current theme mode.
    # Use these throughout the app instead of hardcoding colors.
    # =================================================================

    @property
    def bg_primary(self):
        """Main background color."""
        return DARK_BG_PRIMARY if self._is_dark else LIGHT_BG_PRIMARY

    @property
    def bg_secondary(self):
        """Panel and card background color."""
        return DARK_BG_SECONDARY if self._is_dark else LIGHT_BG_SECONDARY

    @property
    def bg_tertiary(self):
        """Hover state and subtle separator color."""
        return DARK_BG_TERTIARY if self._is_dark else LIGHT_BG_TERTIARY

    @property
    def bg_sidebar(self):
        """Sidebar background color."""
        return DARK_BG_SIDEBAR if self._is_dark else LIGHT_BG_SIDEBAR

    @property
    def border(self):
        """Standard border color."""
        return DARK_BORDER if self._is_dark else LIGHT_BORDER

    @property
    def border_light(self):
        """Subtle secondary border color."""
        return DARK_BORDER_LIGHT if self._is_dark else LIGHT_BORDER_LIGHT

    @property
    def text_primary(self):
        """Main readable text color."""
        return DARK_TEXT_PRIMARY if self._is_dark else LIGHT_TEXT_PRIMARY

    @property
    def text_secondary(self):
        """Dimmed label text color."""
        return DARK_TEXT_SECONDARY if self._is_dark else LIGHT_TEXT_SECONDARY

    @property
    def text_muted(self):
        """Very dimmed section label text color."""
        return DARK_TEXT_MUTED if self._is_dark else LIGHT_TEXT_MUTED

    @property
    def accent(self):
        """Primary accent color (ghost white on dark, dark on light)."""
        return ACCENT if self._is_dark else LIGHT_ACCENT

    @property
    def accent_dim(self):
        """Dimmed accent color."""
        return ACCENT_DIM if self._is_dark else LIGHT_ACCENT_DIM

    # Severity colors are the same in both modes for consistency
    @property
    def critical(self):
        """Critical issue color."""
        return COLOR_CRITICAL

    @property
    def warning(self):
        """Warning color."""
        return COLOR_WARNING

    @property
    def info(self):
        """Informational color."""
        return COLOR_INFO

    @property
    def safe(self):
        """Safe/passed check color."""
        return COLOR_SAFE

    @property
    def unknown(self):
        """Unknown/not yet checked color."""
        return COLOR_UNKNOWN

    # Severity background colors
    @property
    def bg_critical(self):
        """Background for critical finding cards."""
        return BG_CRITICAL

    @property
    def bg_warning(self):
        """Background for warning finding cards."""
        return BG_WARNING

    @property
    def bg_info(self):
        """Background for info finding cards."""
        return BG_INFO

    @property
    def bg_safe(self):
        """Background for safe/passed check cards."""
        return BG_SAFE


    # =================================================================
    # FONT HELPERS
    # Return tuples in the format Tkinter expects: (family, size, style)
    # =================================================================

    def font(self, size=FONT_SIZE_BASE, bold=False, mono=False):
        """
        Returns a Tkinter-compatible font tuple.

        Parameters:
            size (int)  : Font size in points. Use FONT_SIZE_* constants.
            bold (bool) : True for bold weight, False for normal.
            mono (bool) : True for monospace font (IPs, MACs, code).

        Returns:
            tuple: (family, size) or (family, size, 'bold')

        Example:
            label.configure(font=theme.font(size=FONT_SIZE_LG, bold=True))
        """
        family = FONT_MONO if mono else FONT_UI     # Choose font family
        style = "bold" if bold else ""              # Add bold if requested

        if style:
            return (family, size, style)    # Three-part tuple with style
        else:
            return (family, size)           # Two-part tuple without style


    def severity_color(self, severity):
        """
        Returns the appropriate color for a given severity level.

        Parameters:
            severity (str): 'critical', 'warning', 'info', or 'pass'

        Returns:
            str: The hex color code for that severity level.
        """
        colors = {
            SEVERITY_CRITICAL:  self.critical,
            SEVERITY_WARNING:   self.warning,
            SEVERITY_INFO:      self.info,
            SEVERITY_PASS:      self.safe,
        }
        return colors.get(severity, self.unknown)   # Default to unknown color


    def severity_bg(self, severity):
        """
        Returns the appropriate background color for a severity level.

        Parameters:
            severity (str): 'critical', 'warning', 'info', or 'pass'

        Returns:
            str: The hex background color code for that severity level.
        """
        backgrounds = {
            SEVERITY_CRITICAL:  self.bg_critical,
            SEVERITY_WARNING:   self.bg_warning,
            SEVERITY_INFO:      self.bg_info,
            SEVERITY_PASS:      self.bg_safe,
        }
        return backgrounds.get(severity, self.bg_secondary)
