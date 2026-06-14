"""
=============================================================
  SENTINELHOME101 — Constants and Theme Configuration
  File: modules/constants.py

  Single source of truth for all colors, fonts, sizes,
  and other values used throughout the entire application.

  Changing a value here automatically updates it everywhere
  in the app — no need to hunt through multiple files.
=============================================================
"""

# =============================================================
# APPLICATION IDENTITY
# =============================================================

APP_NAME        = "SentinelHome101"         # Full product name
APP_VERSION     = "1.0.1"                   # Current version number
APP_SUPPORT     = "support@sentinelhome101.com"  # Support email address
APP_DESCRIPTION = "101-point home network and computer security audit"

# Minimum window dimensions in pixels
# The app does not work well below these sizes
MIN_WIDTH   = 1024  # Minimum window width
MIN_HEIGHT  = 680   # Minimum window height

# Default window dimensions on first launch
DEFAULT_WIDTH   = 1280  # Default window width
DEFAULT_HEIGHT  = 800   # Default window height


# =============================================================
# DARK MODE COLORS (default)
# =============================================================

# --- Backgrounds ---
DARK_BG_PRIMARY     = "#0d1117"     # Main background — deepest dark
DARK_BG_SECONDARY   = "#161b22"     # Panel/card background
DARK_BG_TERTIARY    = "#21262d"     # Hover states and subtle separators
DARK_BG_SIDEBAR     = "#161b22"     # Left navigation sidebar

# --- Borders ---
DARK_BORDER         = "#30363d"     # Standard border color
DARK_BORDER_LIGHT   = "#21262d"     # Subtle / secondary border

# --- Text ---
DARK_TEXT_PRIMARY   = "#e6edf3"     # Main readable text
DARK_TEXT_SECONDARY = "#8b949e"     # Dimmed / label text
DARK_TEXT_MUTED     = "#484f58"     # Very dimmed text (section labels)

# --- Accent (Ghost White — matches icon palette) ---
ACCENT              = "#f1f5f9"     # Primary ghost white accent
ACCENT_DIM          = "#cbd5e1"     # Dimmed ghost white for secondary use
ACCENT_SUBTLE       = "#1e2a3a"     # Very subtle accent background tint

# --- Semantic Colors (severity indicators) ---
COLOR_CRITICAL      = "#f85149"     # Red — critical issues
COLOR_WARNING       = "#d29922"     # Amber — warnings
COLOR_INFO          = "#378add"     # Blue — informational
COLOR_SAFE          = "#3fb950"     # Green — safe / passed checks
COLOR_UNKNOWN       = "#8b949e"     # Grey — not yet checked

# --- Semantic Backgrounds (for finding cards and badges) ---
BG_CRITICAL         = "#3a1010"     # Dark red background for critical items
BG_WARNING          = "#3a2000"     # Dark amber background for warnings
BG_INFO             = "#0d1a2e"     # Dark blue background for info items
BG_SAFE             = "#0d2818"     # Dark green background for safe items


# =============================================================
# LIGHT MODE COLORS
# =============================================================

# --- Backgrounds ---
LIGHT_BG_PRIMARY    = "#ffffff"     # Main background — white
LIGHT_BG_SECONDARY  = "#f8fafc"     # Panel/card background
LIGHT_BG_TERTIARY   = "#f1f5f9"     # Hover states
LIGHT_BG_SIDEBAR    = "#f1f5f9"     # Left navigation sidebar

# --- Borders ---
LIGHT_BORDER        = "#e2e8f0"     # Standard border
LIGHT_BORDER_LIGHT  = "#f1f5f9"     # Subtle border

# --- Text ---
LIGHT_TEXT_PRIMARY  = "#0d1117"     # Main readable text (dark)
LIGHT_TEXT_SECONDARY= "#64748b"     # Dimmed label text
LIGHT_TEXT_MUTED    = "#94a3b8"     # Very dimmed text

# --- Accent (dark for light mode) ---
LIGHT_ACCENT        = "#0d1117"     # Primary dark accent on light background
LIGHT_ACCENT_DIM    = "#1e293b"     # Dimmed accent


# =============================================================
# FONTS
# Note: Tkinter uses system fonts. These are the best
# available on Windows for a professional appearance.
# =============================================================

FONT_UI         = "Segoe UI"        # Primary UI font (clean Windows font)
FONT_MONO       = "Courier New"     # Monospace for IPs, MACs, code
FONT_FALLBACK   = "Arial"           # Fallback if Segoe UI unavailable

# Font sizes
FONT_SIZE_XS    = 8     # Tiny labels
FONT_SIZE_SM    = 10    # Small labels, badges, notes
FONT_SIZE_BASE  = 11    # Standard body text
FONT_SIZE_MD    = 12    # Medium text, panel content
FONT_SIZE_LG    = 13    # Section headers, important labels
FONT_SIZE_XL    = 14    # Tab labels, major headers
FONT_SIZE_2XL   = 16    # Dashboard stat labels
FONT_SIZE_3XL   = 22    # Dashboard stat numbers
FONT_SIZE_HUGE  = 32    # Score gauge number


# =============================================================
# LAYOUT DIMENSIONS
# =============================================================

SIDEBAR_WIDTH       = 52    # Left icon sidebar width in pixels
PADDING_SM          = 6     # Small padding
PADDING_MD          = 12    # Medium padding
PADDING_LG          = 16    # Large padding
PADDING_XL          = 24    # Extra large padding

BORDER_RADIUS       = 8     # Standard corner radius for panels
BORDER_RADIUS_SM    = 4     # Small corner radius for badges


# =============================================================
# SCAN PROFILES
# Each profile defines what checks run and expected duration.
# =============================================================

SCAN_PROFILES = {
    "quick": {
        "label":        "Quick Scan",
        "description":  "Ping sweep and basic host checks only",
        "duration":     "~30 seconds",
        "features":     [1, 2, 3, 4, 5, 6, 7, 8, 11, 13, 16, 17]
                        # Only the fastest, most critical checks
    },
    "standard": {
        "label":        "Standard Scan",
        "description":  "Full 101-feature audit",
        "duration":     "4–6 minutes",
        "features":     list(range(1, 102))    # All 101 features
    },
    "deep": {
        "label":        "Deep Scan",
        "description":  "Full audit with extended port scan (all ports)",
        "duration":     "15–25 minutes",
        "features":     list(range(1, 102))    # All 101 features + full port scan
    }
}

# The default scan profile used on first launch
DEFAULT_SCAN_PROFILE = "quick"


# =============================================================
# SEVERITY LEVELS
# Used to categorize findings and calculate the network score.
# =============================================================

SEVERITY_CRITICAL   = "critical"    # Immediate action required
SEVERITY_WARNING    = "warning"     # Should be addressed soon
SEVERITY_INFO       = "info"        # Worth knowing, low urgency
SEVERITY_PASS       = "pass"        # Check passed, no issue found

# Score penalty for each severity level
# Used to calculate the 0-100 network score
SCORE_PENALTY = {
    SEVERITY_CRITICAL:  15,     # Each critical finding costs 15 points
    SEVERITY_WARNING:   5,      # Each warning costs 5 points
    SEVERITY_INFO:      1,      # Each info finding costs 1 point
    SEVERITY_PASS:      0       # Passing checks cost nothing
}

# Starting score before penalties are applied
SCORE_BASE = 100


# =============================================================
# TAB IDENTIFIERS
# Used to identify which tab is active.
# =============================================================

TAB_DASHBOARD   = "dashboard"
TAB_HOST        = "host"
TAB_THREAT      = "threat"
TAB_NETWORK     = "network"
TAB_MONITORING  = "monitoring"
TAB_REPORTS     = "reports"

# Tab display order (left to right in sidebar)
TAB_ORDER = [
    TAB_DASHBOARD,
    TAB_HOST,
    TAB_THREAT,
    TAB_NETWORK,
    TAB_MONITORING,
    TAB_REPORTS
]

# Tab labels shown in tooltips
TAB_LABELS = {
    TAB_DASHBOARD:  "Dashboard",
    TAB_HOST:       "This Device",
    TAB_THREAT:     "Threat Detection",
    TAB_NETWORK:    "Network",
    TAB_MONITORING: "Monitoring",
    TAB_REPORTS:    "Reports & Settings"
}


# =============================================================
# EXTERNAL SERVICES
# The two features that connect outside the local network.
# Both are opt-in only and disabled by default.
# =============================================================

HIBP_API_URL        = "https://haveibeenpwned.com/api/v3/breachedaccount/"
HIBP_API_HEADERS    = {"hibp-api-key": ""}   # User must supply their own key
SPEEDTEST_ENABLED   = False     # Default: disabled (opt-in required)
HIBP_ENABLED        = False     # Default: disabled (opt-in required)

# OUI database file location (relative to the project root)
OUI_DATABASE_FILE   = "assets/oui_database.txt"

# First 6 characters of a MAC address identify the manufacturer
OUI_PREFIX_LENGTH   = 8    # Format is XX:XX:XX so 8 chars including colons


# =============================================================
# CANARY FILE CONFIGURATION
# =============================================================

# Folders where canary files are planted
CANARY_FOLDERS = [
    "Desktop",      # Most common ransomware target
    "Documents",    # High-value document folder
    "Downloads",    # Common entry point for malware
    "Pictures"      # Often targeted for encryption
]

# Name of the canary file in each folder
CANARY_FILENAME     = ".s101_canary.dat"    # Hidden-style name

# Content written to each canary file
# Must be unique enough that accidental matches are impossible
CANARY_CONTENT      = f"SentinelHome101 Ransomware Canary File v{APP_VERSION}\n"
CANARY_CONTENT     += "This file is monitored for tampering.\n"
CANARY_CONTENT     += "If this file is modified or missing, it may indicate ransomware activity.\n"
CANARY_CONTENT     += "Do not delete or modify this file.\n"
