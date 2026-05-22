# =============================================================
#  SENTINELHOME101 — PyInstaller Build Specification
#  File: SentinelHome101.spec
#
#  This file tells PyInstaller exactly how to package
#  SentinelHome101 into a standalone Windows .exe file.
#
#  TO BUILD THE EXE:
#  1. Open Command Prompt as Administrator
#  2. Navigate to C:\SentinelHome101\
#  3. Run: pyinstaller SentinelHome101.spec
#  4. Find the exe in: C:\SentinelHome101\dist\SentinelHome101.exe
#
#  The resulting exe requires no Python installation on
#  the user's machine. It is fully self-contained.
# =============================================================

import os

# The project root directory
# PyInstaller resolves this relative to where the spec file lives
project_root = os.path.dirname(os.path.abspath(SPEC))  # noqa: F821

block_cipher = None  # No encryption on the bundled files

# -------------------------------------------------------
# ANALYSIS
# Tells PyInstaller what Python files to include and
# what data files (non-Python) to bundle alongside them.
# -------------------------------------------------------
a = Analysis(
    # Entry point — the first file Python runs
    scripts=[os.path.join(project_root, 'main.py')],

    # Additional paths to search for imports
    pathex=[project_root],

    # Binary files to include (DLLs, .so files)
    # We have none — all our dependencies are pure Python
    binaries=[],

    # Non-Python data files to bundle
    # Format: (source_path, destination_folder_in_bundle)
    datas=[
        # OUI database — required for MAC manufacturer lookup
        (os.path.join(project_root, 'assets', 'oui_database.txt'),
         'assets'),

        # App icon — used in the title bar and taskbar
        (os.path.join(project_root, 'assets', 'icon.ico'),
         'assets'),
    ],

    # Python modules that PyInstaller might miss due to
    # dynamic imports (import inside functions, etc.)
    hiddenimports=[
        'tkinter',
        'tkinter.ttk',
        'tkinter.messagebox',
        'tkinter.filedialog',
        'sqlite3',
        'winreg',
        'ctypes',
        'ctypes.windll',
        'subprocess',
        'socket',
        'ipaddress',
        'concurrent.futures',
        'threading',
        'hashlib',
        'json',
        'datetime',
        'webbrowser',
        'urllib.request',
        'urllib.error',
        'ssl',
        'speedtest',
        'requests',
        'PIL',
        'PIL.Image',
    ],

    # Files/directories to exclude from the bundle
    # Keeps the exe smaller by removing things we do not need
    excludes=[
        'matplotlib',       # Only needed if charts are enabled
        'numpy',            # Large — only include if needed
        'pandas',           # Not used
        'scipy',            # Not used
        '_tkinter.tests',   # Tkinter test files
    ],

    # Hook files that help PyInstaller find hidden dependencies
    hookspath=[],

    # Runtime hooks — run before the app starts
    runtime_hooks=[],

    # Whether to use UPX compression on binaries
    # UPX reduces file size but can trigger antivirus false positives
    # Disabled here to avoid false positive issues during distribution
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# -------------------------------------------------------
# PYZ — Python bytecode archive
# Compresses all the Python modules into a single archive
# -------------------------------------------------------
pyz = PYZ(  # noqa: F821
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)

# -------------------------------------------------------
# EXE — The final executable
# -------------------------------------------------------
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,

    # Output filename (without .exe — Windows adds it automatically)
    name='SentinelHome101',

    # Whether to show a console window
    # False = no black console window — GUI only
    console=False,

    # Path to the application icon file
    # This icon appears on the .exe file and in the taskbar
    icon=os.path.join(project_root, 'assets', 'icon.ico'),

    # UPX compression — disabled to avoid antivirus false positives
    upx=False,

    # Strip debug symbols from the exe
    strip=False,

    # Windows-specific: embed a manifest file
    # The manifest requests Administrator elevation via UAC
    # This replaces the runtime elevation check in main.py
    # when running as a packaged exe
    uac_admin=True,

    # Version info embedded in the exe's file properties
    # (visible when right-clicking the exe → Properties → Details)
    version=None,  # Set to version file path if created

    # One-file mode: bundle everything into a single .exe
    # The exe extracts to a temp folder on first run
    # Alternative is one-folder mode (comment out a.binaries etc above)
    onefile=True,
)
