"""
=============================================================
  SENTINELHOME101 — Main Entry Point
  Version: 1.0.0
  Description: 101-point home network and computer security
               audit tool for Windows home users.

  This file does three things:
  1. Checks that the app is running as Administrator
  2. Re-launches itself with elevation if it is not
  3. Starts the main application window

  DATA PRIVACY: SentinelHome101 sends NO data outside your
  local network or machine except for two explicitly opt-in
  features (speed test and HaveIBeenPwned check) which are
  disabled by default and clearly labeled in settings.

  Support: support@sentinelhome101.com
=============================================================
"""

# --- Standard library imports ---
import sys          # Lets us access system functions like exit()
import os           # Lets us work with file paths and directories
import ctypes       # Lets us call Windows API functions (for admin check)
import subprocess   # Lets us launch new processes (for re-launching elevated)

# --- Add the project root to Python's path ---
# This ensures all our module imports work correctly
# regardless of where Python is launched from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def is_admin():
    """
    Checks whether the current process is running with
    Windows Administrator privileges.

    Returns True if running as admin, False if not.

    We need admin rights because several of our 101 security
    checks require elevated access:
    - Reading Windows Security Center status
    - Querying WMI for system information
    - Running netsh for network configuration checks
    - Accessing certain registry keys
    """
    try:
        # ctypes.windll.shell32.IsUserAnAdmin() is a Windows API
        # call that returns 1 if the current user is an admin
        # and 0 if they are not
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        # If the call fails for any reason, assume not admin
        # This prevents the app from crashing on the check
        return False


def elevate():
    """
    Re-launches this script with Administrator privileges.

    Uses the Windows ShellExecute API with the 'runas' verb,
    which triggers the standard Windows UAC (User Account Control)
    prompt asking the user to allow elevated access.

    After re-launching, exits the current non-elevated process.
    """
    # Get the full path to the Python interpreter currently running
    python_executable = sys.executable

    # Get the full path to this script file
    script_path = os.path.abspath(__file__)

    # ShellExecuteW parameters:
    # hwnd=None    - no parent window
    # op='runas'   - this is the verb that triggers the UAC prompt
    # file=python  - run Python
    # params=script- with this script as the argument
    # dir=None     - use default working directory
    # show=1       - show the window normally
    ctypes.windll.shell32.ShellExecuteW(
        None,               # No parent window handle
        "runas",            # Operation: run as administrator
        python_executable,  # Program to run
        f'"{script_path}"', # Script to pass as argument
        None,               # Working directory (use default)
        1                   # Show window normally (SW_SHOWNORMAL)
    )

    # Exit the current non-elevated process now that
    # the elevated version has been launched
    sys.exit(0)


def main():
    """
    Main entry point. Checks for admin rights, elevates if needed,
    then launches the SentinelHome101 application window.
    """

    # --- Step 1: Check for Administrator privileges ---
    if not is_admin():
        # Not running as admin — re-launch with elevation
        # The user will see a standard Windows UAC prompt
        elevate()
        # elevate() calls sys.exit() so we never reach here
        return

    # --- Step 2: Set up AppData directory ---
    # This is where we store the database, settings, and canary files
    # Using AppData\Roaming so data persists across Windows updates
    appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
    app_data_dir = os.path.join(appdata, 'SentinelHome101')

    # Create the directory if it does not already exist
    # exist_ok=True means no error if it already exists
    os.makedirs(app_data_dir, exist_ok=True)

    # Create subdirectories for organized data storage
    os.makedirs(os.path.join(app_data_dir, 'reports'), exist_ok=True)   # Saved scan reports
    os.makedirs(os.path.join(app_data_dir, 'canary'), exist_ok=True)    # Ransomware canary files
    os.makedirs(os.path.join(app_data_dir, 'logs'), exist_ok=True)      # Application logs

    # --- Step 3: Launch the application ---
    # Import here (after path setup) to avoid circular imports
    # and to ensure all directories exist before the app starts
    from modules.app import SentinelHome101App  # The main application class

    # Create and run the application
    # This call blocks until the user closes the window
    app = SentinelHome101App(app_data_dir)  # Pass the data directory to the app
    app.run()                                # Start the Tkinter main loop


# --- Standard Python entry point guard ---
# This ensures main() only runs when this file is executed directly,
# not when it is imported as a module by another file
if __name__ == "__main__":
    main()
