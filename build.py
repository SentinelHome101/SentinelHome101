"""
=============================================================
  SENTINELHOME101 — Build Script
  File: build.py

  One-command build process. Run this from Command Prompt
  as Administrator to produce the distributable exe:

      python build.py

  What this script does:
  1. Verifies all required libraries are installed
  2. Generates the icon .ico file
  3. Runs PyInstaller to package the exe
  4. Reports the output location

  Output: C:/SentinelHome101/dist/SentinelHome101.exe
=============================================================
"""

import sys
import os
import subprocess


def check_dependencies():
    """Verifies all required packages are installed."""
    print("Checking dependencies...")
    required = ['PIL', 'speedtest', 'requests', 'PyInstaller']
    missing = []

    for pkg in required:
        try:
            __import__(pkg.lower().replace('pyinstaller', 'PyInstaller'))
        except ImportError:
            # Try alternate import name
            try:
                if pkg == 'PIL':
                    import PIL
                elif pkg == 'speedtest':
                    import speedtest
                elif pkg == 'requests':
                    import requests
                elif pkg == 'PyInstaller':
                    import PyInstaller
            except ImportError:
                missing.append(pkg)

    if missing:
        print(f"\nMissing packages: {', '.join(missing)}")
        print("Install with: pip install " + ' '.join(missing))
        return False

    print("  All dependencies found.")
    return True


def generate_icon():
    """Runs the icon generator script."""
    print("\nGenerating icon files...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    icon_script = os.path.join(script_dir, 'create_icon.py')

    if not os.path.exists(icon_script):
        print("  ERROR: create_icon.py not found")
        return False

    result = subprocess.run(
        [sys.executable, icon_script],
        capture_output=False
    )

    ico_path = os.path.join(script_dir, 'assets', 'icon.ico')
    if os.path.exists(ico_path):
        print("  Icon generated successfully.")
        return True
    else:
        print("  WARNING: Icon file not found after generation.")
        print("  The exe will build without a custom icon.")
        return True  # Non-fatal — build can continue


def run_pyinstaller():
    """Runs PyInstaller with the spec file."""
    print("\nRunning PyInstaller...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    spec_file = os.path.join(script_dir, 'SentinelHome101.spec')

    if not os.path.exists(spec_file):
        print("  ERROR: SentinelHome101.spec not found")
        return False

    # Run PyInstaller
    result = subprocess.run(
        [sys.executable, '-m', 'PyInstaller',
         '--clean',          # Clean build cache before building
         '--noconfirm',      # Overwrite output without asking
         spec_file],
        cwd=script_dir,
        capture_output=False
    )

    if result.returncode == 0:
        exe_path = os.path.join(script_dir, 'dist', 'SentinelHome101.exe')
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print(f"\n  SUCCESS: SentinelHome101.exe built successfully")
            print(f"  Location: {exe_path}")
            print(f"  Size: {size_mb:.1f} MB")
            return True
        else:
            print("  Build completed but exe not found in dist/")
            return False
    else:
        print(f"  PyInstaller failed with return code {result.returncode}")
        print("  Check the output above for error details.")
        return False


def main():
    """Main build process."""
    print("=" * 60)
    print(f"  SentinelHome101 — Build Script")
    print("=" * 60)

    # Step 1: Check dependencies
    if not check_dependencies():
        print("\nBuild aborted — install missing dependencies first.")
        sys.exit(1)

    # Step 2: Generate icon
    generate_icon()

    # Step 3: Run PyInstaller
    success = run_pyinstaller()

    print("\n" + "=" * 60)
    if success:
        print("  BUILD COMPLETE")
        print("  Copy dist\\SentinelHome101.exe to distribute.")
        print("  The exe requires no Python installation to run.")
    else:
        print("  BUILD FAILED — see errors above.")
    print("=" * 60)


if __name__ == "__main__":
    main()
