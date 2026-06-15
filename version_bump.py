"""
=============================================================
  SENTINELHOME101 — Version Bump Script
  File: version_bump.py

  Run this script once at the start of every version bump.
  It updates every file that contains a version string
  automatically, so nothing gets missed.

  Usage:
      python version_bump.py

  The script will:
  1. Ask you for the old version and new version
  2. Show you every change it plans to make
  3. Ask for confirmation before touching anything
  4. Apply all changes and report results

  Files updated automatically:
  - modules/constants.py (APP_VERSION)
  - main.py (header comment)
  - README.md (version reference)
  - index.html (3 version references)
  - faq.html (footer)
  - privacy.html (footer and page meta)
  - All 10 blog HTML files (footers)
  - sitemap.xml (homepage lastmod date)
  - Documentation/files/SentinelHome101_Changelog.txt
    (adds new entry placeholder at top)

  Files NOT updated by this script (manual task):
  - Documentation/files/EULA.docx
  - Documentation/files/FAQ.docx
  - Documentation/files/Installation_Guide.docx
  - Documentation/files/Privacy_Policy.docx
  - Documentation/files/README.docx
  - Documentation/files/User_Manual.docx
  - Documentation/files/Attorney_Briefing_Package.docx
  - Documentation/files/Data_Handling_White_Sheet.docx
  - directory_submission_copy.txt (also needs VirusTotal link update)

  DATA: This script reads and writes local files only.
  Nothing is sent outside your machine.
=============================================================
"""

import os       # File path operations
import re       # Regular expressions for pattern matching
import datetime # Date handling for sitemap lastmod update


# =============================================================
# FILE PATHS
# All paths relative to the project root (C:\SentinelHome101)
# =============================================================

# Determine project root from the script's location
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))  # Folder containing this script

# Python source files
FILES_PYTHON = [
    os.path.join(PROJECT_ROOT, 'main.py'),
    os.path.join(PROJECT_ROOT, 'modules', 'constants.py'),
]

# Root-level HTML and markdown files
FILES_ROOT_WEB = [
    os.path.join(PROJECT_ROOT, 'README.md'),
    os.path.join(PROJECT_ROOT, 'index.html'),
    os.path.join(PROJECT_ROOT, 'faq.html'),
    os.path.join(PROJECT_ROOT, 'privacy.html'),
]

# Blog article HTML files
BLOG_DIR = os.path.join(PROJECT_ROOT, 'blog')  # Blog subdirectory
BLOG_FILES = [
    'best-free-home-network-security-scanner-windows.html',
    'free-alternative-to-nessus-home-users.html',
    'home-network-security-checklist.html',
    'how-to-audit-home-network-security.html',
    'how-to-check-devices-on-home-network.html',
    'how-to-check-if-wifi-is-secure.html',
    'how-to-tell-if-home-network-compromised.html',
    'router-default-credentials.html',
    'what-is-dns-hijacking.html',
    'what-is-upnp-and-why-is-it-dangerous.html',
    'index.html',  # Blog index page
]

# Sitemap file
SITEMAP_FILE = os.path.join(PROJECT_ROOT, 'sitemap.xml')  # Sitemap for homepage lastmod

# Changelog text file
CHANGELOG_FILE = os.path.join(PROJECT_ROOT, 'Documentation', 'files', 'SentinelHome101_Changelog.txt')


def read_file(path):
    """
    Reads a file and returns its content as a string.
    Returns None if the file does not exist.
    """
    if not os.path.exists(path):  # Check file exists before reading
        return None
    with open(path, 'r', encoding='utf-8') as f:  # Open with UTF-8 to handle special chars
        return f.read()


def write_file(path, content):
    """
    Writes content to a file, replacing existing content.
    Creates parent directories if they do not exist.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)  # Ensure parent directory exists
    with open(path, 'w', encoding='utf-8') as f:        # Open for writing with UTF-8
        f.write(content)                                 # Write new content


def count_occurrences(content, old_version):
    """
    Counts how many times the old version string appears in a file.
    Used to preview changes before applying them.
    """
    return content.count(old_version)  # Simple string count


def apply_simple_replace(path, old_version, new_version):
    """
    Replaces all occurrences of old_version with new_version in a file.
    Returns a tuple of (success, count_replaced, error_message).
    """
    content = read_file(path)  # Read current file content
    if content is None:        # File does not exist
        return False, 0, f"File not found: {path}"

    count = content.count(old_version)  # Count occurrences before replacing
    if count == 0:                       # Nothing to replace in this file
        return True, 0, None

    new_content = content.replace(old_version, new_version)  # Replace all occurrences
    write_file(path, new_content)                             # Write updated content back
    return True, count, None                                  # Return success and count


def update_sitemap_lastmod(path, new_date):
    """
    Updates the lastmod date on the homepage entry in sitemap.xml.
    The homepage entry is identified by being the first <lastmod> tag.
    """
    content = read_file(path)  # Read current sitemap content
    if content is None:
        return False, "Sitemap file not found"

    # Pattern matches the lastmod date in the sitemap
    # Looks for: <lastmod>YYYY-MM-DD</lastmod>
    pattern = r'(<loc>https://sentinelhome101\.com</loc>.*?<lastmod>)(\d{4}-\d{2}-\d{2})(</lastmod>)'

    # re.DOTALL allows . to match newlines so multi-line entries work
    new_content = re.sub(pattern, rf'\g<1>{new_date}\3', content, count=1, flags=re.DOTALL)

    if new_content == content:  # No change was made — pattern did not match
        return False, "Could not find homepage lastmod in sitemap"

    write_file(path, new_content)  # Write updated sitemap
    return True, None


def add_changelog_placeholder(path, new_version, today):
    """
    Adds a placeholder entry at the top of the changelog for the new version.
    The developer fills in the actual changes after running this script.
    """
    content = read_file(path)  # Read current changelog content
    if content is None:
        return False, "Changelog file not found"

    # Build the placeholder entry that goes at the top
    placeholder = f"""SentinelHome101 — Changelog


Version {new_version}  ·  {today}
[FILL IN RELEASE DESCRIPTION HERE]

[FILL IN CHANGES HERE]

Known Limitations
[FILL IN OR CARRY FORWARD FROM PREVIOUS VERSION]

───────────────────────────────────────────────────────────────

"""  # Two blank lines before the old content starts

    # Remove the existing "SentinelHome101 — Changelog" header if present
    # so it does not appear twice after we prepend the new entry
    if content.startswith("SentinelHome101 — Changelog"):
        # Strip the header line and any leading blank lines
        content = content.lstrip()                           # Remove leading whitespace
        lines = content.split('\n')                          # Split into lines
        lines = lines[1:]                                    # Remove first line (the header)
        content = '\n'.join(lines).lstrip('\n')              # Rejoin and strip leading newlines

    new_content = placeholder + content  # Prepend the new entry
    write_file(path, new_content)        # Write updated changelog
    return True, None


def main():
    """
    Main version bump process.
    Prompts for versions, previews all changes, then applies them.
    """
    print("=" * 60)
    print("  SentinelHome101 — Version Bump Script")
    print("=" * 60)
    print()

    # -------------------------------------------------------
    # STEP 1: Get version numbers from the user
    # -------------------------------------------------------
    old_version = input("Enter the CURRENT version number (e.g. 1.0.1): ").strip()
    new_version = input("Enter the NEW version number    (e.g. 1.1.0): ").strip()

    if not old_version or not new_version:      # Validate input
        print("\nERROR: Both version numbers are required. Exiting.")
        return

    if old_version == new_version:              # Catch accidental same-version input
        print("\nERROR: Old and new versions are the same. Exiting.")
        return

    today = datetime.date.today().strftime('%B %d, %Y')   # e.g. "June 14, 2026"
    today_iso = datetime.date.today().strftime('%Y-%m-%d') # e.g. "2026-06-14"

    print(f"\nBumping version: {old_version} → {new_version}")
    print(f"Today's date: {today}")
    print()

    # -------------------------------------------------------
    # STEP 2: Preview all changes before applying anything
    # -------------------------------------------------------
    print("Scanning files for changes needed...")
    print()

    all_files = []  # List of (path, display_name) tuples to process

    # Add Python source files
    for path in FILES_PYTHON:
        all_files.append((path, os.path.relpath(path, PROJECT_ROOT)))

    # Add root web files
    for path in FILES_ROOT_WEB:
        all_files.append((path, os.path.relpath(path, PROJECT_ROOT)))

    # Add blog HTML files
    for filename in BLOG_FILES:
        path = os.path.join(BLOG_DIR, filename)
        all_files.append((path, os.path.join('blog', filename)))

    # Preview results
    changes_found = []   # Files with changes needed
    missing_files = []   # Files that do not exist
    no_changes = []      # Files with no occurrences of old version

    for path, display in all_files:
        content = read_file(path)   # Read file to check for occurrences
        if content is None:
            missing_files.append(display)   # File does not exist
        else:
            count = count_occurrences(content, old_version)  # Count occurrences
            if count > 0:
                changes_found.append((path, display, count)) # Will need changes
            else:
                no_changes.append(display)                   # Already clean or not present

    # Report preview
    if changes_found:
        print(f"Files to update ({len(changes_found)}):")
        for _, display, count in changes_found:
            print(f"  {display}  ({count} occurrence{'s' if count > 1 else ''})")
    else:
        print("No version strings found to update in any file.")

    if missing_files:
        print(f"\nFiles not found (will be skipped):")
        for display in missing_files:
            print(f"  {display}")

    print(f"\nAdditional actions:")
    print(f"  sitemap.xml — update homepage lastmod to {today_iso}")
    print(f"  Changelog.txt — add placeholder entry for v{new_version}")
    print()

    # -------------------------------------------------------
    # STEP 3: Confirm before making any changes
    # -------------------------------------------------------
    confirm = input(f"Apply all changes? (yes/no): ").strip().lower()
    if confirm not in ('yes', 'y'):
        print("\nAborted. No files were changed.")
        return

    print()
    print("Applying changes...")
    print()

    # -------------------------------------------------------
    # STEP 4: Apply changes to all files
    # -------------------------------------------------------
    success_count = 0   # Track successful updates
    error_count = 0     # Track failures

    # Update all files with simple version string replacement
    for path, display, _ in changes_found:
        success, count, error = apply_simple_replace(path, old_version, new_version)
        if success and count > 0:
            print(f"  Updated: {display} ({count} change{'s' if count > 1 else ''})")
            success_count += 1  # Increment success counter
        elif error:
            print(f"  ERROR: {display} — {error}")
            error_count += 1    # Increment error counter

    # Update sitemap lastmod for homepage
    ok, err = update_sitemap_lastmod(SITEMAP_FILE, today_iso)  # Update date in sitemap
    if ok:
        print(f"  Updated: sitemap.xml (homepage lastmod → {today_iso})")
        success_count += 1
    else:
        print(f"  WARNING: sitemap.xml — {err}")

    # Add changelog placeholder
    ok, err = add_changelog_placeholder(CHANGELOG_FILE, new_version, today)
    if ok:
        print(f"  Updated: SentinelHome101_Changelog.txt (placeholder added at top)")
        success_count += 1
    elif err:
        print(f"  WARNING: Changelog — {err}")

    # -------------------------------------------------------
    # STEP 5: Report results and next steps
    # -------------------------------------------------------
    print()
    print("=" * 60)
    print(f"  Done. {success_count} files updated, {error_count} errors.")
    print("=" * 60)
    print()
    print("Next steps (manual):")
    print(f"  1. Fill in the new version entry in SentinelHome101_Changelog.txt")
    print(f"  2. Update version in all 9 Word documents in Documentation/files/")
    print(f"  3. Update directory_submission_copy.txt version and VirusTotal link")
    print(f"  4. Run python build.py to rebuild the exe")
    print(f"  5. Sign the exe with signtool")
    print(f"  6. Run a VirusTotal scan on the signed exe")
    print(f"  7. git add -A && git commit -m 'Version bump to {new_version}'")
    print(f"  8. git push origin main")
    print(f"  9. Update GitHub release with new exe")
    print()
    print("MANUAL DOCS TO UPDATE:")
    docs = [
        "Documentation/files/EULA.docx",
        "Documentation/files/FAQ.docx",
        "Documentation/files/Installation_Guide.docx",
        "Documentation/files/Privacy_Policy.docx",
        "Documentation/files/README.docx",
        "Documentation/files/User_Manual.docx",
        "Documentation/files/Attorney_Briefing_Package.docx",
        "Documentation/files/Data_Handling_White_Sheet.docx",
    ]
    for doc in docs:
        print(f"  [ ] {doc}")
    print()


if __name__ == "__main__":
    main()
