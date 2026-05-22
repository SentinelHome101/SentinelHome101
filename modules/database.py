"""
=============================================================
  SENTINELHOME101 — Database Module
  File: modules/database.py

  Manages all persistent data storage using SQLite.
  SQLite is a file-based database built into Python —
  no server needed, no external dependencies.

  Everything stored here lives in:
  C:/Users/[Name]/AppData/Roaming/SentinelHome101/

  Tables created and managed by this module:
  - settings       : User preferences and app configuration
  - scan_history   : Record of every scan ever run
  - devices        : Known devices with nicknames and trust status
  - findings       : Individual findings from each scan
  - canary_files   : Ransomware canary file registry
=============================================================
"""

# --- Imports ---
import sqlite3      # Python's built-in SQLite database library
import os           # For building file paths
import json         # For storing complex data as JSON strings
import datetime     # For timestamping records


class Database:
    """
    Manages all database operations for SentinelHome101.

    Uses the context manager pattern (with statements) internally
    to ensure database connections are always properly closed,
    even if an error occurs.
    """

    def __init__(self, app_data_dir):
        """
        Initializes the database connection.

        Parameters:
            app_data_dir (str): Path to the AppData folder where
                                the database file will be stored.

        The database file is named sentinelhome101.db and lives
        in the AppData directory alongside other app data.
        """
        # Build the full path to the database file
        self.db_path = os.path.join(app_data_dir, 'sentinelhome101.db')

        # Store the app data directory for other uses
        self.app_data_dir = app_data_dir

        # Create all tables if they do not exist yet
        # This runs on every startup but only creates tables
        # if they are missing — safe to run repeatedly
        self._initialize_tables()


    def _get_connection(self):
        """
        Creates and returns a new SQLite database connection.

        Sets row_factory to sqlite3.Row so we can access columns
        by name (like a dictionary) instead of just by index number.

        Returns:
            sqlite3.Connection: An open database connection.
        """
        conn = sqlite3.connect(self.db_path)    # Open the database file
        conn.row_factory = sqlite3.Row          # Enable column-name access
        return conn


    def _initialize_tables(self):
        """
        Creates all required database tables if they do not exist.

        Uses 'CREATE TABLE IF NOT EXISTS' so this is safe to call
        on every app startup — existing data is never touched.
        """
        conn = self._get_connection()   # Open connection
        cursor = conn.cursor()          # Create a cursor for executing SQL

        # --- Settings table ---
        # Stores all user preferences as key-value pairs.
        # This approach means we can add new settings without
        # changing the database structure.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key     TEXT PRIMARY KEY,   -- Setting name (unique)
                value   TEXT,               -- Setting value (stored as text)
                updated TEXT                -- When this setting was last changed
            )
        ''')

        # --- Scan history table ---
        # Records every scan that has been run, with summary stats.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,  -- Unique scan ID
                scan_date       TEXT,       -- When the scan was run (ISO format)
                scan_type       TEXT,       -- quick / standard / deep
                duration_secs   INTEGER,    -- How long the scan took in seconds
                devices_found   INTEGER,    -- Number of devices discovered
                critical_count  INTEGER,    -- Number of critical findings
                warning_count   INTEGER,    -- Number of warning findings
                score           INTEGER,    -- Overall network score (0-100)
                network_name    TEXT        -- Name of network scanned
            )
        ''')

        # --- Devices table ---
        # Stores information about every device ever seen on the network.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address      TEXT,       -- Last known IP address
                mac_address     TEXT UNIQUE,-- MAC address (unique hardware ID)
                hostname        TEXT,       -- Device hostname if available
                manufacturer    TEXT,       -- Manufacturer from OUI database
                nickname        TEXT,       -- User-assigned friendly name
                trusted         INTEGER DEFAULT 0,  -- 0=untrusted, 1=trusted
                first_seen      TEXT,       -- First time this device appeared
                last_seen       TEXT,       -- Most recent time device was seen
                notes           TEXT        -- User notes about this device
            )
        ''')

        # --- Findings table ---
        # Stores every individual security finding from every scan.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         INTEGER,    -- Links to scan_history.id
                feature_number  INTEGER,    -- Which of the 101 features found this
                severity        TEXT,       -- critical / warning / info / pass
                title           TEXT,       -- Short description of the finding
                detail          TEXT,       -- Full plain-English explanation
                device_ip       TEXT,       -- Which device this finding is about
                remediation     TEXT,       -- How to fix this issue
                FOREIGN KEY (scan_id) REFERENCES scan_history(id)
            )
        ''')

        # --- Canary files table ---
        # Tracks the ransomware canary files we have planted.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS canary_files (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path       TEXT UNIQUE,    -- Full path to the canary file
                file_hash       TEXT,           -- SHA256 hash of file contents
                created_date    TEXT,           -- When the canary was planted
                last_verified   TEXT,           -- When we last confirmed it intact
                status          TEXT DEFAULT 'intact'  -- intact / tampered / missing
            )
        ''')

        # --- Window state table ---
        # Remembers the app window size and position between sessions.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS window_state (
                id      INTEGER PRIMARY KEY CHECK (id = 1),  -- Only one row ever
                x       INTEGER DEFAULT 100,    -- Window X position on screen
                y       INTEGER DEFAULT 100,    -- Window Y position on screen
                width   INTEGER DEFAULT 1280,   -- Window width in pixels
                height  INTEGER DEFAULT 800     -- Window height in pixels
            )
        ''')

        # Save all the table creations to disk
        conn.commit()   # Commit = save changes permanently
        conn.close()    # Always close the connection when done


    # =================================================================
    # SETTINGS METHODS
    # =================================================================

    def get_setting(self, key, default=None):
        """
        Retrieves a setting value by its key name.

        Parameters:
            key (str)    : The setting name to look up.
            default      : Value to return if the setting does not exist.

        Returns:
            The setting value as a string, or default if not found.

        Example:
            scan_profile = db.get_setting('scan_profile', 'quick')
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # SELECT the value column WHERE the key matches
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()     # Get the first (and only) matching row

        conn.close()

        # Return the value if found, otherwise return the default
        return row['value'] if row else default


    def set_setting(self, key, value):
        """
        Saves or updates a setting value.

        Uses INSERT OR REPLACE which either:
        - Inserts a new row if the key does not exist, OR
        - Replaces the existing row if the key already exists.
        This way we never have duplicate settings.

        Parameters:
            key (str)  : The setting name.
            value      : The value to save (will be converted to string).
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Get current timestamp for the updated field
        now = datetime.datetime.now().isoformat()

        # INSERT OR REPLACE handles both new and existing settings
        cursor.execute(
            'INSERT OR REPLACE INTO settings (key, value, updated) VALUES (?, ?, ?)',
            (key, str(value), now)  # Convert value to string for storage
        )

        conn.commit()   # Save the change
        conn.close()


    def get_all_settings(self):
        """
        Returns all settings as a dictionary.

        Returns:
            dict: All settings as {key: value} pairs.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT key, value FROM settings')
        rows = cursor.fetchall()    # Get all rows

        conn.close()

        # Convert the list of rows into a dictionary
        return {row['key']: row['value'] for row in rows}


    # =================================================================
    # SCAN HISTORY METHODS
    # =================================================================

    def save_scan(self, scan_type, duration_secs, devices_found,
                  critical_count, warning_count, score, network_name):
        """
        Saves a completed scan to the history database.

        Parameters:
            scan_type     (str) : 'quick', 'standard', or 'deep'
            duration_secs (int) : How many seconds the scan took
            devices_found (int) : Number of devices found
            critical_count(int) : Number of critical findings
            warning_count (int) : Number of warning findings
            score         (int) : Overall score 0-100
            network_name  (str) : Name of the network scanned

        Returns:
            int: The ID of the newly saved scan record.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = datetime.datetime.now().isoformat()   # Current timestamp

        cursor.execute('''
            INSERT INTO scan_history
            (scan_date, scan_type, duration_secs, devices_found,
             critical_count, warning_count, score, network_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (now, scan_type, duration_secs, devices_found,
              critical_count, warning_count, score, network_name))

        scan_id = cursor.lastrowid  # Get the ID of the row we just inserted
        conn.commit()
        conn.close()

        return scan_id  # Return the scan ID so findings can reference it


    def get_scan_history(self, limit=50):
        """
        Retrieves recent scan history records.

        Parameters:
            limit (int): Maximum number of records to return.
                         Defaults to 50 most recent scans.

        Returns:
            list: List of scan history records, newest first.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # ORDER BY scan_date DESC = newest scans first
        # LIMIT = only return this many records
        cursor.execute('''
            SELECT * FROM scan_history
            ORDER BY scan_date DESC
            LIMIT ?
        ''', (limit,))

        rows = cursor.fetchall()
        conn.close()

        # Convert Row objects to regular dictionaries for easier use
        return [dict(row) for row in rows]


    def get_last_scan(self):
        """
        Returns the most recent scan record.

        Returns:
            dict: The most recent scan, or None if no scans exist yet.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM scan_history
            ORDER BY scan_date DESC
            LIMIT 1
        ''')

        row = cursor.fetchone()
        conn.close()

        return dict(row) if row else None


    # =================================================================
    # DEVICE METHODS
    # =================================================================

    def upsert_device(self, mac_address, ip_address, hostname='Unknown',
                      manufacturer='Unknown'):
        """
        Inserts a new device or updates an existing one.

        'Upsert' = Update or Insert. If the MAC address already
        exists in the database, we update its last_seen time and
        current IP. If it is new, we insert a fresh record.

        Parameters:
            mac_address  (str): The device's hardware MAC address (unique ID)
            ip_address   (str): Current IP address on the network
            hostname     (str): Device hostname if available
            manufacturer (str): Manufacturer from OUI database lookup

        Returns:
            int: The device's database ID.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = datetime.datetime.now().isoformat()

        # Try to find the device by its MAC address
        cursor.execute(
            'SELECT id, first_seen FROM devices WHERE mac_address = ?',
            (mac_address,)
        )
        existing = cursor.fetchone()

        if existing:
            # Device already known — update its current info
            cursor.execute('''
                UPDATE devices
                SET ip_address = ?,
                    hostname = ?,
                    manufacturer = ?,
                    last_seen = ?
                WHERE mac_address = ?
            ''', (ip_address, hostname, manufacturer, now, mac_address))
            device_id = existing['id']
        else:
            # New device — insert a fresh record
            cursor.execute('''
                INSERT INTO devices
                (ip_address, mac_address, hostname, manufacturer,
                 first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (ip_address, mac_address, hostname, manufacturer, now, now))
            device_id = cursor.lastrowid   # ID of the newly inserted row

        conn.commit()
        conn.close()

        return device_id


    def set_device_nickname(self, mac_address, nickname):
        """
        Sets or updates the user-assigned nickname for a device.

        Parameters:
            mac_address (str): The device to nickname.
            nickname    (str): The friendly name to assign.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            'UPDATE devices SET nickname = ? WHERE mac_address = ?',
            (nickname, mac_address)
        )

        conn.commit()
        conn.close()


    def set_device_trusted(self, mac_address, trusted):
        """
        Marks a device as trusted or untrusted.

        Parameters:
            mac_address (str) : The device to update.
            trusted     (bool): True = trusted, False = untrusted.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Convert bool to integer (SQLite stores booleans as 0 or 1)
        cursor.execute(
            'UPDATE devices SET trusted = ? WHERE mac_address = ?',
            (1 if trusted else 0, mac_address)
        )

        conn.commit()
        conn.close()


    def get_all_devices(self):
        """
        Returns all known devices from the database.

        Returns:
            list: All device records as dictionaries, sorted by last_seen.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM devices
            ORDER BY last_seen DESC
        ''')

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]


    def get_inactive_devices(self, days=30):
        """
        Returns devices that have not been seen recently.

        Parameters:
            days (int): Number of days of inactivity threshold.
                        Default is 30 days.

        Returns:
            list: Devices not seen in the specified number of days.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Calculate the cutoff date
        cutoff = (datetime.datetime.now() -
                  datetime.timedelta(days=days)).isoformat()

        cursor.execute('''
            SELECT * FROM devices
            WHERE last_seen < ?
            ORDER BY last_seen ASC
        ''', (cutoff,))

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]


    # =================================================================
    # FINDINGS METHODS
    # =================================================================

    def save_finding(self, scan_id, feature_number, severity,
                     title, detail, device_ip='', remediation=''):
        """
        Saves a single security finding from a scan.

        Parameters:
            scan_id        (int): Which scan this finding belongs to.
            feature_number (int): Which of the 101 features found this.
            severity       (str): 'critical', 'warning', 'info', or 'pass'
            title          (str): Short description of the finding.
            detail         (str): Full plain-English explanation.
            device_ip      (str): IP address of affected device (if applicable).
            remediation    (str): How to fix this issue.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO findings
            (scan_id, feature_number, severity, title,
             detail, device_ip, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, feature_number, severity, title,
              detail, device_ip, remediation))

        conn.commit()
        conn.close()


    def get_findings_for_scan(self, scan_id):
        """
        Returns all findings for a specific scan.

        Parameters:
            scan_id (int): The scan ID to retrieve findings for.

        Returns:
            list: All findings for this scan, sorted by severity.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Custom severity ordering: critical first, then warning, info, pass
        cursor.execute('''
            SELECT * FROM findings
            WHERE scan_id = ?
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'warning'  THEN 2
                    WHEN 'info'     THEN 3
                    WHEN 'pass'     THEN 4
                    ELSE 5
                END
        ''', (scan_id,))

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]


    # =================================================================
    # CANARY FILE METHODS
    # =================================================================

    def register_canary(self, file_path, file_hash):
        """
        Registers a newly planted ransomware canary file.

        Parameters:
            file_path (str): Full path to the canary file.
            file_hash (str): SHA256 hash of the file's contents.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = datetime.datetime.now().isoformat()

        cursor.execute('''
            INSERT OR REPLACE INTO canary_files
            (file_path, file_hash, created_date, last_verified, status)
            VALUES (?, ?, ?, ?, 'intact')
        ''', (file_path, file_hash, now, now))

        conn.commit()
        conn.close()


    def get_canary_files(self):
        """
        Returns all registered canary files.

        Returns:
            list: All canary file records as dictionaries.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM canary_files')
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]


    def update_canary_status(self, file_path, status, file_hash=None):
        """
        Updates the status of a canary file after verification.

        Parameters:
            file_path (str): Path to the canary file.
            status    (str): 'intact', 'tampered', or 'missing'
            file_hash (str): Updated hash if file still exists.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = datetime.datetime.now().isoformat()

        if file_hash:
            # Update both status and hash
            cursor.execute('''
                UPDATE canary_files
                SET status = ?, file_hash = ?, last_verified = ?
                WHERE file_path = ?
            ''', (status, file_hash, now, file_path))
        else:
            # Update status only (file may be missing so no hash)
            cursor.execute('''
                UPDATE canary_files
                SET status = ?, last_verified = ?
                WHERE file_path = ?
            ''', (status, now, file_path))

        conn.commit()
        conn.close()


    # =================================================================
    # WINDOW STATE METHODS
    # =================================================================

    def save_window_state(self, x, y, width, height):
        """
        Saves the current window position and size.

        Uses INSERT OR REPLACE with a fixed ID of 1 so there
        is always exactly one row — we only ever need to remember
        one window state at a time.

        Parameters:
            x      (int): Window X position on screen.
            y      (int): Window Y position on screen.
            width  (int): Window width in pixels.
            height (int): Window height in pixels.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # id=1 ensures there is only ever one window state row
        cursor.execute('''
            INSERT OR REPLACE INTO window_state (id, x, y, width, height)
            VALUES (1, ?, ?, ?, ?)
        ''', (x, y, width, height))

        conn.commit()
        conn.close()


    def get_window_state(self):
        """
        Retrieves the saved window position and size.

        Returns:
            dict: Window state with x, y, width, height keys.
                  Returns sensible defaults if no state has been saved yet.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM window_state WHERE id = 1')
        row = cursor.fetchone()
        conn.close()

        if row:
            return dict(row)    # Return saved state
        else:
            # No saved state yet — return defaults
            return {'x': 100, 'y': 100, 'width': 1280, 'height': 800}
