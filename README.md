Amcache Parser
Amcache Parser is a command-line tool for parsing Windows Amcache.hve registry hives, extracting forensic data from live systems or offline hive files, and storing results in SQLite, JSON, or CSV formats.

Parse Amcache.hve: Extracts data from InventoryApplication, InventoryApplicationFile, InventoryDriverBinary, and other subkeys.
Output Formats: Saves data to SQLite (default), JSON, or CSV.
Date Conversion: Converts timestamps (e.g., InstallDate, LinkDate) to ISO 8601 format for timeline analysis.
Virtual Environment: Automatically sets up a virtual environment for dependencies.


Requirements

Operating System: Windows 7 or later (live analysis requires admin privileges).
Python: Version 3.7 or higher (tested with Python 3.12).
Dependencies:
python-registry: For parsing registry hives.
tqdm: For progress bars during parsing.
Automatically installed in a virtual environment.









Ensure Python 3.12 is installed:C:/Users/<YourUsername>/AppData/Local/Microsoft/WindowsApps/python3.12.exe --version


If not installed, download from python.org.


Run the Script:

The script creates a virtual environment (C:\Amcache\venv_amcache_parser) and installs dependencies automatically on first run.



Usage
Non-Interactive Mode
Run the script with command-line arguments for automated parsing:
C:/Users/<YourUsername>/AppData/Local/Microsoft/WindowsApps/python3.12.exe "C:\Amcache\amcache_parser.py" --offline "E:\Crow Eye research\Amcache.hve" --output json --search-keys "InventoryApplication,InventoryApplicationFile" --output-path "C:\Amcache" --filter-language "1033" --non-interactive

Options:

--live: Parse the live Amcache.hve (C:\Windows\AppCompat\Programs\Amcache.hve). Requires admin privileges.
--offline <path>: Parse an offline Amcache.hve file.
--output <format>: Output format (sqlite, json, csv). Default: sqlite.
--output-path <path>: Output directory for database, JSON, CSV, logs, and summary. Default: C:\Amcache.
--search-keys <keys>: Comma-separated subkeys to parse (e.g., InventoryApplication,InventoryApplicationFile).
--filter-language <language>: Filter entries by LCID or language name (e.g., 1033, English (United States)).
--non-interactive: Run without the interactive menu.



Note: For live analysis, run as administrator:


Interactive Mode
Run the script and follow the menu prompts:
C:/Users/<YourUsername>/AppData/Local/Microsoft/WindowsApps/python3.12.exe "C:\Amcache\amcache_parser.py"


Select 1 for live analysis (requires admin privileges).
Select 2 to specify an offline Amcache.hve file.
Select 3 to change the output format.
Select 4 to exit.

Outputs
All outputs are saved to the specified --output-path (default: C:\Amcache).

SQLite: amcache-offline.db

Structured tables for InventoryApplication, InventoryApplicationFile, InventoryDriverBinary.
Generic data column for other subkeys.
Example queries:sqlite3 "C:\Amcache\amcache-offline.db" "SELECT Language, LanguageName, Name FROM InventoryApplication WHERE LanguageName = 'English (United States)' LIMIT 5;"
sqlite3 "C:\Amcache\amcache-offline.db" "SELECT LowerCaseLongPath, FileHash FROM InventoryApplicationFile LIMIT 5;"
sqlite3 "C:\Amcache\amcache-offline.db" "SELECT InstallDate, Name FROM InventoryApplication ORDER BY InstallDate DESC LIMIT 5;"




JSON: amcache-offline.json

Structured JSON with subkey entries, including LanguageName and FileHash.


CSV: amcache-offline.csv

Flat CSV with columns for all supported fields, including LanguageName and FileHash.


Summary: amcache-offline_summary.txt

Summary of parsed data (entry counts, unique languages, date ranges).
Example:Amcache Parser Summary - 2025-07-19T00:29:00.000000+00:00
==================================================
Subkey: InventoryApplication, Entries: 100
Subkey: InventoryApplicationFile, Entries: 500
Subkey: InventoryDriverBinary, Entries: 50
Unique Languages: 5
  - 1033: English (United States)
  - 1049: Russian (Russia)
  ...
Install Date Range: 2024-01-27T00:00:00Z to 2025-07-18T00:00:00Z




Log: amcache_parser.log

Detailed logs for debugging and error tracking.
Check errors:type "C:\Amcache\amcache_parser.log" | findstr "ERROR"





LCID Mapping
The lcid_mapping.json file maps LCIDs to language names. Update it to add new LCIDs:
{
  "1033": "English (United States)",
  "2057": "English (United Kingdom)",
  ...
}

If the file is missing, a default mapping is used. Save it to C:\Amcache\lcid_mapping.json.
Troubleshooting

Permission Errors: Run as administrator for live analysis or ensure read access to offline hives.
Corrupted Hive: If parsing fails, check amcache_parser.log for details..
Missing Dependencies: The script installs python-registry and tqdm automatically. Check the virtual environment:C:\Amcache\venv_amcache_parser\Scripts\python.exe -m pip list




License
This project is licensed under the GNU General Public License v3.0. See LICENSE for details.
Author : Ghassan elsman
Version : 1 (July 2025)

