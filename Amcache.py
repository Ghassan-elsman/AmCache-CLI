
"""

Version: 1
"""

import ctypes
import os
from platform import system, version
import sys
import sqlite3
import json
import csv
import logging
import argparse
from pathlib import Path
from typing import List, Optional
import subprocess
import time
from datetime import datetime, timezone

LOGO = """
═══════════════════════════════════════════════════════════════════
 ██████╗██████╗  ██████╗ ██╗    ██╗      ███████╗██╗   ██╗███████╗
██╔════╝██╔══██╗██╔═══██╗██║    ██║      ██╔════╝╚██╗ ██╔╝██╔════╝
██║     ██████╔╝██║   ██║██║ █╗ ██║█████╗█████╗   ╚████╔╝ █████╗  
██║     ██╔══██╗██║   ██║██║███╗██║╚════╝██╔══╝    ╚██╔╝  ██╔══╝  
╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝      ███████╗   ██║   ███████╗
 ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝       ╚══════╝   ╚═╝   ╚══════╝
                  [ CROW-EYE AMCACHE ANALYZER ]
═══════════════════════════════════════════════════════════════════
"""

# Configuration defaults
DEFAULT_DATABASE_PATH = r"C:\Amcache\amcache.db"
DEFAULT_LIVE_PATH = r"C:\Windows\AppCompat\Programs\Amcache.hve"

# LCID to Language Name mapping
LCID_TO_LANGUAGE = {
    1033: "English (United States)",
    2057: "English (United Kingdom)",
    3082: "Spanish (Spain, Modern Sort)",
    1036: "French (France)",
    1031: "German (Germany)",
    1049: "Russian (Russia)",
    2052: "Chinese (Simplified, China)",
    1028: "Chinese (Traditional, Taiwan)",
    1041: "Japanese (Japan)",
    1042: "Korean (Korea)",
    1030: "Danish (Denmark)",
    1040: "Italian (Italy)",
    1035: "Finnish (Finland)",
    1032: "Greek (Greece)",
    1043: "Dutch (Netherlands)",
    2067: "Dutch (Belgium)",
    2070: "Portuguese (Portugal)",
    1046: "Portuguese (Brazil)",
    1053: "Swedish (Sweden)",
    1054: "Thai (Thailand)",
    1055: "Turkish (Turkey)",
    1029: "Czech (Czech Republic)",
    1038: "Hungarian (Hungary)",
    1045: "Polish (Poland)",
    1060: "Slovenian (Slovenia)",
    1058: "Ukrainian (Ukraine)",
    1066: "Vietnamese (Vietnam)",
    1025: "Arabic (Saudi Arabia)",
    1037: "Hebrew (Israel)",
    1069: "Basque (Basque)",
    1027: "Catalan (Catalan)",
    1110: "Galician (Galician)",
    1034: "Spanish (Traditional Sort)",
    3081: "English (Australia)",
    4105: "English (Canada)",
    1039: "Icelandic (Iceland)",
    1044: "Norwegian (Bokmål, Norway)",
    2068: "Norwegian (Nynorsk, Norway)",
    1057: "Indonesian (Indonesia)",
    1081: "Hindi (India)",
    1038: "Malay (Malaysia)",
    1086: "Malay (Brunei)",
    1051: "Slovak (Slovakia)",
    1061: "Estonian (Estonia)",
    1062: "Latvian (Latvia)",
    1063: "Lithuanian (Lithuania)",
    1091: "Uzbek (Latin, Uzbekistan)",
    1092: "Tatar (Russia)",
    1093: "Bengali (India)",
    1102: "Marathi (India)"
}

# Windows API definitions
_TOKEN_ADJUST_PRIVILEGES = 0x20
_SE_PRIVILEGE_ENABLED = 0x2
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_CREATE_ALWAYS = 2
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_ATTRIBUTE_TEMPORARY = 0x100
_FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
_FILE_SHARE_READ = 1
_FILE_SHARE_WRITE = 2
_FILE_SHARE_DELETE = 4
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_KEY_READ = 0x20019
_KEY_WOW64_64KEY = 0x100
_STATUS_INVALID_PARAMETER = ctypes.c_int32(0xC000000D).value
_REG_NO_COMPRESSION = 4
_INVALID_SET_FILE_POINTER = 0xFFFFFFFF
_HKEY_LOCAL_MACHINE = 0x80000002

class _LUID(ctypes.Structure):
    _fields_ = [('LowPart', ctypes.c_uint32), ('HighPart', ctypes.c_int32)]

class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Luid', _LUID), ('Attributes', ctypes.c_uint32)]

class _TOKEN_PRIVILEGES_5(ctypes.Structure):
    _fields_ = [('PrivilegeCount', ctypes.c_uint32), ('Privilege0', _LUID_AND_ATTRIBUTES),
                ('Privilege1', _LUID_AND_ATTRIBUTES), ('Privilege2', _LUID_AND_ATTRIBUTES),
                ('Privilege3', _LUID_AND_ATTRIBUTES), ('Privilege4', _LUID_AND_ATTRIBUTES)]

# Windows API function definitions
ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
ctypes.windll.kernel32.GetCurrentProcess.argtypes = []
ctypes.windll.advapi32.LookupPrivilegeValueW.restype = ctypes.c_int32
ctypes.windll.advapi32.LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
ctypes.windll.advapi32.OpenProcessToken.restype = ctypes.c_int32
ctypes.windll.advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
ctypes.windll.advapi32.AdjustTokenPrivileges.restype = ctypes.c_int32
ctypes.windll.advapi32.AdjustTokenPrivileges.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
ctypes.windll.kernel32.GetLastError.restype = ctypes.c_uint32
ctypes.windll.kernel32.GetLastError.argtypes = []
ctypes.windll.kernel32.CloseHandle.restype = ctypes.c_int32
ctypes.windll.kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
ctypes.windll.kernel32.CreateFileW.restype = ctypes.c_void_p
ctypes.windll.kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
ctypes.windll.advapi32.RegOpenKeyExW.restype = ctypes.c_int32
ctypes.windll.advapi32.RegOpenKeyExW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
ctypes.windll.advapi32.RegCloseKey.restype = ctypes.c_int32
ctypes.windll.advapi32.RegCloseKey.argtypes = [ctypes.c_void_p]
ctypes.windll.ntdll.NtSaveKeyEx.restype = ctypes.c_int32
ctypes.windll.ntdll.NtSaveKeyEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
ctypes.windll.kernel32.GetTempFileNameA.restype = ctypes.c_uint32
ctypes.windll.kernel32.GetTempFileNameA.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_void_p]
ctypes.windll.kernel32.SetFilePointer.restype = ctypes.c_uint32
ctypes.windll.kernel32.SetFilePointer.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32]
ctypes.windll.kernel32.ReadFile.restype = ctypes.c_int32
ctypes.windll.kernel32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]

_APP_HIVES_SUPPORTED = hasattr(ctypes.windll.advapi32, 'RegLoadAppKeyW')
if _APP_HIVES_SUPPORTED:
    ctypes.windll.advapi32.RegLoadAppKeyW.restype = ctypes.c_int32
    ctypes.windll.advapi32.RegLoadAppKeyW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]

def ensure_venv_and_relaunch():
    """Ensure virtual environment exists and relaunch script in it if not active."""
    logging.basicConfig(
        filename=r'C:\Amcache\amcache_parser.log',
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    script_dir = Path(__file__).parent.absolute()
    venv_path = script_dir / "venv_amcache_parser"
    python_exe = sys.executable

    if os.environ.get('VIRTUAL_ENV') or sys.prefix != sys.base_prefix:
        logging.debug(f"Running in virtual environment: {sys.prefix}")
        return

    venv_path_str = os.path.normpath(str(venv_path))
    python_exe = os.path.normpath(python_exe)
    venv_python = os.path.normpath(os.path.join(venv_path_str, "Scripts" if os.name == 'nt' else "bin", "python.exe" if os.name == 'nt' else "python"))

    if not os.path.exists(venv_python):
        print(f"Creating virtual environment at {venv_path_str}...")
        logging.debug(f"Creating virtual environment at {venv_path_str}")
        try:
            subprocess.check_call([python_exe, "-m", "venv", venv_path_str])
            print(f"✓ Virtual environment created at {venv_path_str}")
            logging.debug(f"Virtual environment created at {venv_path_str}")
            print("Updating pip in virtual environment...")
            subprocess.check_call([venv_python, "-m", "pip", "install", "--upgrade", "pip"])
            print("✓ Pip updated successfully")
            logging.debug("Pip updated successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create virtual environment or update pip: {e}")
            logging.error(f"Failed to create virtual environment or update pip: {e}")
            sys.exit(1)

    print(f"Relaunching script in virtual environment: {venv_python}")
    logging.debug(f"Relaunching script in virtual environment: {venv_python}")
    try:
        new_env = os.environ.copy()
        new_env['VIRTUAL_ENV'] = venv_path_str
        new_env['PATH'] = os.path.join(venv_path_str, "Scripts" if os.name == 'nt' else "bin") + os.pathsep + new_env['PATH']
        cmd = [venv_python, os.path.normpath(sys.argv[0])] + sys.argv[1:]
        os.execvpe(venv_python, cmd, new_env)
    except Exception as e:
        print(f"❌ Failed to relaunch in virtual environment: {e}")
        logging.error(f"Failed to relaunch in virtual environment: {e}")
        sys.exit(1)

def check_and_install_packages():
    """Check for required packages and install in virtual environment if missing."""
    required_packages = ['python-registry', 'tqdm']
    for package in required_packages:
        try:
            __import__(package)
            logging.debug(f"Package {package} already installed")
        except ImportError:
            print(f"Installing {package} in virtual environment...")
            logging.debug(f"Installing {package} in virtual environment")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"✓ Successfully installed {package}")
                logging.debug(f"Successfully installed {package}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install {package}: {e}")
                logging.error(f"Failed to install {package}: {e}")
                sys.exit(1)

ensure_venv_and_relaunch()
check_and_install_packages()
from Registry import Registry
from tqdm import tqdm

def is_admin() -> bool:
    """Check if the script is running with administrative privileges."""
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

class NTFileLikeObject:
    def __init__(self, handle):
        self.handle = handle
        self.max_size = self.seek(0, 2)
        self.seek(0, 0)

    def seek(self, offset, whence=0):
        offset = ctypes.windll.kernel32.SetFilePointer(self.handle, offset, None, whence)
        if offset == _INVALID_SET_FILE_POINTER:
            raise OSError('The SetFilePointer() routine failed')
        return offset

    def tell(self):
        return self.seek(0, 1)

    def read(self, size=None):
        if size is None or size < 0:
            size = self.max_size - self.tell()
        if size <= 0:
            return b''
        buffer = ctypes.create_string_buffer(size)
        size_out = ctypes.c_uint32()
        result = ctypes.windll.kernel32.ReadFile(self.handle, ctypes.byref(buffer), size, ctypes.byref(size_out), None)
        if result == 0:
            last_error = ctypes.windll.kernel32.GetLastError()
            raise OSError(f'The ReadFile() routine failed with status: {last_error}')
        return buffer.raw[:size_out.value]

    def close(self):
        ctypes.windll.kernel32.CloseHandle(self.handle)

class RegistryHivesLive:
    def __init__(self):
        self._src_handle = None
        self._dst_handle = None
        self._lookup_process_handle_and_backup_privilege()
        self._acquire_backup_privilege()

    def _lookup_process_handle_and_backup_privilege(self):
        self._proc = ctypes.windll.kernel32.GetCurrentProcess()
        self._backup_luid = _LUID()
        result = ctypes.windll.advapi32.LookupPrivilegeValueW(None, 'SeBackupPrivilege', ctypes.byref(self._backup_luid))
        if result == 0:
            raise OSError('The LookupPrivilegeValueW() routine failed to resolve the \'SeBackupPrivilege\' name')

    def _acquire_backup_privilege(self):
        handle = ctypes.c_void_p()
        result = ctypes.windll.advapi32.OpenProcessToken(self._proc, _TOKEN_ADJUST_PRIVILEGES, ctypes.byref(handle))
        if result == 0:
            raise OSError('The OpenProcessToken() routine failed to provide TOKEN_ADJUST_PRIVILEGES access')
        tp = _TOKEN_PRIVILEGES_5()
        tp.PrivilegeCount = 1
        tp.Privilege0 = _LUID_AND_ATTRIBUTES()
        tp.Privilege0.Luid = self._backup_luid
        tp.Privilege0.Attributes = _SE_PRIVILEGE_ENABLED
        result_1 = ctypes.windll.advapi32.AdjustTokenPrivileges(handle, False, ctypes.byref(tp), 0, None, None)
        result_2 = ctypes.windll.kernel32.GetLastError()
        if result_1 == 0 or result_2 != 0:
            ctypes.windll.kernel32.CloseHandle(handle)
            raise OSError('The AdjustTokenPrivileges() routine failed to set the backup privilege')
        ctypes.windll.kernel32.CloseHandle(handle)

    def _create_destination_handle(self, FilePath):
        if FilePath is None:
            file_attr = _FILE_ATTRIBUTE_TEMPORARY | _FILE_FLAG_DELETE_ON_CLOSE
            FilePath = self._temp_file()
        else:
            file_attr = _FILE_ATTRIBUTE_NORMAL
        handle = ctypes.windll.kernel32.CreateFileW(FilePath, _GENERIC_READ | _GENERIC_WRITE, _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE, None, _CREATE_ALWAYS, file_attr, None)
        if handle == _INVALID_HANDLE_VALUE:
            raise OSError('The CreateFileW() routine failed to create a file')
        self._dst_handle = handle
        return FilePath

    def _close_destination_handle(self):
        if self._dst_handle:
            ctypes.windll.kernel32.CloseHandle(self._dst_handle)
            self._dst_handle = None

    def _open_root_key(self, PredefinedKey, KeyPath, WOW64=False):
        handle = ctypes.c_void_p()
        access_rights = _KEY_READ | (_KEY_WOW64_64KEY if WOW64 else 0)
        result = ctypes.windll.advapi32.RegOpenKeyExW(PredefinedKey, KeyPath, 0, access_rights, ctypes.byref(handle))
        if result != 0:
            raise OSError(f'The RegOpenKeyExW() routine failed to open key: {KeyPath}')
        self._src_handle = handle

    def _load_application_hive(self, HivePath):
        if not _APP_HIVES_SUPPORTED:
            raise OSError('Application hives are not supported on this system')
        handle = ctypes.c_void_p()
        result = ctypes.windll.advapi32.RegLoadAppKeyW(HivePath, ctypes.byref(handle), _KEY_READ, 0, 0)
        if result != 0:
            raise OSError(f'The RegLoadAppKeyW() routine failed to load hive: {HivePath}')
        self._src_handle = handle

    def _close_root_key(self):
        if self._src_handle:
            ctypes.windll.advapi32.RegCloseKey(self._src_handle)
            self._src_handle = None

    def _do_container_check(self, file_object):
        signature = file_object.read(4)
        if signature != b'regf':
            raise OSError('The exported hive is invalid')
        seq_1 = file_object.read(4)
        seq_2 = file_object.read(4)
        if seq_1 == seq_2 == b'\x01\x00\x00\x00':
            print('It seems that you run this script from inside of a container', file=sys.stderr)
        file_object.seek(0, 0)

    def open_apphive_by_file(self, AppHivePath, FilePath=None):
        if self._src_handle is not None:
            self._close_root_key()
        if self._dst_handle is not None:
            self._close_destination_handle()
        FilePath = self._create_destination_handle(FilePath)
        try:
            self._load_application_hive(AppHivePath)
        except Exception:
            self._close_destination_handle()
            raise
        result = ctypes.windll.ntdll.NtSaveKeyEx(self._src_handle, self._dst_handle, _REG_NO_COMPRESSION)
        if result != 0:
            self._close_root_key()
            self._close_destination_handle()
            raise OSError(f'The NtSaveKeyEx() routine failed with status: {hex(result)}')
        self._close_root_key()
        f = NTFileLikeObject(self._dst_handle)
        self._do_container_check(f)
        return f

    def _temp_file(self):
        buffer = ctypes.create_string_buffer(513)
        result = ctypes.windll.kernel32.GetTempFileNameA(b'.', b'hiv', 0, ctypes.byref(buffer))
        if result == 0:
            raise OSError('The GetTempFileNameA() routine failed to create a temporary file')
        return buffer.value.decode()

class AmcacheParser:
    def __init__(self, file_path: str, db_path: str, output_format: str = 'sqlite', search_keys: Optional[List[str]] = None):
        self.file_path = file_path
        self.db_path = db_path
        self.output_format = output_format.lower()
        self.search_keys = search_keys
        self.entries = []
        self.failed_parses = 0
        self.analysis_time = datetime.now(tz=timezone.utc)
        self.handle = self._load_hive_with_retry()
        self._init_database()

    def _load_hive_with_retry(self, retries: int = 3) -> NTFileLikeObject:
        """Attempt to load the Amcache hive with retries."""
        for attempt in range(retries):
            try:
                handle = RegistryHivesLive().open_apphive_by_file(self.file_path)
                print(f"✓ Successfully loaded hive: {self.file_path}")
                logging.debug(f"Loaded hive: {self.file_path}")
                return handle
            except OSError as e:
                print(f"⚠️ Attempt {attempt + 1}/{retries} failed to load hive: {e}")
                logging.error(f"Attempt {attempt + 1}/{retries} failed to load hive: {e}")
                if attempt == retries - 1:
                    print(f"❌ Max retries reached for {self.file_path}. Ensure the file is a valid Amcache.hve and you have sufficient permissions.")
                    logging.error("Max retries reached")
                    sys.exit(1)
                time.sleep(1)
        return None

    def _init_database(self):
        """Initialize SQLite database with a table to track subkeys."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS subkeys (
                        subkey_name TEXT PRIMARY KEY,
                        parsed_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
            print(f"✓ Database initialized: {self.db_path}")
            logging.debug(f"Database initialized: {self.db_path}")
        except sqlite3.OperationalError as e:
            print(f"❌ Database initialization failed: {e}")
            logging.error(f"Database initialization failed: {e}")
            sys.exit(1)

    def _create_table_for_subkey(self, subkey_name: str):
        """Create a table for a specific subkey with appropriate columns."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                safe_table_name = subkey_name.replace("-", "_").replace(" ", "_")
                if subkey_name == "InventoryApplicationFile":
                    cursor.execute(f"""
                        CREATE TABLE IF NOT EXISTS {safe_table_name} (
                            entry_id TEXT PRIMARY KEY,
                            ProgramId TEXT,
                            FileId TEXT,
                            LowerCaseLongPath TEXT,
                            Name TEXT,
                            OriginalFileName TEXT,
                            Publisher TEXT,
                            Version TEXT,
                            BinFileVersion TEXT,
                            BinaryType TEXT,
                            ProductName TEXT,
                            ProductVersion TEXT,
                            LinkDate TEXT,
                            BinProductVersion TEXT,
                            Size TEXT,
                            Language TEXT,
                            LanguageName TEXT,
                            Usn TEXT,
                            parsed_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                elif subkey_name == "InventoryApplication":
                    cursor.execute(f"""
                        CREATE TABLE IF NOT EXISTS {safe_table_name} (
                            entry_id TEXT PRIMARY KEY,
                            ProgramId TEXT,
                            ProgramInstanceId TEXT,
                            Name TEXT,
                            Version TEXT,
                            Publisher TEXT,
                            Language TEXT,
                            LanguageName TEXT,
                            InstallDate TEXT,
                            Source TEXT,
                            RootDirPath TEXT,
                            HiddenArp TEXT,
                            UninstallString TEXT,
                            RegistryKeyPath TEXT,
                            MsiPackageCode TEXT,
                            MsiProductCode TEXT,
                            MsiInstallDate TEXT,
                            DefaultValue TEXT,
                            parsed_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                else:
                    cursor.execute(f"""
                        CREATE TABLE IF NOT EXISTS {safe_table_name} (
                            entry_id TEXT PRIMARY KEY,
                            data TEXT NOT NULL,
                            parsed_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                cursor.execute("INSERT OR IGNORE INTO subkeys (subkey_name) VALUES (?)", (subkey_name,))
                conn.commit()
            logging.debug(f"Created table for subkey: {subkey_name}")
        except sqlite3.OperationalError as e:
            print(f"❌ Failed to create table for subkey {subkey_name}: {e}")
            logging.error(f"Failed to create table for subkey {subkey_name}: {e}")
            sys.exit(1)

    def _check_entry_exists(self, subkey_name: str, entry_id: str) -> bool:
        """Check if an entry exists in the specified subkey table."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                safe_table_name = subkey_name.replace("-", "_").replace(" ", "_")
                cursor.execute(f"SELECT 1 FROM {safe_table_name} WHERE entry_id = ?", (entry_id,))
                return cursor.fetchone() is not None
        except sqlite3.OperationalError as e:
            logging.error(f"Error checking entry in {subkey_name}: {e}")
            return False

    def _insert_entry(self, subkey_name: str, entry_id: str, data: dict):
        """Insert a new entry into the specified subkey table."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                safe_table_name = subkey_name.replace("-", "_").replace(" ", "_")
                language_value = data.get("Language")
                language_name = LCID_TO_LANGUAGE.get(int(language_value), "Unknown") if language_value and language_value.isdigit() else "Unknown"
                if subkey_name == "InventoryApplicationFile":
                    cursor.execute(f"""
                        INSERT INTO {safe_table_name} (
                            entry_id, ProgramId, FileId, LowerCaseLongPath, Name, OriginalFileName,
                            Publisher, Version, BinFileVersion, BinaryType, ProductName,
                            ProductVersion, LinkDate, BinProductVersion, Size, Language, LanguageName, Usn
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        entry_id,
                        data.get("ProgramId"),
                        data.get("FileId"),
                        data.get("LowerCaseLongPath"),
                        data.get("Name"),
                        data.get("OriginalFileName"),
                        data.get("Publisher"),
                        data.get("Version"),
                        data.get("BinFileVersion"),
                        data.get("BinaryType"),
                        data.get("ProductName"),
                        data.get("ProductVersion"),
                        data.get("LinkDate"),
                        data.get("BinProductVersion"),
                        data.get("Size"),
                        data.get("Language"),
                        language_name,
                        data.get("Usn")
                    ))
                elif subkey_name == "InventoryApplication":
                    cursor.execute(f"""
                        INSERT INTO {safe_table_name} (
                            entry_id, ProgramId, ProgramInstanceId, Name, Version, Publisher,
                            Language, LanguageName, InstallDate, Source, RootDirPath, HiddenArp,
                            UninstallString, RegistryKeyPath, MsiPackageCode, MsiProductCode,
                            MsiInstallDate, DefaultValue
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        entry_id,
                        data.get("ProgramId"),
                        data.get("ProgramInstanceId"),
                        data.get("Name"),
                        data.get("Version"),
                        data.get("Publisher"),
                        data.get("Language"),
                        language_name,
                        data.get("InstallDate"),
                        data.get("Source"),
                        data.get("RootDirPath"),
                        data.get("HiddenArp"),
                        data.get("UninstallString"),
                        data.get("RegistryKeyPath"),
                        data.get("MsiPackageCode"),
                        data.get("MsiProductCode"),
                        data.get("MsiInstallDate"),
                        data.get("(default)")
                    ))
                else:
                    cursor.execute(f"""
                        INSERT INTO {safe_table_name} (entry_id, data)
                        VALUES (?, ?)
                    """, (entry_id, json.dumps(data)))
                conn.commit()
            logging.debug(f"Inserted entry {entry_id} into {subkey_name}")
        except sqlite3.OperationalError as e:
            print(f"❌ Failed to insert entry {entry_id} into {subkey_name}: {e}")
            logging.error(f"Failed to insert entry {entry_id} into {subkey_name}: {e}")
            self.failed_parses += 1

    def _save_to_json(self, output_path: str):
        """Save parsed entries to a JSON file with LanguageName."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT subkey_name FROM subkeys")
                subkeys = [row[0] for row in cursor.fetchall()]
                data = {}
                for subkey in subkeys:
                    safe_table_name = subkey.replace("-", "_").replace(" ", "_")
                    if subkey == "InventoryApplicationFile":
                        cursor.execute(f"""
                            SELECT entry_id, ProgramId, FileId, LowerCaseLongPath, Name, OriginalFileName,
                                   Publisher, Version, BinFileVersion, BinaryType, ProductName,
                                   ProductVersion, LinkDate, BinProductVersion, Size, Language, LanguageName, Usn
                            FROM {safe_table_name}
                        """)
                        entries = [
                            {
                                "entry_id": row[0],
                                "data": {
                                    "ProgramId": row[1],
                                    "FileId": row[2],
                                    "LowerCaseLongPath": row[3],
                                    "Name": row[4],
                                    "OriginalFileName": row[5],
                                    "Publisher": row[6],
                                    "Version": row[7],
                                    "BinFileVersion": row[8],
                                    "BinaryType": row[9],
                                    "ProductName": row[10],
                                    "ProductVersion": row[11],
                                    "LinkDate": row[12],
                                    "BinProductVersion": row[13],
                                    "Size": row[14],
                                    "Language": row[15],
                                    "LanguageName": row[16],
                                    "Usn": row[17]
                                }
                            } for row in cursor.fetchall()
                        ]
                    elif subkey == "InventoryApplication":
                        cursor.execute(f"""
                            SELECT entry_id, ProgramId, ProgramInstanceId, Name, Version, Publisher,
                                   Language, LanguageName, InstallDate, Source, RootDirPath, HiddenArp,
                                   UninstallString, RegistryKeyPath, MsiPackageCode, MsiProductCode,
                                   MsiInstallDate, DefaultValue
                            FROM {safe_table_name}
                        """)
                        entries = [
                            {
                                "entry_id": row[0],
                                "data": {
                                    "ProgramId": row[1],
                                    "ProgramInstanceId": row[2],
                                    "Name": row[3],
                                    "Version": row[4],
                                    "Publisher": row[5],
                                    "Language": row[6],
                                    "LanguageName": row[7],
                                    "InstallDate": row[8],
                                    "Source": row[9],
                                    "RootDirPath": row[10],
                                    "HiddenArp": row[11],
                                    "UninstallString": row[12],
                                    "RegistryKeyPath": row[13],
                                    "MsiPackageCode": row[14],
                                    "MsiProductCode": row[15],
                                    "MsiInstallDate": row[16],
                                    "(default)": row[17]
                                }
                            } for row in cursor.fetchall()
                        ]
                    else:
                        cursor.execute(f"SELECT entry_id, data FROM {safe_table_name}")
                        entries = [{"entry_id": row[0], "data": json.loads(row[1])} for row in cursor.fetchall()]
                    data[subkey] = entries
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"✓ Saved {len(data)} subkeys to JSON: {output_path}")
            logging.debug(f"Saved {len(data)} subkeys to JSON: {output_path}")
        except Exception as e:
            print(f"❌ Failed to save JSON: {e}")
            logging.error(f"Failed to save JSON to {output_path}: {e}")

    def _save_to_csv(self, output_path: str):
        """Save parsed entries to a CSV file with LanguageName."""
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT subkey_name FROM subkeys")
                    subkeys = [row[0] for row in cursor.fetchall()]
                    headers = [
                        'subkey_name', 'entry_id', 'ProgramId', 'ProgramInstanceId', 'FileId', 'LowerCaseLongPath',
                        'Name', 'OriginalFileName', 'Publisher', 'Version', 'BinFileVersion', 'BinaryType',
                        'ProductName', 'ProductVersion', 'LinkDate', 'BinProductVersion', 'Size', 'Language',
                        'LanguageName', 'Usn', 'InstallDate', 'Source', 'RootDirPath', 'HiddenArp', 'UninstallString',
                        'RegistryKeyPath', 'MsiPackageCode', 'MsiProductCode', 'MsiInstallDate', 'DefaultValue'
                    ]
                    writer = csv.DictWriter(f, fieldnames=headers)
                    writer.writeheader()
                    for subkey in subkeys:
                        safe_table_name = subkey.replace("-", "_").replace(" ", "_")
                        if subkey == "InventoryApplicationFile":
                            cursor.execute(f"""
                                SELECT entry_id, ProgramId, FileId, LowerCaseLongPath, Name, OriginalFileName,
                                       Publisher, Version, BinFileVersion, BinaryType, ProductName,
                                       ProductVersion, LinkDate, BinProductVersion, Size, Language, LanguageName, Usn
                                FROM {safe_table_name}
                            """)
                            for row in cursor.fetchall():
                                writer.writerow({
                                    'subkey_name': subkey,
                                    'entry_id': row[0],
                                    'ProgramId': row[1],
                                    'FileId': row[2],
                                    'LowerCaseLongPath': row[3],
                                    'Name': row[4],
                                    'OriginalFileName': row[5],
                                    'Publisher': row[6],
                                    'Version': row[7],
                                    'BinFileVersion': row[8],
                                    'BinaryType': row[9],
                                    'ProductName': row[10],
                                    'ProductVersion': row[11],
                                    'LinkDate': row[12],
                                    'BinProductVersion': row[13],
                                    'Size': row[14],
                                    'Language': row[15],
                                    'LanguageName': row[16],
                                    'Usn': row[17]
                                })
                        elif subkey == "InventoryApplication":
                            cursor.execute(f"""
                                SELECT entry_id, ProgramId, ProgramInstanceId, Name, Version, Publisher,
                                       Language, LanguageName, InstallDate, Source, RootDirPath, HiddenArp,
                                       UninstallString, RegistryKeyPath, MsiPackageCode, MsiProductCode,
                                       MsiInstallDate, DefaultValue
                                FROM {safe_table_name}
                            """)
                            for row in cursor.fetchall():
                                writer.writerow({
                                    'subkey_name': subkey,
                                    'entry_id': row[0],
                                    'ProgramId': row[1],
                                    'ProgramInstanceId': row[2],
                                    'Name': row[3],
                                    'Version': row[4],
                                    'Publisher': row[5],
                                    'Language': row[6],
                                    'LanguageName': row[7],
                                    'InstallDate': row[8],
                                    'Source': row[9],
                                    'RootDirPath': row[10],
                                    'HiddenArp': row[11],
                                    'UninstallString': row[12],
                                    'RegistryKeyPath': row[13],
                                    'MsiPackageCode': row[14],
                                    'MsiProductCode': row[15],
                                    'MsiInstallDate': row[16],
                                    'DefaultValue': row[17]
                                })
                        else:
                            cursor.execute(f"SELECT entry_id, data FROM {safe_table_name}")
                            for row in cursor.fetchall():
                                writer.writerow({
                                    'subkey_name': subkey,
                                    'entry_id': row[0],
                                    'data': row[1]
                                })
            print(f"✓ Saved entries to CSV: {output_path}")
            logging.debug(f"Saved entries to CSV: {output_path}")
        except Exception as e:
            print(f"❌ Failed to save CSV: {e}")
            logging.error(f"Failed to save CSV to {output_path}: {e}")

    def parse(self):
        """Parse the Amcache hive and store results."""
        try:
            r = Registry.Registry(self.handle)
            root = r.open("Root")
            root_subkeys = root.subkeys()
            total_subkeys = len(root_subkeys)
            print(f"🔍 Found {total_subkeys} subkeys to parse")
            logging.debug(f"Found {total_subkeys} subkeys to parse")

            with tqdm(total=total_subkeys, desc="Parsing Subkeys", unit="subkey") as pbar:
                for subkey in root_subkeys:
                    subkey_name = subkey.name()
                    if self.search_keys and subkey_name not in self.search_keys:
                        pbar.update(1)
                        continue
                    self._create_table_for_subkey(subkey_name)
                    subkey_entries = subkey.subkeys()
                    for key in subkey_entries:
                        key_name = key.name()
                        values_dict = {value.name(): str(value.value()) for value in key.values()}
                        if not self._check_entry_exists(subkey_name, key_name):
                            self._insert_entry(subkey_name, key_name, values_dict)
                            self.entries.append({
                                'subkey_name': subkey_name,
                                'entry_id': key_name,
                                'data': values_dict
                            })
                        pbar.update(1)

            print(f"✓ Parsed {len(self.entries)} entries, {self.failed_parses} failed")
            logging.debug(f"Parsed {len(self.entries)} entries, {self.failed_parses} failed")

            if self.output_format == 'json':
                self._save_to_json(self.db_path.replace('.db', '.json'))
            elif self.output_format == 'csv':
                self._save_to_csv(self.db_path.replace('.db', '.csv'))

        except Exception as e:
            print(f"❌ Error parsing hive: {e}")
            logging.error(f"Error parsing hive: {e}")
            self.failed_parses += 1
            sys.exit(1)
        finally:
            self.handle.close()

def interactive_menu():
    """Display interactive menu for user input."""
    print(LOGO)
    print("Welcome to AmcacheParser")
    print("1. Live Analysis (requires admin privileges)")
    print("2. Offline Analysis")
    print("3. Select Output Format (SQLite, JSON, CSV)")
    print("4. Exit")
    choice = input("Select an option (1-4): ").strip()
    return choice

def main():
    parser = argparse.ArgumentParser(description="AmcacheParser: Parse Windows Amcache.hve files")
    parser.add_argument('--live', action='store_true', help="Perform live analysis")
    parser.add_argument('--offline', type=str, help="Path to offline Amcache.hve file")
    parser.add_argument('--output', choices=['sqlite', 'json', 'csv'], default='sqlite', help="Output format")
    parser.add_argument('--search-keys', type=str, help="Comma-separated list of subkeys to parse")
    parser.add_argument('--non-interactive', action='store_true', help="Run without interactive menu")
    args = parser.parse_args()

    logging.basicConfig(
        filename=r'C:\Amcache\amcache_parser.log',
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    print(LOGO)  # Display logo in all modes

    file_path = None
    db_path = DEFAULT_DATABASE_PATH
    output_format = args.output
    search_keys = args.search_keys.split(',') if args.search_keys else None

    if args.non_interactive:
        if args.live:
            file_path = DEFAULT_LIVE_PATH
        elif args.offline:
            file_path = args.offline
        else:
            print("❌ Offline path must be specified with --offline in non-interactive mode")
            logging.error("Offline path not specified in non-interactive mode")
            sys.exit(1)
        print(f"Running in non-interactive mode: {file_path}, output={output_format}")
        logging.debug(f"Non-interactive mode: file_path={file_path}, output={output_format}")
        if args.live and not is_admin():
            print("❌ Live analysis requires administrative privileges")
            print("   Run as administrator:")
            print("   Start-Process powershell -Verb RunAs -ArgumentList \"-NoProfile -ExecutionPolicy Bypass -Command \\\"C:/Users/Ghass/AppData/Local/Microsoft/WindowsApps/python3.12.exe 'C:/Amcache/amcache_parser.py' --live\\\"\"")
            logging.error("Live analysis attempted without admin privileges")
            sys.exit(1)
        if not os.path.exists(file_path):
            print(f"❌ Input file does not exist: {file_path}")
            logging.error(f"Input file does not exist: {file_path}")
            sys.exit(1)
        if args.live and system() == 'Windows' and int(version().split(".")[0]) < 7:
            print("❌ Your system is not compatible with Amcache.hve")
            logging.error("System not compatible with Amcache.hve")
            sys.exit(1)
        ap = AmcacheParser(file_path, db_path, output_format, search_keys)
        ap.parse()
        return

    while True:
        choice = interactive_menu()
        if choice == '1':
            if not is_admin():
                print("❌ Live analysis requires administrative privileges")
                print("   Run as administrator:")
                print("   Start-Process powershell -Verb RunAs -ArgumentList \"-NoProfile -ExecutionPolicy Bypass -Command \\\"C:/Users/Ghass/AppData/Local/Microsoft/WindowsApps/python3.12.exe 'C:/Amcache/amcache_parser.py' --live\\\"\"")
                logging.error("Live analysis attempted without admin privileges")
                continue
            file_path = DEFAULT_LIVE_PATH
            if system() == 'Windows' and int(version().split(".")[0]) < 7:
                print("❌ Your system is not compatible with Amcache.hve")
                logging.error("System not compatible with Amcache.hve")
                continue
            ap = AmcacheParser(file_path, db_path, output_format, search_keys)
            ap.parse()
        elif choice == '2':
            file_path = input("Enter offline Amcache.hve path: ").strip()
            if not file_path:
                print("❌ Offline path must be specified")
                logging.error("Offline path not specified")
                continue
            if not os.path.exists(file_path):
                print(f"❌ Input file does not exist: {file_path}")
                logging.error(f"Input file does not exist: {file_path}")
                continue
            ap = AmcacheParser(file_path, db_path, output_format, search_keys)
            ap.parse()
        elif choice == '3':
            output_format = input("Enter output format (sqlite, json, csv) [sqlite]: ").strip().lower() or 'sqlite'
            if output_format not in ['sqlite', 'json', 'csv']:
                print("❌ Invalid output format. Choose sqlite, json, or csv")
                logging.error(f"Invalid output format: {output_format}")
                continue
            print(f"✓ Output format set to: {output_format}")
            logging.debug(f"Output format set to: {output_format}")
        elif choice == '4':
            print("Exiting...")
            logging.debug("User exited the program")
            sys.exit(0)
        else:
            print("❌ Invalid choice. Please select 1-4")
            logging.error(f"Invalid menu choice: {choice}")

if __name__ == '__main__':
    main()
