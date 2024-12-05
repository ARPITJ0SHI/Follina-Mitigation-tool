import os
import winreg
import subprocess
import psutil
import threading
import hashlib
import logging
import time
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, render_template, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename
from flask_cors import CORS
import re
import base64
import zipfile
import shutil
import random
import olefile


logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('follina_mitigation.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)


current_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(current_dir, 'templates')
frontend_dir = os.path.join(current_dir, 'frontend', 'build')


app = Flask(__name__, 
           static_folder=frontend_dir,
           static_url_path='')

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
app.config['UPLOAD_FOLDER'] = os.path.join(current_dir, 'temp_uploads')


os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


CORS(app, resources={r"/api/*": {"origins": "*"}})

class Stats:
    def __init__(self):
        self.safe_files = 0
        self.unsafe_files = 0
        self.attacks_prevented = 0
        self.last_detection = None
        self.detection_history = []

    def add_detection(self, file_name, is_malicious):
        if is_malicious:
            self.unsafe_files += 1
            self.attacks_prevented += 1
        else:
            self.safe_files += 1
        
        self.last_detection = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'file': file_name,
            'status': 'Malicious' if is_malicious else 'Safe'
        }
        
        self.detection_history.append(self.last_detection)
       
        if len(self.detection_history) > 100:
            self.detection_history.pop(0)

class FolderMonitor(FileSystemEventHandler):
    def __init__(self, mitigation, stats):
        self.mitigation = mitigation
        self.stats = stats
        self.processed_files = set()
        self.is_monitoring = False
        self.auto_protection = False
        self.ignored_files = {
            'follina_mitigation.log',
            'follina_mitigation.py',
            '__pycache__',
            '.git',
            '.gitignore',
            'README.md'
        }
        logging.info("[INIT] FolderMonitor initialized")

    def should_process_file(self, file_path):
       
        if os.path.basename(file_path) in self.ignored_files:
            return False
      
        return file_path.lower().endswith(('.doc', '.docx', '.rtf'))

    def toggle_auto_protection(self, enabled):
        self.auto_protection = enabled
        return True

    def start_monitoring(self):
        self.is_monitoring = True
        logging.info(f"[START] Starting monitoring of directory: {self.mitigation.monitored_directory}")
       
        self.scan_existing_files()
        logging.info("[STATUS] Monitoring active and ready for file events")

    def stop_monitoring(self):
        self.is_monitoring = False
        logging.info("[STOP] Stopped real-time monitoring")

    def scan_existing_files(self):
        try:
            monitored_dir = self.mitigation.monitored_directory
            logging.info(f"[SCAN] Scanning existing files in: {monitored_dir}")
            files_found = False
            for file in os.listdir(monitored_dir):
                file_path = os.path.join(monitored_dir, file)
                if self.should_process_file(file_path):
                    files_found = True
                    logging.info(f"[FOUND] Found existing file: {file}")
                    self.process_file(file_path, is_initial=True)
            if not files_found:
                logging.info("[SCAN] No document files found in monitored directory")
        except Exception as e:
            logging.error(f"[ERROR] Error scanning existing files: {str(e)}")

    def on_created(self, event):
        if event.is_directory or not self.should_process_file(event.src_path):
            return
        logging.info(f"[EVENT] File created: {event.src_path}")
        self.process_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory or not self.should_process_file(event.src_path):
            return
        logging.info(f"[EVENT] File modified: {event.src_path}")
        self.process_file(event.src_path)

    def process_file(self, file_path, is_initial=False):
        try:
            
            with open(file_path, 'rb') as f:
                content_hash = hashlib.md5(f.read()).hexdigest()
            
            file_key = f"{file_path}_{content_hash}"
            if file_key in self.processed_files:
                return
            self.processed_files.add(file_key)

           
            if len(self.processed_files) > 1000:
                self.processed_files.clear()

            prefix = "[INIT] Initial scan:" if is_initial else "[NEW] New/Modified file detected:"
            logging.info(f"{prefix} {os.path.basename(file_path)}")
            
            
            scan_results = self.mitigation.scan_file(file_path)
            
            if scan_results.get("suspicious", False):
                logging.warning(f"[WARN] Malicious file detected: {os.path.basename(file_path)}")
                logging.warning(f"[WARN] Automatically disabling MSDT for protection")
                self.mitigation.disable_msdt()
                self.stats.add_detection(os.path.basename(file_path), True)
                
             
                for detail in scan_results.get("details", []):
                    logging.warning(f"  └─ {detail}")
            else:
                logging.info(f"[STATUS] File is safe: {os.path.basename(file_path)}")
                self.stats.add_detection(os.path.basename(file_path), False)

        except Exception as e:
            logging.error(f"[ERROR] Error processing file {file_path}: {str(e)}")

class FollinaMitigation:
    def __init__(self):
        self.msdt_disabled = False
        self.monitoring_active = False
        self.monitor_thread = None
        self.suspicious_activities = []
        self.stats = Stats()
        self.folder_monitor = None
        self.observer = None
        self.monitored_directory = r"C:\Users\arpit\Downloads\attack\attack" 
        self._check_msdt_status()
        self.setup_monitoring()

    def setup_monitoring(self):
        try:
            logging.info(f"[INIT] Setting up monitoring for directory: {self.monitored_directory}")
            

            if not os.path.exists(self.monitored_directory):
                logging.info(f"[CREATE] Creating monitored directory: {self.monitored_directory}")
                os.makedirs(self.monitored_directory, exist_ok=True)
            
           
            self.folder_monitor = FolderMonitor(self, self.stats)
            self.observer = Observer()
            
           
            self.observer.schedule(self.folder_monitor, path=self.monitored_directory, recursive=False)
            self.observer.start()
            logging.info("[STATUS] Monitoring system initialized successfully")
            
         
            logging.info(f"[INFO] Current monitoring state:")
            logging.info(f"  - Directory: {self.monitored_directory}")
            logging.info(f"  - Observer active: {self.observer.is_alive()}")
            logging.info(f"  - Monitoring active: {self.monitoring_active}")
            
        except Exception as e:
            logging.error(f"[ERROR] Failed to initialize monitoring: {str(e)}")
            raise

    def start_monitoring(self):
        try:
            if self.folder_monitor:
                self.folder_monitor.start_monitoring()
                self.monitoring_active = True
                return {"success": True, "monitoring": True}
            return {"success": False, "error": "Monitor not initialized"}
        except Exception as e:
            logging.error(f"[ERROR] Error starting monitoring: {str(e)}")
            return {"success": False, "error": str(e)}

    def stop_monitoring(self):
        try:
            if self.folder_monitor:
                self.folder_monitor.stop_monitoring()
                self.monitoring_active = False
                return {"success": True, "monitoring": False}
            return {"success": False, "error": "Monitor not initialized"}
        except Exception as e:
            logging.error(f"[ERROR] Error stopping monitoring: {str(e)}")
            return {"success": False, "error": str(e)}

    def _check_msdt_status(self):
        try:
           
            key_path = r"Software\Policies\Microsoft\Windows\ScriptedDiagnostics"
            try:
                key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, 
                                       winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
                winreg.CloseKey(key)
            except WindowsError:
                pass

           
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, 
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            try:
                value, _ = winreg.QueryValueEx(key, "DisableProtocolHandler")
                self.msdt_disabled = bool(value)
            except WindowsError:
               
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, 
                                    winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
                winreg.SetValueEx(key, "DisableProtocolHandler", 0, winreg.REG_DWORD, 0)
                self.msdt_disabled = False
            finally:
                winreg.CloseKey(key)
        except Exception as e:
            logging.error(f"[ERROR] Error accessing registry: {str(e)}")
            self.msdt_disabled = False

    def disable_msdt(self):
        try:
           
            try:
                os.system('taskkill /F /IM msdt.exe 2>nul')
            except:
                pass

           
            key_paths = {
                
                r"Software\Policies\Microsoft\Windows\ScriptedDiagnostics": [
                    ("DisableProtocolHandler", 1, winreg.REG_DWORD),
                    ("EnableDiagnostics", 0, winreg.REG_DWORD)
                ],
                # Disable Windows Troubleshooting
                r"Software\Policies\Microsoft\Windows\WDI\{C295FBBA-FD47-46AC-8BEE-B1715EC634E5}": [
                    ("EnabledScenarioExecutionLevel", 0, winreg.REG_DWORD)
                ],
                # Disable Diagnostic Data
                r"Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy": [
                    ("DisableQueryRemoteServer", 1, winreg.REG_DWORD),
                    ("EnableQueryRemoteServer", 0, winreg.REG_DWORD)
                ],
                # Disable Troubleshooting UI
                r"Software\Microsoft\Windows\CurrentVersion\Policies\System": [
                    ("EnableDiagnostics", 0, winreg.REG_DWORD)
                ]
            }
            
            for key_path, values in key_paths.items():
                try:
                    key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, 
                                           winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
                    for value_name, value_data, value_type in values:
                        winreg.SetValueEx(key, value_name, 0, value_type, value_data)
                    winreg.CloseKey(key)
                except Exception as e:
                    logging.error(f"[ERROR] Failed to set registry key {key_path}: {str(e)}")

            # Disable MSDT URL Protocol
            try:
                key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r"ms-msdt", 0,
                                       winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
                winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
                # Add a deny command to prevent execution
                shell_key = winreg.CreateKeyEx(key, r"shell\open\command", 0, 
                                             winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
                winreg.SetValueEx(shell_key, "", 0, winreg.REG_SZ, "")
                winreg.CloseKey(shell_key)
                winreg.CloseKey(key)
            except Exception as e:
                logging.error(f"[ERROR] Failed to modify MSDT protocol: {str(e)}")

            self.msdt_disabled = True
            logging.info("[STATUS] Successfully disabled MSDT protocol handler and troubleshooter UI")
            return True
        except Exception as e:
            logging.error(f"[ERROR] Failed to disable MSDT: {str(e)}")
            return False

    def enable_msdt(self):
        try:
            logging.info("[STATUS] Attempting to enable MSDT...")
            success = True

            # First try to restart the diagnostic services
            try:
                subprocess.run(['net', 'start', 'DPS'], check=True, capture_output=True)
                subprocess.run(['net', 'start', 'WdiServiceHost'], check=True, capture_output=True)
                logging.info("[STATUS] Successfully started diagnostic services")
            except Exception as e:
                logging.warning(f"[WARN] Could not start services: {str(e)}")
                success = False

            # Registry paths to restore
            key_paths = {
                r"Software\Policies\Microsoft\Windows\ScriptedDiagnostics": [
                    ("DisableProtocolHandler", 0, winreg.REG_DWORD),
                    ("EnableDiagnostics", 1, winreg.REG_DWORD)
                ]
            }
            
            for key_path, values in key_paths.items():
                try:
                    key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, 
                                           winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
                    for value_name, value_data, value_type in values:
                        winreg.SetValueEx(key, value_name, 0, value_type, value_data)
                    winreg.CloseKey(key)
                    logging.info(f"[STATUS] Successfully modified registry key: {key_path}")
                except Exception as e:
                    logging.error(f"[ERROR] Failed to set registry key {key_path}: {str(e)}")
                    success = False

            # Restore MSDT URL Protocol
            try:
                msdt_path = os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 
                                       'System32\\msdt.exe')
                
                key = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r"ms-msdt", 0,
                                       winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
                winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
                shell_key = winreg.CreateKeyEx(key, r"shell\open\command", 0, 
                                             winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
                winreg.SetValueEx(shell_key, "", 0, winreg.REG_SZ, f'"{msdt_path}" %1')
                winreg.CloseKey(shell_key)
                winreg.CloseKey(key)
                logging.info("[STATUS] Successfully restored MSDT protocol handler")
            except Exception as e:
                logging.error(f"[ERROR] Failed to restore MSDT protocol: {str(e)}")
                success = False

            # Verify the changes
            try:
                self._check_msdt_status()
                if self.msdt_disabled:
                    logging.warning("[WARN] MSDT still appears to be disabled after enable attempt")
                    success = False
            except Exception as e:
                logging.error(f"[ERROR] Failed to verify MSDT status: {str(e)}")
                success = False

            if success:
                self.msdt_disabled = False
                logging.info("[SUCCESS] Successfully enabled MSDT protocol handler and troubleshooter")
            else:
                logging.warning("[WARN] Some operations failed while enabling MSDT")

            return success
        except Exception as e:
            logging.error(f"[ERROR] Failed to enable MSDT: {str(e)}")
            return False

    def scan_file(self, file_path):
        try:
            logging.info(f"[INIT] Starting scan of file: {file_path}")
            
            # Only scan document files
            if not file_path.lower().endswith(('.doc', '.docx', '.rtf')):
                logging.info("[INFO] Not a document file, skipping detailed scan")
                return {
                    "file": os.path.basename(file_path),
                    "size": os.path.getsize(file_path),
                    "md5": hashlib.md5(open(file_path, 'rb').read()).hexdigest(),
                    "suspicious": False,
                    "risk_level": "Low",
                    "matches": [],
                    "details": ["Not a document file"]
                }

            results = {
                "file": os.path.basename(file_path),
                "size": os.path.getsize(file_path),
                "md5": hashlib.md5(open(file_path, 'rb').read()).hexdigest(),
                "suspicious": False,
                "risk_level": "Low",
                "matches": [],
                "details": []
            }

            # Comprehensive patterns for Follina detection
            follina_patterns = [
                "ms-msdt:/id", "pcwdiagnostic", "it_rebrowseforfil",
                "it_launchmethod=contextmenu", "mpsigstub.exe",
                "invoke-expression", "system.diagnostics.process",
                "it_browseforfil", "windows/system32/mpsigstub.exe",
                "frombase64string", "downloadstring", "iex",
                "powershell -enc", "cmd.exe", "-e cmd",
                "targetmode=\"external\"", "target=\"http",
                "IT_RebrowseForFile=?", "IT_BrowseForFile=",
                "PCWDiagnostic /skip force",
                "invoke-webrequest",
                "system.text.encoding",
                "system.convert",
                "utf8.getstring",
                "/skip force /param",
                "../../../../../../../../../../../../../../Windows/System32/",
                "ms-msdt:/id PCWDiagnostic",
                "location.href",
                "script>location",
                ".href = \"ms-msdt"
            ]

            # Command execution patterns
            command_patterns = [
                "cmd.exe", "powershell", "invoke-expression",
                "iex", "system.diagnostics.process", "downloadstring",
                "frombase64string", "system.net.webclient",
                "invoke-webrequest", "-outfile", "-e cmd",
                "system.text.encoding", "utf8.getstring",
                "system.convert", "frombase64string",
                "windows/tasks/nc.exe", "nc.exe -e",
                "calc.exe", "mpsigstub.exe", "notepad.exe"
            ]

            # Additional suspicious patterns
            suspicious_patterns = [
                r"char\]58", r"char\]34",  # Character code obfuscation
                r"join\(['\"]{2,}", r"\+['\"]",  # String concatenation
                r"IT_.*File=.*\$\(",  # Parameter injection
                r"system\..*::",  # .NET system calls
                r"frombase64string\(.*\)",  # Base64 decoding
                r"invoke-.*\(",  # PowerShell invocation
                r"windows.*system32.*\.exe",  # System32 exe access
                r"/param.*=.*\$\(",  # Parameter manipulation
                r"\.exe.*\s+-[a-z]",  # Executable with parameters
                r"\\windows\\.*\\.*\.exe",  # Windows path traversal
                r"[A-Za-z0-9+/=]{30,}",  # Long base64-like strings
                r"location\.href\s*=\s*[\"']ms-msdt:/",  # JavaScript MSDT redirect
                r"IT_BrowseForFile=\$\(.*\)",  # Command injection in IT_BrowseForFile
                r"Invoke-Expression\(\$\(Invoke-Expression\(",  # Nested Invoke-Expression
                r"\[System\.Text\.Encoding\].*::.*\[System\.Convert\]",  # Encoded system calls
                r"PCWDiagnostic\s*/skip\s*force\s*/param",  # MSDT command structure
                r"[\"']ms-msdt:/.*mpsigstub\.exe[\"']",  # Full MSDT exploit pattern
                r"<script>.*ms-msdt:/.*</script>",  # Script-based MSDT execution
                r"Target=\"http.*:.*\"",  # External target URLs
                r"Relationship.*Target=\"http",  # External relationships
                r"IT_LaunchMethod=ContextMenu.*IT_BrowseForFile=",  # Follina parameter chain
                r"_rels/.*\.xml\.rels"  # Suspicious relationship files
            ]

            def check_content_for_patterns(content, is_binary=False, filename=""):
                if is_binary:
                    content_str = content.decode('utf-8', errors='ignore').lower()
                else:
                    content_str = content.lower()

                # Check exact patterns
                for pattern in follina_patterns + command_patterns:
                    if pattern.lower() in content_str:
                        results["suspicious"] = True
                        results["risk_level"] = "Critical"
                        results["matches"].append(f"Found pattern: {pattern}")
                        results["details"].append(f"Detected malicious pattern in {filename}: {pattern}")

                # Check regex patterns
                for pattern in suspicious_patterns:
                    matches = re.finditer(pattern, content_str, re.IGNORECASE)
                    for match in matches:
                        results["suspicious"] = True
                        results["risk_level"] = "Critical"
                        results["matches"].append(f"Found suspicious pattern: {match.group()}")
                        results["details"].append(f"Detected suspicious pattern in {filename}")

                # Special checks for document relationship files
                if "_rels/" in filename.lower() or ".rels" in filename.lower():
                    if "target=" in content_str and "http" in content_str:
                        results["suspicious"] = True
                        results["risk_level"] = "Critical"
                        results["matches"].append("Found external relationship target")
                        results["details"].append(f"Document contains suspicious external reference in {filename}")

                # Check for concatenated or obfuscated commands
                if re.search(r"(\+|&|\||\s+).*\.exe", content_str) and re.search(r"(cmd|powershell|system|invoke)", content_str):
                    results["suspicious"] = True
                    results["risk_level"] = "Critical"
                    results["matches"].append("Found concatenated command execution")
                    results["details"].append(f"Detected attempt to obfuscate command execution in {filename}")

                # Check for Base64 encoded content
                if "base64" in content_str:
                    encoded_matches = re.finditer(r'[A-Za-z0-9+/=]{30,}', content_str)
                    for match in encoded_matches:
                        try:
                            decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore').lower()
                            if any(pattern.lower() in decoded for pattern in command_patterns):
                                results["suspicious"] = True
                                results["risk_level"] = "Critical"
                                results["matches"].append("Found Base64 encoded command")
                                results["details"].append(f"Detected encoded malicious command in {filename}")
                        except:
                            pass

            # Create a temporary directory for extraction
            temp_dir = os.path.join(os.path.dirname(file_path), "temp_scan_" + str(random.randint(1000, 9999)))
            os.makedirs(temp_dir, exist_ok=True)

            try:
                # For DOCX files (ZIP format)
                if file_path.lower().endswith('.docx'):
                    logging.info("[INFO] Processing DOCX file")
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir)
                        
                    # Check all files in the document
                    for root, _, files in os.walk(temp_dir):
                        for file in files:
                            curr_file = os.path.join(root, file)
                            rel_path = os.path.relpath(curr_file, temp_dir)
                            
                            try:
                                with open(curr_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    check_content_for_patterns(content, filename=rel_path)
                            except:
                                with open(curr_file, 'rb') as f:
                                    content = f.read()
                                    check_content_for_patterns(content, is_binary=True, filename=rel_path)

                # For DOC/RTF files
                else:
                    logging.info(f"[INFO] Processing {file_path.split('.')[-1].upper()} file")
                    
                    # First try to treat it as a ZIP (some DOC files are actually ZIP)
                    try:
                        with zipfile.ZipFile(file_path, 'r') as zip_ref:
                            zip_ref.extractall(temp_dir)
                            
                        for root, _, files in os.walk(temp_dir):
                            for file in files:
                                curr_file = os.path.join(root, file)
                                rel_path = os.path.relpath(curr_file, temp_dir)
                                
                                try:
                                    with open(curr_file, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read()
                                        check_content_for_patterns(content, filename=rel_path)
                                except:
                                    with open(curr_file, 'rb') as f:
                                        content = f.read()
                                        check_content_for_patterns(content, is_binary=True, filename=rel_path)
                    except:
                        # If not a ZIP, process as binary
                        with open(file_path, 'rb') as f:
                            content = f.read()
                            check_content_for_patterns(content, is_binary=True, filename=os.path.basename(file_path))
                        
                        # Check for OLE objects
                        if olefile.isOleFile(file_path):
                            logging.info("[INFO] Processing OLE structure")
                            ole = olefile.OleFileIO(file_path)
                            for stream in ole.listdir():
                                stream_path = '/'.join(stream)
                                data = ole.openstream(stream).read()
                                check_content_for_patterns(data, is_binary=True, filename=f"OLE:{stream_path}")
                            ole.close()

            finally:
                # Clean up temporary directory
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logging.error(f"[ERROR] Error cleaning up temp directory: {str(e)}")

            logging.info(f"[INFO] Scan results: suspicious={results['suspicious']}, risk_level={results['risk_level']}, matches={results['matches']}")
            return results

        except Exception as e:
            logging.error(f"[ERROR] Error scanning file: {str(e)}")
            return {"error": str(e)}

    def monitor_msdt_calls(self):
        logging.info("[INIT] Starting MSDT monitoring")
        while self.monitoring_active:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    if 'msdt.exe' in proc.info['name'].lower():
                        cmdline = ' '.join(proc.info['cmdline'])
                        if any(indicator in cmdline.lower() for indicator in ['pcwdiagnostic', 'it_rebrowseforfile']):
                            activity = {
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'pid': proc.info['pid'],
                                'cmdline': cmdline
                            }
                            self.suspicious_activities.append(activity)
                            logging.warning(f"[WARN] Suspicious MSDT activity detected: {activity}")
            except Exception as e:
                logging.error(f"[ERROR] Error in MSDT monitoring: {str(e)}")
            time.sleep(1)

    def get_stats(self):
        return {
            "safe_files": self.stats.safe_files,
            "unsafe_files": self.stats.unsafe_files,
            "attacks_prevented": self.stats.attacks_prevented,
            "last_detection": self.stats.last_detection,
            "detection_history": self.stats.detection_history[-10:]  # Last 10 detections
        }

    def toggle_auto_protection(self, enabled):
        try:
            if self.folder_monitor:
                self.folder_monitor.toggle_auto_protection(enabled)
                self.auto_protection = enabled
                logging.info(f"{'🛡️' if enabled else '⚠️'} Auto-protection {'enabled' if enabled else 'disabled'}")
                return {"success": True, "auto_protection": enabled}
            return {"success": False, "error": "Folder monitor not initialized"}
        except Exception as e:
            logging.error(f"[ERROR] Error toggling auto-protection: {str(e)}")
            return {"success": False, "error": str(e)}

    def get_status(self):
        return {
            "msdt_disabled": self.msdt_disabled,
            "monitoring_active": self.monitoring_active,
            "auto_protection": self.folder_monitor.auto_protection if self.folder_monitor else False
        }

mitigation = FollinaMitigation()

@app.route('/')
def serve_react_app():
    return app.send_static_file('index.html')

@app.errorhandler(404)
def not_found(e):
    return app.send_static_file('index.html')

@app.route('/api/status')
def get_status():
    return jsonify(mitigation.get_status())

@app.route('/api/disable_msdt', methods=['POST'])
def api_disable_msdt():
    success = mitigation.disable_msdt()
    return jsonify({"success": success})

@app.route('/api/enable_msdt', methods=['POST'])
def api_enable_msdt():
    success = mitigation.enable_msdt()
    return jsonify({"success": success})

@app.route('/api/scan_file', methods=['POST'])
def api_scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            file.save(filepath)
            logging.info(f"[INFO] Saved uploaded file to {filepath}")
            results = mitigation.scan_file(filepath)
            os.remove(filepath)  # Clean up
            logging.info(f"[INFO] Scan completed. Results: {results}")
            return jsonify(results)
        except Exception as e:
            logging.error(f"[ERROR] Error processing uploaded file: {str(e)}")
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({"error": f"[ERROR] Error processing file: {str(e)}"}), 500

@app.route('/api/toggle_monitoring', methods=['POST'])
def api_toggle_monitoring():
    try:
        data = request.get_json()
        if data.get('enable', False):
            if not mitigation.monitoring_active:
                mitigation.monitoring_active = True
                mitigation.monitor_thread = threading.Thread(target=mitigation.monitor_msdt_calls)
                mitigation.monitor_thread.start()
                logging.info("[INFO] Monitoring started")
        else:
            mitigation.monitoring_active = False
            if mitigation.monitor_thread:
                mitigation.monitor_thread.join()
                logging.info("[INFO] Monitoring stopped")
        
        return jsonify({"monitoring": mitigation.monitoring_active})
    except Exception as e:
        logging.error(f"[ERROR] Error toggling monitoring: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/get_activities', methods=['GET'])
def api_get_activities():
    return jsonify(mitigation.suspicious_activities)

@app.route('/api/stats')
def get_stats():
    return jsonify(mitigation.get_stats())

@app.route('/api/toggle_auto_protection', methods=['POST'])
def api_toggle_auto_protection():
    try:
        data = request.get_json()
        if data is None:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        enabled = data.get('enable', True)
        result = mitigation.toggle_auto_protection(enabled)
        
        if result["success"]:
            return jsonify(result)
        else:
            return jsonify(result), 500
            
    except Exception as e:
        logging.error(f"[ERROR] Error in toggle_auto_protection endpoint: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/start_monitoring', methods=['POST'])
def api_start_monitoring():
    try:
        result = mitigation.start_monitoring()
        return jsonify(result)
    except Exception as e:
        logging.error(f"[ERROR] Error in start_monitoring endpoint: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/stop_monitoring', methods=['POST'])
def api_stop_monitoring():
    try:
        result = mitigation.stop_monitoring()
        return jsonify(result)
    except Exception as e:
        logging.error(f"[ERROR] Error in stop_monitoring endpoint: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    logging.info("[INFO] Starting Follina Mitigation Tool")
    app.run(host='localhost', port=5000, debug=True) 