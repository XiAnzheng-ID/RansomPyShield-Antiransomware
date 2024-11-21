import yara
import os
import psutil
import time
import threading
import shutil  
from notifypy import Notify
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Global flag for stopping the monitoring thread
stop_flag = threading.Event()

# Other variables
user = os.path.expanduser("~")

# Directories to monitor
MONITORED_DIRECTORIES = [
    os.path.join(user, "Downloads"),
    os.path.join(user, "Desktop"),
    os.path.join(user, "AppData", "Local", "Temp"),
    os.path.join(user, "AppData", "Roaming"),
    "C:\\ProgramData",
]

# List of processes to exclude from killing
EXCLUDED_PROCESSES = []

# Set to keep track of monitored PIDs
initial_pids = set()
observers = []
threads = []

# Quarantine directory
QUARANTINE_DIR = os.path.join(user, "AppData", "Local", "RansomPyShield", "Quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)  # Create quarantine directory if it doesn't exist

def warn(file_path):
    notification = Notify()
    notification.title = "RansomPyShield"
    notification.message = f"Ransomware detected: {file_path} \n and has been quarantined"
    notification.send()

def stop_monitoring():
    stop_flag.set()
    for observer in observers:
        observer.stop()
    for thread in threads:
        thread.join()

class YaraScanHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"New file created: {event.src_path}")
            self.perform_scans(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"File modified: {event.src_path}")
            self.perform_scans(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            print(f"File renamed/moved: {event.src_path}")
            self.perform_scans(event.src_path)

    def perform_scans(self, file_path):
        scan_functions = [signature, ransompyshield, suspicious_technique, exploit_scan]

        for scan_function in scan_functions:
            result = [False]
            thread = threading.Thread(target=scan_with_thread, args=(scan_function, file_path, result))
            thread.daemon = True  # Make thread a daemon
            thread.start()
            thread.join()  # Wait for the scan to complete
            if result[0]:
                quarantine_file(file_path)
                warn(file_path)  # Call the quarantine function
                kill_all_new_processes()
                break  # Stop further scans if any scan detects malicious activity

def quarantine_file(file_path):
    try:
        # Get the original file name and extension
        base, ext = os.path.splitext(file_path)
        new_file_path = f"{base}.ransom"  # Add .ransom extension
        os.rename(file_path, new_file_path)  # Rename the file

        # Move the renamed file to the quarantine directory
        shutil.move(new_file_path, os.path.join(QUARANTINE_DIR, os.path.basename(new_file_path)))  # Move to quarantine
        print(f"File {new_file_path} moved to quarantine.")
    except Exception as e:
        print(f"Error quarantining file {file_path}: {e}")

def load_yara_rules(yara_file_path):
    try:
        rules = yara.compile(filepath=yara_file_path)
        return rules
    except yara.SyntaxError as e:
        print(f"YARA Syntax Error: {e}")
        return None
    except Exception as e:
        print(f"Error loading YARA file: {e}")
        return None

def scan_file_with_yara(rules, file_path):
    try:
        matches = rules.match(file_path)
        if matches:
            for match in matches:
                print(f"Detected: {match.rule}")
            return True  # Return True if any match is found
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
    return False  # Return False if no match is found

def scan_with_thread(scan_function, file_path, result):
    try:
        result[0] = scan_function(file_path)
    except Exception as e:
        print(f"Error in thread while running {scan_function.__name__}: {e}")
        result[0] = False

def exploit_scan(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Exploit.yar")
    rules = load_yara_rules(yara_file_path)
    return scan_file_with_yara(rules, file_path) if rules else False

def suspicious_technique(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "red-is-sus.yar")
    rules = load_yara_rules(yara_file_path)
    return scan_file_with_yara(rules, file_path) if rules else False

def signature(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Signature.yar")
    rules = load_yara_rules(yara_file_path)
    return scan_file_with_yara(rules, file_path) if rules else False

def ransompyshield(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "RansomPyShield.yar")
    rules = load_yara_rules(yara_file_path)
    return scan_file_with_yara(rules, file_path) if rules else False

def is_excluded_process(process_name):
    return process_name in EXCLUDED_PROCESSES

def kill_process(pid):
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        process.kill()
        print(f"Process {process_name} ({pid}) killed.")
    except Exception as e:
        print(f"Failed to kill process {pid}: {e}")

def kill_all_new_processes():
    current_pids = set(proc.pid for proc in psutil.process_iter(['pid']))
    new_pids = current_pids - initial_pids
    for pid in new_pids:
        kill_process(pid)

def monitor_directory(directory):
    global initial_pids
    initial_pids = set(proc.pid for proc in psutil.process_iter(['pid']))

    event_handler = YaraScanHandler()
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=False)
    observers.append(observer)
    observer.start()

    print(f"Monitoring started for {directory}...")
    try:
        while not stop_flag.is_set():
            time.sleep(0.1)
    finally:
        observer.stop()
        observer.join()

def start_monitoring():
    threads = []
    for directory in MONITORED_DIRECTORIES:
        thread = threading.Thread(target=monitor_directory, args=(directory,))
        thread.daemon = True  # Make thread a daemon
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    start_monitoring()
