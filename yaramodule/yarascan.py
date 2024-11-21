import yara
import os
import psutil
import time
import threading
import shutil
from notifypy import Notify

# Global flag for stopping the monitoring thread
stop_flag = threading.Event()

# Other variables
user = os.path.expanduser("~")
QUARANTINE_DIR = os.path.join(user, "AppData", "Local", "RansomPyShield", "Quarantine")

# List of directories to quarantine
MONITOR_DIRECTORIES = [
    os.path.join(user, "Desktop"),
    os.path.join(user, "Downloads"),
    os.path.join(user, "AppData", "Local", "Temp"),
    os.path.join(user, "AppData", "Roaming"),
    "C:\\ProgramData",
]

# Whitelist
# Dont Forget to fill this as you need
EXCLUDED_DIRECTORIES = [
    
]


EXCLUDED_PROCESSES = [
    
]

def stop_monitoring():
    stop_flag.set()

def warn(file_path):
    notification = Notify()
    notification.title = "RansomPyShield"
    notification.message = f"Ransomware detected: {file_path} \n and has been quarantined"
    notification.send()

def sus_warn(file_path):
    notification = Notify()
    notification.title = "RansomPyShield"
    notification.message = f"Suspicious File detected: {file_path} \n and has been blocked"
    notification.send()

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

def rename_and_quarantine(file_path):
    try:
        base, ext = os.path.splitext(file_path)
        new_file_path = f"{base}{ext}.ransom"
        shutil.move(file_path, new_file_path)
        quarantine_path = os.path.join(QUARANTINE_DIR, os.path.basename(new_file_path))
        shutil.move(new_file_path, quarantine_path)
        print(f"File {file_path} renamed to {new_file_path} and moved to quarantine.")
    except Exception as e:
        print(f"Failed to quarantine file {file_path}: {e}")

def ransompyshield(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "RansomPyShield.yar")
    rules = load_yara_rules(yara_file_path)
    if rules and scan_file_with_yara(rules, file_path):
        # Check if the file is in one of the monitored directories
        if any(file_path.startswith(dir) for dir in MONITOR_DIRECTORIES):
            rename_and_quarantine(file_path)
            warn(file_path)
            return True 
    return scan_file_with_yara(rules, file_path) if rules else False

def exploit_scan(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Exploit.yar")
    rules = load_yara_rules(yara_file_path)
    # Warn
    if rules and scan_file_with_yara(rules, file_path):
        sus_warn(file_path)
        return True 
    return scan_file_with_yara(rules, file_path) if rules else False

def convention_engine(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "ConventionEngine.yar")
    rules = load_yara_rules(yara_file_path)
    if rules and scan_file_with_yara(rules, file_path):
        sus_warn(file_path)
        return True 
    return scan_file_with_yara(rules, file_path) if rules else False

def suspicious_technique(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "red-is-sus.yar")
    rules = load_yara_rules(yara_file_path)
    if rules and scan_file_with_yara(rules, file_path):
        sus_warn(file_path)
        return True 
    return scan_file_with_yara(rules, file_path) if rules else False

def signature(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Signature.yar")
    rules = load_yara_rules(yara_file_path)
    
    if rules and scan_file_with_yara(rules, file_path):
        # Check if the file is in one of the monitored directories
        if any(file_path.startswith(dir) for dir in MONITOR_DIRECTORIES):
            rename_and_quarantine(file_path)
            warn(file_path)
            return True 
    return False

def custom_rule_scan(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "custom.yar")
    rules = load_yara_rules(yara_file_path)
    if rules and scan_file_with_yara(rules, file_path):
        notification = Notify()
        notification.title = "RansomPyShield"
        notification.message = f"File match with custom Ruleset: {file_path} \n and has been blocked"
        notification.send()
    return scan_file_with_yara(rules, file_path) if rules else False

# Function to detect changes in YARA file and reload rules
def watch_yara_files(file_path, last_mod_time, reload_callback):
    try:
        # Get the current modification time of the YARA file
        current_mod_time = os.path.getmtime(file_path)
        if current_mod_time != last_mod_time:
            reload_callback()
            return current_mod_time
    except Exception as e:
        print(f"Error watching YARA file {file_path}: {e}")
    return last_mod_time

def is_excluded_process(process_name, file_path):
    # Check if the process name or file path should be excluded
    if process_name in EXCLUDED_PROCESSES:
        return True
    for excluded_dir in EXCLUDED_DIRECTORIES:
        if file_path.lower().startswith(excluded_dir.lower()):
            return True
    return False

def kill_process(pid):
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        process.kill()
        print(f"Process {process_name} ({pid}) killed.")
    except Exception as e:
        print(f"Failed to kill process {pid}: {e}")

def perform_scans(file_path, pid):
    scan_functions = [signature, ransompyshield, suspicious_technique, convention_engine, exploit_scan]
    
    # If custom.yar exists, add it to the scan functions
    custom_yara_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Custom.yar")
    if os.path.exists(custom_yara_path):
        scan_functions.append(custom_rule_scan)
        print("Custom YARA rules detected. Including Custom.yar in scanning.")

    for scan_function in scan_functions:
        result = [False]
        thread = threading.Thread(target=scan_with_thread, args=(scan_function, file_path, result))
        thread.start()
        thread.join()  # Wait for the scan to complete
        if result[0]:
            kill_process(pid)
            print(f"Malicious activity detected in {file_path}. Killing process {pid}.")
            return  # Stop further scans if any scan detects malicious activity

def monitor_processes():
    monitored_pids = set(proc.pid for proc in psutil.process_iter(['pid']))  # Process Snapshot
    yara_file_paths = [
        os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Exploit.yar"),
        os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "ConventionEngine.yar"),
        os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "red-is-sus.yar"),
        os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Signature.yar"),
    ]

    # Check if custom.yar exists and add it to yara_file_paths
    custom_yara_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "custom.yar")
    if os.path.exists(custom_yara_path):
        yara_file_paths.append(custom_yara_path)
        print("Custom YARA file detected. Including custom.yar in scanning.")

    last_mod_times = {path: os.path.getmtime(path) for path in yara_file_paths}

    while not stop_flag.is_set(): # Check stop_flag to exit loop 
        current_pids = set(proc.pid for proc in psutil.process_iter(['pid', 'exe']))  # New PID
        new_pids = current_pids - monitored_pids  # Get New pid

        # Monitor for new processes
        for pid in new_pids:
            try:
                process = psutil.Process(pid)
                process_name = process.name()
                file_path = process.exe()

                # Skip scanning if the process or its path is excluded
                if is_excluded_process(process_name, file_path):
                    print(f"Skipping potentially safe process: {process_name} ({file_path})")
                    continue

                if os.path.exists(file_path):  # Ensure the file path exists
                    perform_scans(file_path, pid)
                else:
                    print(f"File path for process {pid} does not exist")

            except psutil.NoSuchProcess:
                print(f"{process_name} with PID {pid} no longer exists")
                continue
            except Exception as e:
                print(f"Error handling process with PID {pid}: {e}")

        # Watch YARA files for changes and reload if necessary
        for yara_file in yara_file_paths:
            last_mod_times[yara_file] = watch_yara_files(
                yara_file,
                last_mod_times[yara_file],
                lambda: print(f"{yara_file} has been modified. Reloading YARA rules")
            )

        monitored_pids = current_pids  # Update monitored PIDs
        time.sleep(0.1)

if __name__ == "__main__":
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    monitor_processes()