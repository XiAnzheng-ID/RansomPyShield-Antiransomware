import yara
import os
import psutil
import time
import threading
import shutil
from notifypy import Notify

# Global state
yara_monitor_thread = None
yara_monitor_running = False

user = os.path.expanduser("~")
QUARANTINE_DIR = os.path.join(user, "AppData", "Local", "RansomPyShield", "Quarantine")

# Notification functions
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

# Load YARA rules
def load_yara_rules(yara_file_path):
    try:
        return yara.compile(filepath=yara_file_path)
    except yara.SyntaxError as e:
        print(f"YARA Syntax Error: {e}")
    except Exception as e:
        print(f"Error loading YARA file: {e}")
    return None

# Scan file
def scan_file_with_yara(rules, file_path):
    try:
        matches = rules.match(file_path)
        if matches:
            for match in matches:
                print(f"Detected: {match.rule}")
            return True
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
    return False

def scan_with_thread(scan_function, file_path, result):
    try:
        result[0] = scan_function(file_path)
    except Exception as e:
        print(f"Error in thread while running {scan_function.__name__}: {e}")
        result[0] = False

# Quarantine
def rename_and_quarantine(file_path):
    try:
        base, ext = os.path.splitext(file_path)
        new_file_path = f"{base}{ext}.ransom"
        shutil.move(file_path, new_file_path)
        quarantine_path = os.path.join(QUARANTINE_DIR, os.path.basename(new_file_path))
        shutil.move(new_file_path, quarantine_path)
        print(f"File {file_path} renamed and moved to quarantine.")
    except Exception as e:
        print(f"Failed to quarantine file {file_path}: {e}")

# YARA scan functions
def signature(file_path):
    rule_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Signature.yar")
    rules = load_yara_rules(rule_path)
    if rules and scan_file_with_yara(rules, file_path):
        rename_and_quarantine(file_path)
        warn(file_path)
        return True
    return False

def exploit_scan(file_path):
    rule_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Exploit.yar")
    rules = load_yara_rules(rule_path)
    if rules and scan_file_with_yara(rules, file_path):
        sus_warn(file_path)
        return True
    return False

def suspicious_scan(file_path):
    rule_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "red-is-sus.yar")
    rules = load_yara_rules(rule_path)
    if rules and scan_file_with_yara(rules, file_path):
        sus_warn(file_path)
        return True
    return False

def custom_rule_scan(file_path):
    rule_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Custom.yar")
    rules = load_yara_rules(rule_path)
    if rules and scan_file_with_yara(rules, file_path):
        sus_warn(file_path)
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
    scan_functions = [signature, exploit_scan, suspicious_scan]
    custom_yara_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Custom.yar")
    if os.path.exists(custom_yara_path):
        scan_functions.append(custom_rule_scan)
        print("Custom YARA rules detected.")

    for scan_function in scan_functions:
        result = [False]
        thread = threading.Thread(target=scan_with_thread, args=(scan_function, file_path, result))
        thread.start()
        thread.join()
        if result[0]:
            kill_process(pid)
            print(f"Malicious activity detected in {file_path}. Killing process {pid}.")
            return

def watch_yara_files(file_path, last_mod_time, reload_callback):
    try:
        current_mod_time = os.path.getmtime(file_path)
        if current_mod_time != last_mod_time:
            reload_callback()
            return current_mod_time
    except Exception as e:
        print(f"Error watching YARA file {file_path}: {e}")
    return last_mod_time

def yara_monitor_loop():
    global yara_monitor_running

    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    monitored_pids = set(proc.pid for proc in psutil.process_iter(['pid']))
    yara_files = [
        os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", fname)
        for fname in ["Signature.yar", "Exploit.yar", "red-is-sus.yar"]
    ]
    custom_yara_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Custom.yar")
    if os.path.exists(custom_yara_path):
        yara_files.append(custom_yara_path)

    last_mod_times = {path: os.path.getmtime(path) for path in yara_files}

    while yara_monitor_running:
        current_pids = set(proc.pid for proc in psutil.process_iter(['pid', 'exe']))
        new_pids = current_pids - monitored_pids

        for pid in new_pids:
            try:
                process = psutil.Process(pid)
                file_path = process.exe()
                if os.path.exists(file_path):
                    perform_scans(file_path, pid)
            except psutil.NoSuchProcess:
                continue
            except Exception as e:
                print(f"Error processing PID {pid}: {e}")

        for yara_file in yara_files:
            last_mod_times[yara_file] = watch_yara_files(
                yara_file,
                last_mod_times[yara_file],
                lambda: print(f"{yara_file} modified. YARA rules reloaded.")
            )

        monitored_pids = current_pids
        time.sleep(0.1)

def start_yara_monitor():
    global yara_monitor_thread, yara_monitor_running
    if not yara_monitor_running:
        yara_monitor_running = True
        yara_monitor_thread = threading.Thread(target=yara_monitor_loop, daemon=True)
        yara_monitor_thread.start()
        print("YARA monitor thread started.")

def stop_yara_monitor():
    global yara_monitor_running
    yara_monitor_running = False
    if yara_monitor_thread:
        yara_monitor_thread.join()
        print("YARA monitor thread stopped.")