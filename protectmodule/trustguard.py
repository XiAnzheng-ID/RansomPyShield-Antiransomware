import yara
import subprocess
import psutil
import pefile
import time
import os
import winsound
import ctypes
import threading

# Global Thread & Stop Event
trustguard_thread = None
stop_trustguard_event = threading.Event()

# Sigcheck
def check_signature(file_path):
    result = subprocess.run(
        ['sigcheck.exe', "-nobanner", "-accepteula", file_path], 
        capture_output=True, 
        text=True, 
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    return result.stdout

# Entropy 
def calculate_entropy(file_path):
    pe = pefile.PE(file_path)
    entropy = sum([section.get_entropy() for section in pe.sections]) / len(pe.sections)
    return entropy

# YARA scan
def scan_file_with_yara(rules, file_path):
    matches = rules.match(file_path)
    if matches:
        print(f"YARA match found in {file_path}: {[match.rule for match in matches]}")
        return True
    else:
        print(f"No YARA match found in {file_path}.")
        return False

# Load YARA rules
def load_yara_rules(rule_files):
    rule_sources = {f"rule_{i}": open(file).read() for i, file in enumerate(rule_files)}
    rules = yara.compile(sources=rule_sources)
    return rules

# Define YARA scan functions
def packed(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Packed.yar")
    rules = load_yara_rules([yara_file_path])
    return scan_file_with_yara(rules, file_path) if rules else False

def cert(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Cert.yar")
    rules = load_yara_rules([yara_file_path])
    return scan_file_with_yara(rules, file_path) if rules else False

# Show message box for alerts
def show_message_box():
    winsound.MessageBeep(winsound.MB_ICONASTERISK)
    ctypes.windll.user32.MessageBoxW(
        0,
        "RansomPyShield has blocked this app from running due to security reasons",
        "TrustGuard",
        0x30 | 0x1000
    )

# Analyze process signature and perform checks
def analyze_process_signature(process, max_entropy=7.25):
    try:
        file_path = process.exe()
        print(f"\nAnalyzing {file_path}...")

        # Sigcheck
        output = check_signature(file_path)
        if output:
            if "Signed" in output:
                print(f"Process {process.pid} ({process.name()}): Signed by a trusted publisher.")
            elif "Unsigned" in output:
                process.kill()
                print(f"Killed process {process.pid} ({process.name()}): Not signed.")
                show_message_box()
                return
        else:
            print(f"Process {process.pid} ({process.name()}): Signature status unknown or error.")

        # Entropy
        entropy = calculate_entropy(file_path)
        print(f"Entropy: {entropy:.2f}")
        if entropy > max_entropy:
            show_message_box()
            process.kill()
            print(f"Killed process {process.pid} ({process.name()}) due to high entropy: {entropy:.2f}")
            return

        # YARA scans 
        if packed(file_path) or cert(file_path):
            show_message_box()
            process.kill()
            print(f"Killed process {process.pid} ({process.name()}) due to YARA match.")

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    except Exception as e:
        print(f"Error analyzing process: {e}")

# Monitor for new processes
def monitor_new_processes(stop_event):
    existing_pids = set(p.pid for p in psutil.process_iter())

    while not stop_event.is_set():
        time.sleep(0.1)
        current_pids = set(p.pid for p in psutil.process_iter())
        new_pids = current_pids - existing_pids

        for pid in new_pids:
            try:
                process = psutil.Process(pid)
                analyze_process_signature(process)
            except Exception:
                pass

        existing_pids = current_pids

# control monitoring thread
def start_trustguard_monitor():
    global trustguard_thread, stop_trustguard_event
    if trustguard_thread is None or not trustguard_thread.is_alive():
        stop_trustguard_event.clear()
        trustguard_thread = threading.Thread(target=monitor_new_processes, args=(stop_trustguard_event,), daemon=True)
        trustguard_thread.start()
        print("[Signature Monitor] Thread started.")
    else:
        print("[Signature Monitor] Already running.")

def stop_trustguard_monitor():
    global stop_trustguard_event
    stop_trustguard_event.set()
    print("[Signature Monitor] Stop signal sent.")
