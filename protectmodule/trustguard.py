import yara
import subprocess
import psutil
import pefile
import time
import os
import winsound
import ctypes
import threading

# Sigcheck
def check_signature(file_path):
    result = subprocess.run(['sigcheck.exe', file_path], capture_output=True, text=True)
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

# Rules
def packed(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Packed.yar")
    rules = load_yara_rules([yara_file_path])
    return scan_file_with_yara(rules, file_path) if rules else False

def cert(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Cert.yar")
    rules = load_yara_rules([yara_file_path])
    return scan_file_with_yara(rules, file_path) if rules else False

def show_message_box():
    winsound.MessageBeep(winsound.MB_ICONASTERISK)  # Notification sound
    ctypes.windll.user32.MessageBoxW(0, "TrustGuard", "RansomPyShield have blocked this app from running due to security reason", 0x30 | 0x1000)  # MSGBOX

# Analyze process signature and perform checks
def analyze_process_signature(process, max_entropy=7.5):
    file_path = process.exe()
    print(f"\nAnalyzing {file_path}...")

    # Sigcheck
    output = check_signature(file_path)
    if output:
        if "Signed" in output:
            print(f"Process {process.pid} ({process.name()}): Signed by a trusted publisher.")
        elif "Unsigned" in output:
            show_message_box()
            process.kill()
            print(f"Process {process.pid} ({process.name()}): Not signed.")
    else:
        print(f"Process {process.pid} ({process.name()}): Signature status unknown or error.")

    # Entropy
    try:
        entropy = calculate_entropy(file_path)
        print(f"Entropy: {entropy:.2f}")

        # Entropy Scan
        if entropy > max_entropy:
            process.kill()
            show_message_box()
            print(f"Killing process {process.pid} ({process.name()}) due to high entropy: {entropy:.2f}")
            return 
    except Exception as e:
        print(f"Could not calculate entropy: {e}")

    # YARA scans 
    if packed(file_path) or cert(file_path):
        process.kill()
        show_message_box()
        print(f"Killing process {process.pid} ({process.name()}) due to YARA match.")


# Monitor for new processes
def monitor_new_processes(stop_event):
    existing_pids = set(p.pid for p in psutil.process_iter())

    while not stop_event.is_set():
        time.sleep(0.1)  # Monitor interval
        current_pids = set(p.pid for p in psutil.process_iter())
        
        # Get new processes
        new_pids = current_pids - existing_pids
        for pid in new_pids:
            try:
                process = psutil.Process(pid)
                analyze_process_signature(process)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass 

        # Update the existing process list
        existing_pids = current_pids

# Load YARA rules
def load_yara_rules(rule_files):
    rule_sources = {f"rule_{i}": open(file).read() for i, file in enumerate(rule_files)}
    rules = yara.compile(sources=rule_sources)
    return rules

#other var
scan_functions = [packed, cert]
stop_event = threading.Event()

def start_monitoring():
    global monitoring_thread
    stop_event.clear()
    monitoring_thread = threading.Thread(target=monitor_new_processes, args=(stop_event,))
    monitoring_thread.daemon = True 
    monitoring_thread.start()

def stop_monitoring():
    stop_event.set() 
    
if __name__ == "__main__":
    start_monitoring()
    # stop_monitoring()
