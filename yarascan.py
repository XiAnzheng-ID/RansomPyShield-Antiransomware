import yara
import os
import psutil
import time
import threading

# Global flag for stopping the monitoring thread
stop_flag = threading.Event()

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

def exploit_scan(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Exploit.yar")
    rules = load_yara_rules(yara_file_path)
    return scan_file_with_yara(rules, file_path) if rules else False

def malicious_cert(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Malicious-Cert.yar")
    rules = load_yara_rules(yara_file_path)
    return scan_file_with_yara(rules, file_path) if rules else False

def suspicious_technique(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "red-is-sus.yar")
    rules = load_yara_rules(yara_file_path)
    return scan_file_with_yara(rules, file_path) if rules else False

def ransomware(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Signature.yar")
    rules = load_yara_rules(yara_file_path)
    return scan_file_with_yara(rules, file_path) if rules else False

def kill_process(pid):
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        process.kill()
        print(f"Process {process_name} ({pid}) killed.")
    except Exception as e:
        print(f"Failed to kill process {process_name} ({pid}): {e}")

def scanthread(pid, file_path):
    if ransomware(file_path) or exploit_scan(file_path) or suspicious_technique(file_path) or malicious_cert(file_path):
        kill_process(pid)  # Kill if rule match

def monitor_processes():
    monitored_pids = set(proc.pid for proc in psutil.process_iter(['pid']))  # Process Snapshot
    while not stop_flag.is_set():  # Check stop_flag to exit loop
        current_pids = set(proc.pid for proc in psutil.process_iter(['pid', 'exe']))  # New PID
        new_pids = current_pids - monitored_pids  # Get New pid

        for pid in new_pids:
            try:
                process = psutil.Process(pid)
                file_path = process.exe()

                # Buat thread untuk menjalankan scan pada file baru
                threading.Thread(target=scanthread, args=(pid, file_path)).start()

            except psutil.NoSuchProcess:
                continue  # Proses mungkin sudah selesai sebelum bisa di-scan

        monitored_pids = current_pids  # Update monitored PIDs
        time.sleep(0.1)

def stop_monitoring():
    stop_flag.set()  # Set the stop flag to terminate the loop

if __name__ == "__main__":
    monitor_processes()
