import yara
import os
import psutil
import time
import threading

# Global flag for stopping the monitoring thread
stop_flag = threading.Event()

def stop_monitoring():
    stop_flag.set()

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

def convention_engine(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "ConventionEngine.yar")
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

def kill_process(pid):
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        process.kill()
        print(f"Process {process_name} ({pid}) killed.")
    except Exception as e:
        print(f"Failed to kill process {pid}: {e}")

def perform_scans(file_path, pid):
    scan_functions = [signature, suspicious_technique, convention_engine, exploit_scan]
    for scan_function in scan_functions:
        result = [False]
        thread = threading.Thread(target=scan_with_thread, args=(scan_function, file_path, result))
        thread.start()
        thread.join()  # Wait for the scan to complete
        if result[0]:
            print(f"Malicious activity detected in {file_path}. Killing process {pid}.")
            kill_process(pid)
            return  # Stop further scans if any scan detects malicious activity

def monitor_processes():
    monitored_pids = set(proc.pid for proc in psutil.process_iter(['pid']))  # Process Snapshot
    while not stop_flag.is_set():  # Check stop_flag to exit loop
        current_pids = set(proc.pid for proc in psutil.process_iter(['pid', 'exe']))  # New PID
        new_pids = current_pids - monitored_pids  # Get New pid

        for pid in new_pids:
            try:
                process = psutil.Process(pid)
                process_name = process.name()
                file_path = process.exe()

                if os.path.exists(file_path):  # Ensure the file path exists
                    perform_scans(file_path, pid)
                else:
                    print(f"File path for process {pid} does not exist")

            except psutil.NoSuchProcess:
                print(f"{process_name} with PID {pid} no longer exists")
                continue
            except Exception as e:
                print(f"Error handling process with PID {pid}: {e}")

        monitored_pids = current_pids  # Update monitored PIDs
        time.sleep(0.1)

if __name__ == "__main__":
    monitor_processes()