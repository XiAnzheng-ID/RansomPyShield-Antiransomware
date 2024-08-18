import yara
import os
import psutil
import time
import win32api
import win32con
import win32process

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
            print(f"YARA matched rules in file {file_path}:")
            for match in matches:
                print(f"Rule: {match.rule}")
        else:
            print(f"No YARA rules matched in file {file_path}.")
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")

def exploit_scan(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Exploit.yar")
    rules = load_yara_rules(yara_file_path)
    if rules:
        scan_file_with_yara(rules, file_path)

def malicious_cert(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Malicious-Cert.yar")
    rules = load_yara_rules(yara_file_path)
    if rules:
        scan_file_with_yara(rules, file_path)

def suspicious_technique(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "red-is-sus.yar")
    rules = load_yara_rules(yara_file_path)
    if rules:
        scan_file_with_yara(rules, file_path)

def ransomware(file_path):
    yara_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules", "Signature.yar")
    rules = load_yara_rules(yara_file_path)
    if rules:
        scan_file_with_yara(rules, file_path)

def is_valid_signature(file_path):
    try:
        win32api.VerifyVersionInfo({'ProductType': 1}, file_path)
        return True
    except:
        return False

def pause_process(pid):
    try:
        process = psutil.Process(pid)
        process.suspend()
    except Exception as e:
        print(f"Failed to pause process {pid}: {e}")

def resume_process(pid):
    try:
        process = psutil.Process(pid)
        process.resume()
    except Exception as e:
        print(f"Failed to resume process {pid}: {e}")

def monitor_processes():
    monitored_pids = set(proc.pid for proc in psutil.process_iter(['pid']))  # PID yang sudah ada saat ini
    while True:
        current_pids = set(proc.pid for proc in psutil.process_iter(['pid', 'exe']))  # PID saat ini
        new_pids = current_pids - monitored_pids  # PID baru yang muncul

        for pid in new_pids:
            try:
                process = psutil.Process(pid)
                file_path = process.exe()

                if not is_valid_signature(file_path):
                    pause_process(pid)
                    ransomware(file_path)
                    exploit_scan(file_path)
                    suspicious_technique(file_path)
                    resume_process(pid)
                else:
                    ransomware(file_path)
                    malicious_cert(file_path)
                    exploit_scan(file_path)
                    suspicious_technique(file_path)
            except psutil.NoSuchProcess:
                continue  # Proses mungkin sudah selesai sebelum bisa di-scan

        monitored_pids = current_pids  # Update monitored PIDs
        time.sleep(5)

def main():
    monitor_processes()

if __name__ == "__main__":
    main()
