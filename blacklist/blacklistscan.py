import hashlib
import os
import psutil
import shutil
import threading
import time
from notifypy import Notify

monitor_thread = None
monitor_running = False

def warn(executable_path):
    notification = Notify()
    notification.title = "RansomPyShield"
    notification.message = f"Ransomware file: {executable_path} detected \n and has been quarantined"
    notification.send()

def read_hashes_from_file(file_path):
    hashes = set()
    try:
        with open(file_path, "r") as file:
            for line in file:
                hashes.add(line.strip())
    except Exception as e:
        print(f"Error reading Hash File: {e}")
    return hashes

def calculate_sha256(file_path):
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hash_sha256.update(chunk)
    except Exception as e:
        print(f"Error reading file for hash calculation: {e}")
    return hash_sha256.hexdigest()

def get_current_processes():
    # Retrieve a set of currently running process PIDs when the monitoring starts
    current_processes = set()
    for proc in psutil.process_iter(['pid']):
        try:
            current_processes.add(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return current_processes

def rename_and_move_file(file_path):
    # Directory for quarantine
    quarantine_dir = os.path.join(os.path.expanduser("~"), "AppData", "Local", "RansomPyShield")
    os.makedirs(quarantine_dir, exist_ok=True)

    try:
        # Split file path to get the original file name and extension
        file_name = os.path.basename(file_path)
        file_name_without_ext, file_ext = os.path.splitext(file_name)
        
        # Create new file name by appending .ransom after the original extension
        new_file_name = f"{file_name_without_ext}{file_ext}.ransom"
        destination_path = os.path.join(quarantine_dir, new_file_name)
        
        # Move the file to the quarantine directory
        shutil.move(file_path, destination_path)
        print(f"File {file_path} renamed and moved to {destination_path}")

    except Exception as e:
        print(f"Error renaming and moving file {file_path}: {e}")

def monitor_loop(hash_file):
    global monitor_running
    known_processes = get_current_processes()

    while monitor_running:
        try:
            hashes = read_hashes_from_file(hash_file)

            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if proc.info['pid'] == 0 or proc.info['pid'] in known_processes:
                        continue

                    known_processes.add(proc.info['pid'])
                    executable_path = proc.info['exe']
                    if os.path.exists(executable_path):
                        file_hash = calculate_sha256(executable_path)
                        if file_hash in hashes:
                            warn(executable_path)
                            print(f"Hash match found for process {proc.info['pid']} - {proc.info['name']}")
                            proc.kill()
                            print(f"Process {proc.info['pid']} terminated")
                            rename_and_move_file(executable_path)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    print(f"Unexpected error: {e}")

            time.sleep(0.1)

        except Exception as e:
            print(f"Error in monitor loop: {e}")
            break

    print("[+] Hash monitoring thread stopped.")

def start_hash_monitor():
    global monitor_running, monitor_thread
    if not monitor_running:
        monitor_running = True
        hash_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "hashes.txt")
        monitor_thread = threading.Thread(target=monitor_loop, args=(hash_file_path,), daemon=True)
        monitor_thread.start()
        print("[+] Hash monitoring started.")

def stop_hash_monitor():
    global monitor_running
    if monitor_running:
        monitor_running = False
        print("[*] Stopping hash monitoring...")
