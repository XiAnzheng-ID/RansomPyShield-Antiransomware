import hashlib
import os
import psutil
import shutil
import threading
import time
from notifypy import Notify

stop_event = threading.Event()

def warn(executable_path):
    notification = Notify()
    notification.title = "RansomPyShield"
    notification.message = f"Ransomware file: {executable_path} detected \n and has been quarantined"
    notification.send()

def start_monitoring_thread(hash_file):
    global stop_event
    stop_event.clear()  # Reset stop event
    thread = threading.Thread(target=monitor_hashes, args=(hash_file,))
    thread.daemon = True  # Daemon thread will exit when the main program exits
    thread.start()
    return thread

def stop_monitoring():
    global stop_event
    stop_event.set()  # Set stop event to stop monitoring

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

def monitor_hashes(hash_file):
    hashes = read_hashes_from_file(hash_file)
    known_processes = get_current_processes()  # Set initial whitelist of running processes
    last_mod_time = os.path.getmtime(hash_file)  # Get initial modification time

    while not stop_event.is_set():
        try:
            # Check if the hash file has been modified
            current_mod_time = os.path.getmtime(hash_file)
            if current_mod_time != last_mod_time:
                print(f"Hash file {hash_file} updated. Reloading hashes.")
                hashes = read_hashes_from_file(hash_file)  # Reload hashes
                last_mod_time = current_mod_time  # Update modification time

            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    # Skip the System Idle Process with PID 0
                    if proc.info['pid'] == 0:
                        continue

                    # Only scan newly detected processes (not in the initial whitelist)
                    if proc.info['pid'] not in known_processes:
                        known_processes.add(proc.info['pid'])  # Add new process to known list
                        executable_path = proc.info['exe']
                        if os.path.exists(executable_path):
                            file_hash = calculate_sha256(executable_path)
                            if file_hash in hashes:
                                warn(executable_path)
                                print(f"Hash match found for process {proc.info['pid']} - {proc.info['name']}")
                                proc.kill()  # Terminate the process
                                print(f"Process {proc.info['pid']} terminated")

                                # Rename and move the file after killing the process
                                rename_and_move_file(executable_path)

                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    print(f"Error accessing process: {e}")
                    continue
                except Exception as e:
                    print(f"Unexpected error: {e}")
            time.sleep(0.1)

        except FileNotFoundError:
            print(f"{hash_file} , path cant be found")
        except Exception as e:
            print(f"Unexpected error in monitoring: {e}")
            break

    print("Blacklist monitoring stopped.")

if __name__ == "__main__":
    file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Hashes.txt")
    start_monitoring_thread(file_path)
