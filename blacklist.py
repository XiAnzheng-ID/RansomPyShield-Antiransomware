import hashlib
import os
import psutil
import threading
import time

stop_event = threading.Event()

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

def read_hashes_from_file(file_path=os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Hashes.txt")):
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

def monitor_hashes(hash_file):
    hashes = read_hashes_from_file(hash_file)
    known_processes = set()  # Track known processes

    while not stop_event.is_set():
        current_processes = set()
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # Skip the System Idle Process with PID 0
                if proc.info['pid'] == 0:
                    continue

                # Collect current processes
                current_processes.add(proc.info['pid'])

                if proc.info['pid'] not in known_processes:
                    known_processes.add(proc.info['pid'])  # Mark process as known
                    executable_path = proc.exe()
                    if os.path.exists(executable_path):
                        file_hash = calculate_sha256(executable_path)
                        if file_hash in hashes:
                            print(f"Hash match found for process {proc.info['pid']} - {proc.info['name']}")
                            proc.terminate()  # Terminate the process
                            print(f"Process {proc.info['pid']} terminated")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                # Print specific error messages to debug
                print(f"Error accessing process: {e}")
                continue
            except Exception as e:
                print(f"Unexpected error: {e}")

        # Sleep for a short period before checking again
        time.sleep(0.1)

    print("Blacklist monitoring stopped.")


# if __name__ == "__main__":
#     file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Hashes.txt")
#     start_monitoring_thread(file_path)