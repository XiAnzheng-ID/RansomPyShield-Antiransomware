import hashlib
import os
import shutil
import threading
import time
from notifypy import Notify
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Global control
monitor_thread = None
monitor_running = False
observer = None
user = os.path.expanduser("~")

# Directories to be monitored
MONITORED_DIRECTORIES = [
    os.path.join(user, "Downloads"),
    os.path.join(user, "Desktop"),
]

# Quarantine directory path
QUARANTINE_DIR = os.path.join(user, "AppData", "Local", "RansomPyShield", "Quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

def warn(file_path):
    notification = Notify()
    notification.title = "RansomPyShield"
    notification.message = f"Ransomware file: {file_path} detected \n and has been quarantined"
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

class MonitorHandler(FileSystemEventHandler):
    def __init__(self, hash_file):
        self.hash_file = hash_file
        self.hashes = read_hashes_from_file(hash_file)
        self.last_mod_time = os.path.getmtime(hash_file)

    def process_event(self, file_path):
        try:
            current_mod_time = os.path.getmtime(self.hash_file)
            if current_mod_time != self.last_mod_time:
                print(f"[Watcher] Hash file updated. Reloading hashes.")
                self.hashes = read_hashes_from_file(self.hash_file)
                self.last_mod_time = current_mod_time

            if os.path.exists(file_path):
                file_hash = calculate_sha256(file_path)
                if file_hash in self.hashes:
                    self.quarantine_file(file_path)
                    warn(file_path)
                    print(f"[!] Hash match found for {file_path}")
        except Exception as e:
            print(f"Error processing {file_path}: {e}")

    def quarantine_file(self, file_path):
        try:
            file_name = os.path.basename(file_path)
            new_file_name = f"{file_name}.ransom"
            destination = os.path.join(QUARANTINE_DIR, new_file_name)
            shutil.move(file_path, destination)
            print(f"[+] File {file_path} moved to quarantine as {destination}")
        except Exception as e:
            print(f"Error quarantining file: {e}")

    def on_created(self, event):
        if not event.is_directory:
            self.process_event(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_event(event.dest_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.process_event(event.src_path)

def _monitor_directory_loop(hash_file_path):
    global observer
    event_handler = MonitorHandler(hash_file_path)
    observer = Observer()

    for directory in MONITORED_DIRECTORIES:
        if os.path.exists(directory):
            try:
                observer.schedule(event_handler, directory, recursive=True)
                print(f"[+] Watching: {directory}")
            except Exception as e:
                print(f"Failed to watch {directory}: {e}")

    observer.start()
    try:
        while monitor_running:
            time.sleep(0.1)
    finally:
        observer.stop()
        observer.join()
        print("[*] Directory monitoring stopped.")

def start_directory_monitor():
    global monitor_running, monitor_thread
    if not monitor_running:
        monitor_running = True
        hash_file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "hashes.txt")
        monitor_thread = threading.Thread(target=_monitor_directory_loop, args=(hash_file_path,), daemon=True)
        monitor_thread.start()
        print("[+] Directory monitoring started.")

def stop_directory_monitor():
    global monitor_running
    if monitor_running:
        monitor_running = False
        print("[*] Stopping directory monitoring...")
