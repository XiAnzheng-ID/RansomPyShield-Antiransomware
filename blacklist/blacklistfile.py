import hashlib
import os
import shutil
import threading
import time
from notifypy import Notify
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

stop_event = threading.Event()

# User directory path
user = os.path.expanduser("~")

# Directories to be monitored
MONITORED_DIRECTORIES = [
    os.path.join(user, "Downloads"),
    os.path.join(user, "Desktop"),
    os.path.join(user, "AppData", "Local", "Temp"),
    os.path.join(user, "AppData", "Roaming"),
    "C:\\ProgramData",
]

# Quarantine directory path
QUARANTINE_DIR = os.path.join(user, "AppData", "Local", "RansomPyShield", "Quarantine")

# Create Quarantine directory if it doesn't exist
os.makedirs(QUARANTINE_DIR, exist_ok=True)

def warn(file_path):
    notification = Notify()
    notification.title = "RansomPyShield"
    notification.message = f"Ransomware file: {file_path} detected \n and has been quarantined"
    notification.send()

def start_monitoring_threads(hash_file):
    global stop_event
    stop_event.clear()  # Reset stop event

    observers = []
    for directory in MONITORED_DIRECTORIES:
        observer = Observer()
        event_handler = MonitorHandler(hash_file)  # Pass the hash file to the event handler
        observer.schedule(event_handler, directory, recursive=True)
        observer.start()
        observers.append(observer)
    
    return observers

def stop_monitoring(observers):
    for observer in observers:
        observer.stop()
        observer.join()

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
            # Reload hash file if it was modified
            current_mod_time = os.path.getmtime(self.hash_file)
            if current_mod_time != self.last_mod_time:
                print(f"Hash file {self.hash_file} updated. Reloading hashes.")
                self.hashes = read_hashes_from_file(self.hash_file)
                self.last_mod_time = current_mod_time

            if os.path.exists(file_path):
                file_hash = calculate_sha256(file_path)
                if file_hash in self.hashes:
                    self.quarantine_file(file_path)
                    warn(file_path)
                    print(f"Hash match found for file {file_path}")
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")

    def quarantine_file(self, file_path):
        try:
            # Rename and move file to quarantine directory
            file_name = os.path.basename(file_path)
            new_file_name = f"{file_name}.ransom"
            destination = os.path.join(QUARANTINE_DIR, new_file_name)

            shutil.move(file_path, destination)
            print(f"File {file_path} quarantined as {destination}")

        except Exception as e:
            print(f"Error quarantining file {file_path}: {e}")

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


if __name__ == "__main__":  
    file_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Hashes.txt")

    # Start monitoring each directory in separate threads
    observers = start_monitoring_threads(file_path)

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("Stopping monitoring...")
        stop_monitoring(observers)

    print("All monitoring stopped.")
