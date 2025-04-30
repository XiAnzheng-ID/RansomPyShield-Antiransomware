import psutil
import time
import os
import threading
import winsound
import ctypes
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Variable and counter
folder_counters = {}
user = os.path.expanduser("~")
documents = os.path.join(user, "Documents")
desktop = os.path.join(user, "Desktop")
video = os.path.join(user, "Videos")
download = os.path.join(user, "Downloads")
music = os.path.join(user, "Music")
picture = os.path.join(user, "Pictures")

# Process Snapshot
initial_processes = set(p.pid for p in psutil.process_iter())
last_activity_time = {}
reset_interval = 15  # seconds

directories_to_monitor = [
    documents, desktop, video, download, music, picture,
]

# Monitoring flags
is_monitoring = False
monitor_thread = None
observers = []

def show_message_box():
    winsound.MessageBeep(winsound.MB_ICONASTERISK)
    ctypes.windll.user32.MessageBoxW(
        0,
        "RANSOMWARE ACTIVITY DETECTED, PLEASE SCAN YOUR SYSTEM",
        "Ransomware Detected",
        0x30 | 0x1000
    )

class FolderMonitorHandler(FileSystemEventHandler):
    def __init__(self, folder):
        self.folder = folder
        global folder_counters, last_activity_time
        if folder not in folder_counters:
            folder_counters[folder] = {'delete_count': 0, 'new_file_count': 0}
            last_activity_time[folder] = time.time()

    def on_deleted(self, event):
        folder_counters[self.folder]['delete_count'] += 1
        last_activity_time[self.folder] = time.time()
        print(f"File deleted in {self.folder}: {event.src_path}")

    def on_created(self, event):
        folder_counters[self.folder]['new_file_count'] += 1
        last_activity_time[self.folder] = time.time()
        print(f"New file created in {self.folder}: {event.src_path}")

def reset_counters_if_inactive():
    global folder_counters, last_activity_time
    while is_monitoring:
        current_time = time.time()
        for folder, last_time in last_activity_time.items():
            if current_time - last_time > reset_interval:
                print(f"No recent activity in {folder}, resetting counters.")
                folder_counters[folder] = {'delete_count': 0, 'new_file_count': 0}
        time.sleep(reset_interval)

def kill_new_processes():
    for process in psutil.process_iter():
        if process.pid not in initial_processes:
            try:
                print(f"Killing process {process.pid} - {process.name()}")
                process.kill()
            except Exception as e:
                print(f"Error killing process {process.pid}: {e}")

def monitor_main_loop():
    global observers
    for directory in directories_to_monitor:
        handler = FolderMonitorHandler(directory)
        observer = Observer()
        observer.schedule(handler, directory, recursive=False)
        observer.start()
        observers.append(observer)
        print(f"Monitoring started for {directory}")

    reset_thread = threading.Thread(target=reset_counters_if_inactive, daemon=True)
    reset_thread.start()

    try:
        while is_monitoring:
            time.sleep(0.1)
            for folder, counters in folder_counters.items():
                if counters['delete_count'] >= 10 and counters['new_file_count'] >= 5:
                    kill_new_processes()
                    show_message_box()
                    print(f"Suspicious activity detected in {folder}!")
    finally:
        for observer in observers:
            observer.stop()
        for observer in observers:
            observer.join()
        observers.clear()
        print("Monitoring stopped.")

def start_behaviour_monitoring():
    global is_monitoring, monitor_thread
    if not is_monitoring:
        is_monitoring = True
        monitor_thread = threading.Thread(target=monitor_main_loop)
        monitor_thread.start()
        print("Folder behavior monitoring started.")

def stop_behaviour_monitoring():
    global is_monitoring
    if is_monitoring:
        is_monitoring = False
        print("Folder behavior monitoring stopped.")