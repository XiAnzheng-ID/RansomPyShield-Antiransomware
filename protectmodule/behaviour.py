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
observers = []
stop_threads = False
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
reset_interval = 5  # Interval to reset the counter (seconds)

directories_to_monitor = [
    documents,
    desktop,
    video,
    download,
    music,
    picture,
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\ProgramData",
]

def show_message_box():
    winsound.MessageBeep(winsound.MB_ICONASTERISK)  # Notification sound
    ctypes.windll.user32.MessageBoxW(0, "RANSOMWARE ACTIVITY DETECTED, PLEASE SCAN YOUR SYSTEM", "Ransomware Detected", 0x30 | 0x1000)  # MSGBOX
    
class FolderMonitorHandler(FileSystemEventHandler):
    def __init__(self, folder):
        self.folder = folder  # save path folder
        global folder_counters, last_activity_time
        
        # initialize counters for the folder
        if folder not in folder_counters:
            folder_counters[folder] = {'delete_count': 0, 'new_file_count': 0}
            last_activity_time[folder] = time.time()

    def on_deleted(self, event):
        global last_activity_time
        folder_counters[self.folder]['delete_count'] += 1
        last_activity_time[self.folder] = time.time()  
        print(f"File deleted in {self.folder}: {event.src_path}") #debug print

    def on_created(self, event):
        global last_activity_time
        folder_counters[self.folder]['new_file_count'] += 1
        last_activity_time[self.folder] = time.time()  
        print(f"New file created in {self.folder}: {event.src_path}") #debug print

def reset_counters_if_inactive():
    global folder_counters, last_activity_time
    while True:
        current_time = time.time()
        for folder, last_time in last_activity_time.items():
            time_since_last_activity = current_time - last_time
            if time_since_last_activity > reset_interval:
                #print(f"No recent activity in {folder}, resetting counters.") #debug print
                folder_counters[folder] = {'delete_count': 0, 'new_file_count': 0}
        time.sleep(1)  # Activity check interval

def kill_new_processes():
    for process in psutil.process_iter():
        if process.pid not in initial_processes:
            try:
                print(f"Killing process {process.pid} - {process.name()}")
                process.kill()
            except Exception as e:
                print(f"Error killing process {process.pid}: {e}")

def monitor_folders(directories):
    global observers, stop_threads
    stop_threads = False  # reset stop flag when starting monitoring
    for directory in directories:
        event_handler = FolderMonitorHandler(directory)
        observer = Observer()
        observer.schedule(event_handler, directory, recursive=False)
        observer.start()
        observers.append(observer)
        print(f"Monitoring started for {directory}")

    # reset counter thread
    reset_thread = threading.Thread(target=reset_counters_if_inactive, daemon=True)
    reset_thread.start()

    try:
        while not stop_threads: 
            time.sleep(0.1)
            for folder, counters in folder_counters.items():
                #change this as you need (the lower the number the aggresive this script will act)
                if counters['delete_count'] >= 6 and counters['new_file_count'] >= 3 :
                    kill_new_processes()
                    show_message_box()
                    print(f"Suspicious activity detected in {folder}!")
    except KeyboardInterrupt:
        stop_monitoring()
    for observer in observers:
        observer.join()

def start_monitoring():
    monitor_folders(directories_to_monitor)

def stop_monitoring():
    global stop_threads
    stop_threads = True 
    for observer in observers:
        observer.stop()
    for observer in observers:
        observer.join()
    print("Monitoring stopped.")

if __name__ == "__main__":
    start_monitoring()
