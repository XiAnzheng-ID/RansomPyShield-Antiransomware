import os
import time
import psutil
import threading
import ctypes
import winsound
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Global flag to control monitoring
stop_flag = threading.Event()
observers = []
notification_lock = threading.Lock()  # Lock for controlling notification
folder_name = "Honey"

def stop_monitoring():
    stop_flag.set()
    for observer in observers:
        observer.stop()
        observer.join()
    observers.clear()

# Display MessageBox 
def show_message_box():
    winsound.MessageBeep(winsound.MB_ICONASTERISK)  # Notification sound
    ctypes.windll.user32.MessageBoxW(0, "RANSOMWARE ACTIVITY DETECTED, PLEASE SCAN YOUR SYSTEM", "Ransomware Detected", 0x30 | 0x1000)  # MSGBOX

# Folder Handler
class MyHandler(FileSystemEventHandler):
    def __init__(self):
        self.initial_processes = get_running_processes()
        self.processes_to_kill = set()  # Set untuk menyimpan PID proses yang harus dibunuh
        self.notified = False  # Flag to check if notification is already shown

    def on_any_event(self, event):
        honey_folder = folder_name  # Honeypot Folder name
        if honey_folder in event.src_path:
            last_process_pids = self.get_new_processes_pids() # Add new process PID that been detected
            if last_process_pids:
                self.processes_to_kill.update(last_process_pids)  # Kill all processes after detection
                self.terminate_processes()

    # New Process List
    def get_new_processes_pids(self):
        current_processes = get_running_processes()
        new_processes = set(current_processes.keys()) - set(self.initial_processes.keys())
        return new_processes

    def terminate_processes(self):
        with notification_lock:
            if not self.notified:
                msg_thread = threading.Thread(target=show_message_box)
                msg_thread.start()
                self.notified = True  # Set the flag to prevent further notifications

        print(f"RANSOMWARE ACTIVITY DETECTED!!!, LOG:{time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("KILLED PROCESS:")
        for pid in list(self.processes_to_kill):
            try:
                process = psutil.Process(pid)
                process_name = process.name()
                process_path = process.exe()
                start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(process.create_time()))  # Process start time
                process.kill()  # Kill process
                end_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())  # Process killed time
                print(f"{process_name} dir:{process_path} PID: {pid}")
                print(f"Process started at: {start_time} and terminated at: {end_time}\n")
                self.processes_to_kill.remove(pid)  # Remove from list after kill
            except psutil.NoSuchProcess:
                self.processes_to_kill.remove(pid)  # Remove from list if process no longer exists
            except Exception as e:
                print(f"Error killing {process_name} dir:{process_path} dengan PID {pid}: {e}\n")

        # Reset the notification flag after processes are terminated
        with notification_lock:
            self.notified = False

# Process Snapshot
def get_running_processes():
    processes = {}
    for proc in psutil.process_iter():
        try:
            start_time = proc.create_time()
            processes[proc.pid] = start_time
        except psutil.NoSuchProcess:
            pass
    return processes

def monitor_directory(directory):
    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observers.append(observer)
    observer.start()
    try:
        while not stop_flag.is_set():
            time.sleep(0.1)  # Speed of activity monitoring
    except KeyboardInterrupt:
        observer.stop()
    observer.stop()
    observer.join()

def main():
    global stop_flag
    stop_flag.clear()
    # User directory
    user = os.path.expanduser("~")
    documents = os.path.join(user, "Documents")
    desktop = os.path.join(user, "Desktop")
    video = os.path.join(user, "Videos")
    download = os.path.join(user, "Downloads")
    music = os.path.join(user, "Music")
    picture = os.path.join(user, "Pictures")

    # Drive path
    drives = psutil.disk_partitions()
    directories_to_watch = []
    for drive in drives:
        drive_letter = drive.device.split()[0]
        honey_drive_path = os.path.join(drive_letter, folder_name)
        if os.access(honey_drive_path, os.W_OK):  # Check if drive is writable
            directories_to_watch.append(honey_drive_path)

    directories_to_watch.extend([
        "C:\\Users",
        user,
        documents,
        desktop,
        video,
        download,
        music,
        picture,
        user,
    ])
    
    threads = []
    for directory in directories_to_watch:
        thread = threading.Thread(target=monitor_directory, args=(directory,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
