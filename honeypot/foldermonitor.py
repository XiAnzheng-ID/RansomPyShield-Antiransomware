import os
import time
import psutil
import threading
import ctypes
import winsound
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Global flag to control monitoring and notifications
observer = None
monitor_thread = None
monitor_running = False
notification_lock = threading.Lock()  # Lock for controlling notification
folder_name = "Honey"
cooldown_flag = False  # Flag to control cooldown period for notifications
cooldown_duration = 5  # Cooldown duration in seconds

# Display MessageBox 
def show_message_box():
    winsound.MessageBeep(winsound.MB_ICONASTERISK)  # Notification sound
    ctypes.windll.user32.MessageBoxW(0, "RANSOMWARE ACTIVITY DETECTED, PLEASE SCAN YOUR SYSTEM", "Ransomware Detected", 0x30 | 0x1000)  # MSGBOX

# Function to set cooldown period for notifications
def start_notification_cooldown():
    global cooldown_flag
    cooldown_flag = True
    time.sleep(cooldown_duration)  # Sleep for the duration of the cooldown
    cooldown_flag = False

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
        global cooldown_flag

        with notification_lock:
            # Only notify if not in cooldown period
            if not cooldown_flag:
                msg_thread = threading.Thread(target=show_message_box)
                msg_thread.start()
                cooldown_thread = threading.Thread(target=start_notification_cooldown)  # Start cooldown period
                cooldown_thread.start()

                print(f"RANSOMWARE ACTIVITY DETECTED!!!, LOG:{time.strftime('%Y-%m-%d %H:%M:%S')}")
                print("KILLED PROCESS:")

                self.notified = True  # Set the flag to prevent further notifications

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

def start_honeypot_monitor():
    global observer, monitor_thread, monitor_running

    if monitor_running:
        print("Honeypot monitor already running.")
        return

    def run_monitor():
        global observer
        event_handler = MyHandler()
        observer = Observer()

        user = os.path.expanduser("~")
        folder_name = "Honey"

        watch_dirs = []
        for drive in psutil.disk_partitions():
            try:
                drive_letter = drive.device.split()[0]
                honey_drive_path = os.path.join(drive_letter, folder_name)
                if os.access(honey_drive_path, os.W_OK):
                    watch_dirs.append(honey_drive_path)
            except Exception:
                continue

        additional_dirs = [
            "C:\\Users",
            os.path.join(user, "Documents"),
            os.path.join(user, "Desktop"),
            os.path.join(user, "Videos"),
            os.path.join(user, "Downloads"),
            os.path.join(user, "Music"),
            os.path.join(user, "Pictures"),
        ]
        watch_dirs.extend(additional_dirs)

        for directory in watch_dirs:
            if os.path.exists(directory):
                try:
                    observer.schedule(event_handler, path=directory, recursive=True)
                except Exception as e:
                    print(f"Could not schedule directory {directory}: {e}")

        observer.start()
        print("Honeypot monitor started.")
        try:
            while monitor_running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass

        observer.stop()
        observer.join()
        observer = None

    monitor_running = True
    monitor_thread = threading.Thread(target=run_monitor, daemon=True)
    monitor_thread.start()

def stop_honeypot_monitor():
    global monitor_running, monitor_thread

    if not monitor_running:
        print("Honeypot monitor is not running.")
        return

    monitor_running = False

    # Tunggu sampai thread selesai
    if monitor_thread and monitor_thread.is_alive():
        monitor_thread.join()
        monitor_thread = None

    print("Honeypot monitor stopped.")