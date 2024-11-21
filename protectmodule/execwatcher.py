import psutil
import time
import threading
from notifypy import Notify

# Daftar command yang diblokir
blacklist_commands = [
    "ransompyshield",  # self-defense
    "del",  # Possible deleting something
    "delete",  # Possible deleting something
    "rmdir",  # Deleting whole folder tree
    "cipher",  # Possible encryption command
    # Change Windows Defender, Firewall, Task Manager, Regedit settings
    "set-mppreference", "mppreference", "disabletaskMgr", "disableregedit", "disableregistrytools",
    "firewallpolicy", "enablefirewall", "firewalldisablenotify", "advfirewall",
    # file-enumeration
    "get-childItem", "childItem",
    # Encoded powershell command
    "-en", "-enco", "-encodedcommand", "en", "enc", "enco", "encodedcommand", "encoding",
    # Possible vssadmin usage
    "vssadmin.exe delete shadows /all", "delete shadows /all", "delete shadows",
    # Possible wmic usage
    "cmd /c \"wmic.exe shadowcopy delete\\", "wmic shadowcopy delete",
    "wmic.exe shadowcopy /nointeractive", "shadowcopy /nointeractive",
    # shadowcopy/storage access
    "shadowcopy delete", "resize shadowstorage /for=c: /on=c: /maxsize", "shadowstorage", "shadowcopy",
    # possible trying to boot into safemode or break safemode and boot sequence
    "bcdedit", "bcdedit.exe", "bcdedit /set", "bootstatuspolicy", "ignoreallfailures",
    "recoveryenabled no", "recoveryenabled",
    # Possible partition access
    "multi(0)disk(0)rdisk(0)partition", "partition", "disk", "rdisk",
    # Random commands that can be used by ransomware or other malware
    "disableantispyware", "disable-defender", "disablebehaviormonitoring", "tamperprotection",
    "disableonaccessprotection", "disablescanonrealtimeenable", "disablerealtimemonitoring",
    "spynetreporting", "submitsamplesconsent", "disablescriptscanning", "disablearchivescanning",
    "disableintrusionpreventionsystem", "vdisablerealtimemonitoring", "securityhealth", "hidescahealth",
    "vssadmin", "nouaccheck", "disableuac", "bypass",
]

process_list = ['vssadmin.exe', 'WMIC.exe'] #make sure vssadmin.exe and wmic.exe are killed
is_monitoring = False
process_threads = {}  # Dictionary to store running threads for each process

def warn(cmdline):
    notification = Notify()
    notification.title = "RansomPyShield"
    notification.message = f"Execution Watcher have prevented a suspicious command:\n {cmdline} \n from executing"
    notification.send()

def start_monitoring():
    global is_monitoring
    is_monitoring = True
    monitoring_thread = threading.Thread(target=monitor_new_process, daemon=True)
    monitoring_thread.start()

def stop_monitoring():
    global is_monitoring
    is_monitoring = False  # Set flag untuk menghentikan monitoring

    # Tunggu hingga semua thread selesai
    for pid, thread in process_threads.items():
        if thread.is_alive():
            thread.join()  # Tunggu hingga thread selesai

    print("All monitoring threads have been stopped.")

def kill_vssadmin_and_wmic(process_names):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] in process_names:
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def pause_process(pid):
    try:
        p = psutil.Process(pid)
        p.suspend()
    except psutil.NoSuchProcess:
        print(f"Process with PID {pid} no longer exists.")

def resume_process(pid):
    try:
        p = psutil.Process(pid)
        p.resume()
    except psutil.NoSuchProcess:
        print(f"Process with PID {pid} no longer exists.")

def monitor_process(pid, name, cmdline):
    try:
        # Try to pause that process
        pause_process(pid)
        print(f"Monitoring {name} with PID {pid} and command line: {cmdline}")

        # Check if the process command is in the blacklist
        if name == "powershell.exe" and any(flag in cmdline for flag in ['-e', '-en', '-enc', '-enco', '-encodedcommand']):
            psutil.Process(pid).kill()
            kill_vssadmin_and_wmic(process_list)
            warn(cmdline)
            print(f"Encoded PowerShell command detected: {cmdline}")
            print(f"Process with PID {pid} terminated due to encoded command.")
        elif any(bad_cmd in cmdline for bad_cmd in blacklist_commands):
            psutil.Process(pid).kill()
            kill_vssadmin_and_wmic(process_list)
            warn(cmdline)
            print(f"Suspicious command detected: {cmdline}")
            print(f"Process with PID {pid} terminated due to suspicious command.")
        else:
            # Resume process if it is safe
            resume_process(pid)

    except psutil.NoSuchProcess:
        print(f"Process with PID {pid} no longer exists.")
    finally:
        # Remove thread from tracking when finished
        if pid in process_threads:
            del process_threads[pid]

def monitor_new_process():
    global is_monitoring

    while True:
        if not is_monitoring:
            time.sleep(1)
            break  # Keluar dari loop jika monitoring dihentikan

        for process in psutil.process_iter(['pid', 'name', 'cmdline']):
            if process.info['name'] in ["cmd.exe", "powershell.exe", "vssadmin.exe", "WMIC.exe"]:
                pid = process.info['pid']
                cmdline = ' '.join(process.info['cmdline']).lower()

                # Start a new thread to monitor each process
                if pid not in process_threads:
                    process_thread = threading.Thread(target=monitor_process, args=(pid, process.info['name'], cmdline))
                    process_threads[pid] = process_thread
                    process_thread.start()

        time.sleep(0.1)

if __name__ == "__main__":
    start_monitoring()  # Memulai monitoring saat script dijalankan
