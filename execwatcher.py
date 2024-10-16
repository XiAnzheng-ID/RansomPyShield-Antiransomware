import psutil
import time
import threading

# Daftar command yang diblokir
blacklist_commands = [
    "del", #Possbile deleting something
    "delete", #Possible deleting something
    "rmdir", #Deleting whole folder tree
    "netsh", #Possible Changing Firewall
    "advfirewall", #Possible Changing Firewall
    "cipher", #Possible encryption command
    #Change Windows Defender , Firewall , Task Manager , Regedit settings
    "set-mppreference",
    "mppreference", 
    "disabletaskMgr",
    "disableregedit",
    "disableregistrytools",
    "firewallpolicy",
    "enablefirewall",
    "firewalldisablenotify",
    #file-enumeration
    "get-childItem", 
    "childItem",
    # Encoded powershell command
    "-e", 
    "-en",
    "-enco",
    "-encodedcommand", 
    "en", 
    "enc", 
    "enco", 
    "encodedcommand",
    # Possible vssadmin usage
    "vssadmin.exe delete shadows /all", 
    "delete shadows /all",
    "delete shadows", 
    # Possible wmic usage
    "cmd /c \"wmic.exe shadowcopy delete\\",  
    "wmic shadowcopy delete",
    "wmic.exe shadowcopy /nointeractive", 
    "shadowcopy /nointeractive",
    # shadowcopy/storage access
    "shadowcopy delete",  
    "resize shadowstorage /for=c: /on=c: /maxsize", 
    "shadowstorage",
    "shadowcopy",
    #possible trying to boot into safemode or break safemode and boot sequence
    "bcdedit",
    "bcdedit.exe",
    "bcdedit /set", 
    "bootstatuspolicy", 
    "ignoreallfailures",
    # Possible partition access
    "multi(0)disk(0)rdisk(0)partition", 
    "partition",
    "disk",
    "rdisk",
    # Random commands that can be used by ransomware or other malware
    "bootstatuspolicy",
    "ignoreallfailures", 
    "recoveryenabled no",
    "recoveryenabled",
    "disableantispyware" ,
    "disable-defender",
    "disablebehaviormonitoring",
    "tamperprotection",
    "disableonaccessprotection",
    "disablescanonrealtimeenable",
    "disablerealtimemonitoring",
    "spynetreporting",
    "submitsamplesconsent",
    "disablescriptscanning",
    "sisablearchivescanning",
    "disableintrusionpreventionsystem",
    "submitsamplesconsent",
    "vdisablerealtimemonitoring",
    "securityhealth",
    "hidescahealth",
    "vssadmin",
]

# var and set
existing_cmd_ps_processes = set()
process_list = ['vssadmin.exe', 'WMIC.exe']
is_monitoring = False

def start_monitoring():
    global is_monitoring
    is_monitoring = True
    monitoring_thread = threading.Thread(target=monitor_new_process, daemon=True)
    monitoring_thread.start()

def stop_monitoring():
    global is_monitoring
    is_monitoring = False

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

def monitor_new_process():
    global existing_cmd_ps_processes, is_monitoring

    while True:
        if not is_monitoring:
            time.sleep(1)  # Sleep untuk mengurangi beban CPU saat monitoring dimatikan
            continue
        
        current_cmd_ps_processes = set()

        for process in psutil.process_iter(['pid', 'name', 'cmdline']):
            if process.info['name'] in ["cmd.exe", "powershell.exe", "vssadmin.exe", "WMIC.exe"]:
                pid = process.info['pid']
                current_cmd_ps_processes.add(pid)

                # New Process found
                if pid not in existing_cmd_ps_processes:
                    cmdline = ' '.join(process.info['cmdline']).lower()

                    # Try to Pause that process
                    pause_process(pid)
                    print(f"New {process.info['name']} detected with command line: {cmdline}")

                    # Blacklist command check
                    if process.info['name'] == "powershell.exe" and any(flag in cmdline for flag in ['-e', '-en', '-enc', '-enco', '-encodedcommand']):
                        kill_vssadmin_and_wmic(process_list)
                        print(f"Encoded PowerShell command detected: {cmdline}")
                        psutil.Process(pid).kill()
                        print(f"Process with PID {pid} terminated due to encoded command.")
                    elif any(bad_cmd in cmdline for bad_cmd in blacklist_commands):
                        kill_vssadmin_and_wmic(process_list)
                        print(f"Blocked command detected: {cmdline}")
                        psutil.Process(pid).kill()
                        print(f"Process with PID {pid} terminated due to blacklist command.")
                    else:
                        # resume if safe
                        resume_process(pid)

        # Refresh list set
        existing_cmd_ps_processes = current_cmd_ps_processes
        time.sleep(0.1)

if __name__ == "__main__":
    start_monitoring()  # Memulai monitoring saat script dijalankan
    while True:
        time.sleep(0.1)  # Main thread tidak melakukan apa-apa, bisa diganti dengan UI atau logika lain
