import os
import ctypes
import elevate
import threading
import subprocess
import time
import psutil
import keyboard
import customtkinter as ctk
# other scripts
import honeypot.honeymanager as hm
import yaramodule.getRules as gr
import blacklist.getHashes as gh
from ui.helpui import help_ui
from ui.settingsui import settings_ui

# Var
app_version = "09.11.2024"

# Other Folder & Honeypot
appdata_path = os.getenv('LOCALAPPDATA')
honeyfiles_path = os.path.join(appdata_path, "RansomPyShield", "Honey")
rules_path = os.path.join(appdata_path, "RansomPyShield", "Rules")
quarantine = os.path.join(appdata_path, "RansomPyShield", "Quarantine")

# Membuat folder RansomPyShield jika belum ada
if not os.path.exists(honeyfiles_path) and not os.path.exists(rules_path):
    try:
        os.makedirs(honeyfiles_path)
        os.makedirs(rules_path)
        os.makedirs(quarantine)
    except OSError as e:
        print(f"Failed to create directory {honeyfiles_path}: {e}")

# UAC Admin Req
def run_with_uac():
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    if not is_admin:
        print("Requesting Admin Access, you can close this window")
        elevate.elevate()

# Update Yara rules periodically
def update_rules_scheduler(interval=3600):  # 3600 seconds = 1 hour
    while True:
        try:
            rule = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware/raw/main/Rule.zip"
            zip_rule = "Rule.zip"
            extract_to = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules")
            gr.get_rules(rule, zip_rule, extract_to)
            print("Yara Rules updated successfully.")
        except Exception as e:
            print(f"Failed to update Yara Rules: {e}")
        
        # Wait for the next interval
        time.sleep(interval)

def start_hashes_update_thread():
    update_hashes_thread = threading.Thread(target=gh.check_for_updates, args=(url,save_directory), daemon=True)
    update_hashes_thread.start()

# Open honeypot directory
def open_honeypot_directory():
    if os.path.exists(honeyfiles_path):
        subprocess.Popen(f'explorer "{honeyfiles_path}"')
    else:
        print(f"Path {honeyfiles_path} does not exist.")

# Open Quarantine Directory
def open_quarantine_directory():
    if os.path.exists(honeyfiles_path):
        subprocess.Popen(f'explorer "{quarantine}"')
    else:
        print(f"Path {quarantine} does not exist.")

#Panic Button
def get_process_list():
    return {proc.pid: proc.name() for proc in psutil.process_iter(['pid', 'name'])}

def kill_new_processes(original_processes):
    current_processes = get_process_list()
    new_processes = set(current_processes.keys()) - set(original_processes.keys())
    
    for pid in new_processes:
        print(f"PANIC BUTTON PRESSED: {current_processes[pid]}, killed")
        psutil.Process(pid).terminate()

snapshot = get_process_list()
keyboard.add_hotkey('ctrl + shift + k', kill_new_processes, args=(snapshot,))

# On UI Close stop all features
def on_closing(): 
    app.quit()
    app.destroy()

def main_ui():
    global app
    ctk.set_appearance_mode("System")  
    ctk.set_default_color_theme("dark-blue") 

    app = ctk.CTk()  
    app.geometry("420x350")
    app.resizable(False, False)
    app.title(f"RansomPyShield v{app_version}")
    app.protocol("WM_DELETE_WINDOW", on_closing)

    # Button Section
    # Help Button
    help_button = ctk.CTkButton(master=app, text="How to Use", command=lambda: help_ui())
    help_button.grid(row=0, column=1, padx=20, pady=10)

    # Button Toggle for both protection and Yara scan
    protection_button = ctk.CTkButton(master=app, text="Settings", command=lambda:settings_ui())
    protection_button.grid(row=0, column=2, padx=20, pady=10)

    # Open RansomPyShield folder 
    open_dir_button = ctk.CTkButton(master=app, text="Honeypot Folder ", command=open_honeypot_directory)
    open_dir_button.grid(row=1, column=2, padx=20, pady=10)

    # Quarantine Folder
    open_quarantine_button = ctk.CTkButton(master=app, text="Quarantine Folder ", command=open_quarantine_directory)
    open_quarantine_button.grid(row=2, column=2, padx=20, pady=10)

    # Random Text
    text = '''
    Devin Nathaniel(XiAnzheng)
    Universitas Gunadarma
    https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware
    '''
    label = ctk.CTkLabel(master=app, text=text, justify="left", anchor="w")
    label.place(relx=0.5, rely=0.8, anchor=ctk.CENTER)

    app.mainloop()

if __name__ == "__main__":
    run_with_uac()
    ctypes.windll.kernel32.SetConsoleTitleW(f"RansomPyShield Log , {app_version}")
    hm.create_files_folders()

    # Get YARA rules
    rule = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware/raw/main/Rule.zip"
    zip_rule = "Rule.zip"
    extract_to = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules")

    url = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware/raw/main/hashes.txt"
    save_directory = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield")

    try:
        print("Updating Hashes & Rules....")
        gr.get_rules(rule, zip_rule, extract_to)
        gh.download_file_from_github(url, save_directory)
        start_hashes_update_thread()
        main_ui()
    except Exception as e:
        print(e)
        print("Failed to update one or more protection component. Check your internet connection and re-open this app")
        input("Press anykey to exit")