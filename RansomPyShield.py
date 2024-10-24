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
import honeypot.foldermonitor as fm
import yaramodule.getRules as gr
import yaramodule.yarascan as ys
import yaramodule.yarascanfile as ysf
import blacklist.malwarebazaar as mb
import blacklist.blacklistscan as bs
import blacklist.blacklistfile as bf
import protectmodule.execwatcher as ew
from protectmodule import behaviour

# Var
protection_thread = None
is_protection_on = False

yara_thread = None
is_yara_on = False

yara_file_thread = None
is_yara_file_on = False

blacklist_thread = None
is_blacklist_on = False

blacklist_file_thread = None
is_blacklist_file_on = False
observers = None  # List of global Observer objects 

is_behaviour_on = False
behaviour_thread = None

app_version = "25.10.2024"

# Other Folder
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

# admin?
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# UAC Admin Req
def run_with_uac():
    if not is_admin():
        print("Requesting Admin Access, you can close this window")
        elevate.elevate()

# other script
def antiransomware():
    fm.main()

# Run Honey
def run_honey_thread():
    global protection_thread
    ctypes.windll.kernel32.SetConsoleTitleW(f"RansomPyShield Log , {app_version} [Protection ON]")
    os.system("cls")
    print("Realtime Monitor ON [Honeypot]")
    # Bersihkan dan salin file ke folder "Honey"
    hm.clean_and_copy_honey_files()
    time.sleep(2)  # Let the thread finish clean and copy Honeypot files
    protection_thread = threading.Thread(target=antiransomware)
    protection_thread.start()

# Stop the Honey thread
def stop_honey_thread():
    fm.stop_monitoring()
    if protection_thread:
        protection_thread.join()
    ctypes.windll.kernel32.SetConsoleTitleW(f"RansomPyShield Log , {app_version} [Protection OFF]")
    os.system("cls")
    print("Realtime Monitor OFF") 

# Start Yara
def run_yara_scan_thread():
    global yara_thread
    print("Yara Scan ON")
    yara_thread = threading.Thread(target=ys.monitor_processes)
    yara_thread.start()

# Stop YARA
def stop_yara_scan_thread():
    if yara_thread:
        ys.stop_monitoring()  # Hentikan loop di YARA scan
        yara_thread.join()
        
    print("Yara Scan OFF")

# Start File Scan
def run_yara_file_thread():
    global yara_file_thread
    print("File Scan ON")
    yara_thread = threading.Thread(target=ys.monitor_processes)
    yara_file_thread = threading.Thread(target=ysf.start_monitoring)
    yara_thread.start()
    yara_file_thread.start()

# Stop File Scan
def stop_yara_file_thread():
    if yara_file_thread:
        ysf.stop_monitoring()
        yara_thread.join()
    print("File Scan OFF")


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

# Blacklist monitoring
def run_blacklist_thread():
    global blacklist_thread
    print("Blacklist Monitoring ON")
    blacklist_thread = bs.start_monitoring_thread(os.path.join(appdata_path, "RansomPyShield", "Hashes.txt"))

def stop_blacklist_thread():
    if blacklist_thread:
        bs.stop_monitoring() 
        blacklist_thread.join()

def run_blacklist_file_thread():
    global blacklist_file_thread

    # Start monitoring and store the list of observers (blacklist_file_thread will hold this list)
    blacklist_file_thread = bf.start_monitoring_threads(os.path.join(appdata_path, "RansomPyShield", "Hashes.txt"))

# Stop Blacklist monitoring
def stop_blacklist_file_thread():
    global blacklist_file_thread

    if blacklist_file_thread:
        # Pass the observers to stop_monitoring to stop each one
        bf.stop_monitoring(blacklist_file_thread)
        blacklist_file_thread = None  # Reset to None after stopping

def toggle_blacklist(blacklist_button):
    global is_blacklist_on
    global is_blacklist_file_on
    if is_blacklist_on:
        stop_blacklist_thread()
        stop_blacklist_file_thread()
        blacklist_button.configure(text="Blacklist-[OFF]", fg_color="red")
        is_blacklist_on = False
    else:
        run_blacklist_thread()
        run_blacklist_file_thread()
        blacklist_button.configure(text="Blacklist-[ON]", fg_color="green")
        is_blacklist_on = True

def start_hashes_update_thread():
    update_hashes_thread = threading.Thread(target=mb.update_hashes_scheduler, args=(3600,), daemon=True)
    update_hashes_thread.start()

# behaviour monitoring toggle
def toggle_behaviour_monitoring(behaviour_button):
    global is_behaviour_on, behaviour_thread

    if is_behaviour_on:
        # Stop monitoring
        behaviour.stop_monitoring()  # Menghentikan pemantauan
        if behaviour_thread:
            behaviour_thread.join()  # Tunggu hingga thread monitoring selesai
        behaviour_button.configure(text="Behaviour Monitoring[OFF]", fg_color="red")
        is_behaviour_on = False
    else:
        # Start monitoring in a separate thread
        behaviour_thread = threading.Thread(target=behaviour.start_monitoring)
        behaviour_thread.start()
        behaviour_button.configure(text="Behaviour Monitoring[ON]", fg_color="green")
        is_behaviour_on = True

# Toggle protection status (both Honeypot and Yara Scan)
def toggle_protection(protection_button):
    global is_protection_on, is_yara_on, is_yara_file_on , protection_thread, yara_thread , yara_file_thread
    if is_protection_on and is_yara_on and is_yara_file_on:
        is_protection_on = False
        is_yara_on = False
        is_yara_file_on = False
        protection_button.configure(text="Protection-[OFF]", fg_color="red")

        # Hentikan Honeypot dan Yara Scan
        stop_honey_thread()
        stop_yara_scan_thread()
        stop_yara_file_thread()

    else:
        is_protection_on = True
        is_yara_on = True
        is_yara_file_on = True
        protection_button.configure(text="Protection-[ON]", fg_color="green")

        # Set up log window title and clean terminal
        ctypes.windll.kernel32.SetConsoleTitleW(f"RansomPyShield Log , {app_version} [Protection ON]")
        os.system("cls")
        print("Realtime Monitor ON [Honeypot]")
        print("Yara Scan ON")

        # Bersihkan dan salin file ke folder "Honey"
        hm.clean_and_copy_honey_files()
        time.sleep(2)  # Beri waktu untuk menyelesaikan salinan file Honeypot

        # Mulai Honeypot dan Yara Scan monitoring thread
        protection_thread = threading.Thread(target=antiransomware)
        protection_thread.start()

        yara_thread = threading.Thread(target=ys.monitor_processes)
        yara_thread.start()

        yara_file_thread = threading.Thread(target=ysf.start_monitoring)
        yara_file_thread.start()

#execwatcher.py
def toggle_block_cmd(block_cmd_button):
    global ew
    if ew.is_monitoring:
        ew.stop_monitoring()
        block_cmd_button.configure(text="Exec Watcher[OFF]", fg_color="red")
    else:
        ew.start_monitoring()
        block_cmd_button.configure(text="Exec Watcher[ON]", fg_color="green")

# Open honeypot directory
def open_honeypot_directory():
    if os.path.exists(honeyfiles_path):
        subprocess.Popen(f'explorer "{honeyfiles_path}"')
    else:
        print(f"Path {honeyfiles_path} does not exist.")

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

# UI Section
def help_ui():
    ctk.set_appearance_mode("System")  
    ctk.set_default_color_theme("dark-blue")

    app = ctk.CTk()
    app.geometry("500x300")
    app.title("Panduan")
    
    frame = ctk.CTkScrollableFrame(app, 
                                   width=500,
                                   height=300,
                                   orientation="vertical",
                                   label_text="Panduan Penggunaan",
                                   label_anchor="center")
    frame.pack()
    
    text = """
            1. Klik tombol "Folder Honeypot" pada Aplikasi
            2. Masukan File yang akan menjadi umpan untuk Ransomware 
                 ke dalam folder yang sudah di sediakan
            3. Nyalakan fitur dengan cara klik tombol "Antiransomware"
            4. Biarkan aplikasi berjalan
                (bisa kalian minimize jika mengganggu)
            5. lakukan aktivitas kalian seperti biasa :D

            Jika Aplikasi mendeteksi adanya Ransomware:
            1. Akan ada notifikasi peringatan(MessageBox) yang
                 akan muncul untuk meperingatkan Pengguna
            2. Kalian bisa cek laporan lebih detail nya pada
                 Log Terminal(Waktu,direktori,nama dari proses)
            3. Jika file pada folder Honeypot yang di sediakan terenkripsi 
                 bisa kalian ganti dengan yang baru, tetapi jika tidak
                 biarkan saja

            Notifikasi dan Detail Log pada Terminal hanya akan
            muncul ketika terdeteksi ada nya aktivitas Ransomware
            jika tidak muncul apa apa itu berarti perangkat masih aman
            
            Jenis file yg disarankan sebagai umpan:
            - Dokumen atau Text
            - Gambar atau Foto
            - Video atau Film
            - Audio atau Musik
            - Arsip atau file backup
            - Source Code atau Script
            - file Adobe atau design lain nya
            - beberapa Ransomware juga mentarget file executable(.exe)

            Note: 
            Jika kalian melihat folder hidden bisa jadi itu adalah
            folder milik Aplikasi ini , tolong jgn di hapus ataupun
            di sentuh karena akan mengurangi efektivitas dan memicu 
            keamanan dari aplikasi ini
    """
    label = ctk.CTkLabel(master=frame, text=text, justify="left", anchor="w")
    label.pack()

    app.mainloop()

# On UI Close stop all features
def on_closing():
    global is_protection_on, is_yara_on, app , is_behaviour_on

    if is_protection_on:
        stop_honey_thread()

    if is_yara_on:
        stop_yara_scan_thread()
    
    if is_behaviour_on:
        behaviour.stop_monitoring()
        
    app.destroy()

def main_ui():
    global app
    ctk.set_appearance_mode("System")  
    ctk.set_default_color_theme("dark-blue") 

    app = ctk.CTk()  
    app.geometry("450x350")
    app.title("RansomPyShield")
    app.protocol("WM_DELETE_WINDOW", on_closing)

    # Button Section
    # Help Button
    help_button = ctk.CTkButton(master=app, text="Panduan Penggunaan", command=help_ui)
    help_button.grid(row=0, column=2, padx=20, pady=10)

    # Button Toggle for both protection and Yara scan
    protection_button = ctk.CTkButton(master=app, text="Protection-[OFF]", command=lambda: toggle_protection(protection_button), fg_color="red")
    protection_button.grid(row=0, column=1, padx=20, pady=10)

    # Blacklist Button
    blacklist_button = ctk.CTkButton(master=app, text="Blacklist-[OFF]", command=lambda: toggle_blacklist(blacklist_button), fg_color="red")
    blacklist_button.grid(row=1, column=1, padx=20, pady=10)

    # Tombol untuk toggle BlockCMD monitoring
    block_cmd_button = ctk.CTkButton(master=app, text="Exec Watcher[OFF]", command=lambda: toggle_block_cmd(block_cmd_button), fg_color="red")
    block_cmd_button.grid(row=2, column=1, padx=20, pady=10)

    #Behaviour Monitoring
    behaviour_button = ctk.CTkButton(master=app, text="Behaviour Monitoring[OFF]", command=lambda: toggle_behaviour_monitoring(behaviour_button), fg_color="red")
    behaviour_button.grid(row=3, column=1, padx=20, pady=10)

    # Open RansomPyShield folder 
    open_dir_button = ctk.CTkButton(master=app, text="Folder Honeypot", command=open_honeypot_directory)
    open_dir_button.grid(row=1, column=2, padx=20, pady=10)

    # Quarantine Folder
    open_quarantine_button = ctk.CTkButton(master=app, text="Folder Quarantine", command=open_quarantine_directory)
    open_quarantine_button.grid(row=2, column=2, padx=20, pady=10)

    # Random Text
    text = '''
    ©Devin Nathaniel(XiAnzheng)@2024
    Universitas Gunadarma
    https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware
    '''
    label = ctk.CTkLabel(master=app, text=text, justify="left", anchor="w")
    label.place(relx=0.5, rely=0.7, anchor=ctk.CENTER)

    app.mainloop()

if __name__ == "__main__":
    run_with_uac()
    ctypes.windll.kernel32.SetConsoleTitleW(f"RansomPyShield Log , {app_version} [Protection OFF]")
    hm.create_files_folders()

    # Get YARA rules
    rule = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware/raw/main/Rule.zip"
    zip_rule = "Rule.zip"
    extract_to = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules")

    try:
        print("Updating Hashes & Rules....")
        gr.get_rules(rule, zip_rule, extract_to)
        mb.main()
        print("Blacklist Hashes & Yara Rules Successfully updated")
        update_thread = threading.Thread(target=update_rules_scheduler, daemon=True)
        update_thread.start()
        start_hashes_update_thread()
        main_ui()
    except Exception:
        print("Failed to update one of the protection component. Check your internet connection and re-open this app")
        input("Press anykey to exit")