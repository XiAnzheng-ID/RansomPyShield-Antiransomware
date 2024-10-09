import os
import ctypes
import elevate
import threading
import subprocess
import time
import customtkinter as ctk
# other scripts
import honeymanager as hm
import foldermonitor as fm
import getRules as gr
import yarascan as ys
import malwarebazaar as mb
import blacklist as bl

# Var
is_protection_on = False
is_yara_on = False
is_blacklist_on = False
protection_thread = None
yara_thread = None
blacklist_thread = None
app_version = "29.08.2024"

# Other Folder
appdata_path = os.getenv('LOCALAPPDATA')
honeyfiles_path = os.path.join(appdata_path, "RansomPyShield", "Honey")
rules_path = os.path.join(appdata_path, "RansomPyShield", "Rules")

# Membuat folder RansomPyShield jika belum ada
if not os.path.exists(honeyfiles_path) and not os.path.exists(rules_path):
    try:
        os.makedirs(honeyfiles_path)
        os.makedirs(rules_path)
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

# Update Yara rules periodically
def update_rules_scheduler(interval=3600):  # 3600 seconds = 1 hour
    while True:
        try:
            print("Checking for Yara Rules update...")
            rule = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware/raw/main/Rule.zip"
            zip_rule = "Rule.zip"
            extract_to = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules")
            gr.get_rules(rule, zip_rule, extract_to)
            print("Yara Rules updated successfully.")
        except Exception as e:
            print(f"Failed to update Yara Rules: {e}")
        
        # Wait for the next interval
        time.sleep(interval)

# Start Blacklist monitoring
def run_blacklist_thread():
    global blacklist_thread
    print("Blacklist Monitoring ON")
    blacklist_thread = bl.start_monitoring_thread(os.path.join(appdata_path, "RansomPyShield", "Hashes.txt"))

# Stop Blacklist monitoring
def stop_blacklist_thread():
    # Fungsi untuk menghentikan pemantauan blacklist harus ditambahkan di monitor.py
    if blacklist_thread:
        bl.stop_monitoring() 
        # Contoh jika ada fungsi stop_monitoring() di monitor.py
        # monitor.stop_monitoring()  # Hentikan loop di blacklist monitoring
        blacklist_thread.join()

def toggle_blacklist(blacklist_button):
    global is_blacklist_on
    if is_blacklist_on:
        stop_blacklist_thread()
        blacklist_button.configure(text="Blacklist-[OFF]", fg_color="red")
        is_blacklist_on = False
    else:
        run_blacklist_thread()
        blacklist_button.configure(text="Blacklist-[ON]", fg_color="green")
        is_blacklist_on = True

def start_hashes_update_thread():
    update_hashes_thread = threading.Thread(target=mb.update_hashes_scheduler, args=(3600,), daemon=True)
    update_hashes_thread.start()

# Toggle protection status (both Honeypot and Yara Scan)
def toggle_protection(protection_button):
    global is_protection_on, is_yara_on, protection_thread, yara_thread
    
    if is_protection_on and is_yara_on:
        # Matikan kedua fitur jika keduanya aktif
        is_protection_on = False
        is_yara_on = False
        protection_button.configure(text="Protection-[OFF]", fg_color="red")

        # Hentikan Honeypot dan Yara Scan
        stop_honey_thread()
        stop_yara_scan_thread()

    else:
        # Nyalakan kedua fitur jika keduanya tidak aktif
        is_protection_on = True
        is_yara_on = True
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

# Open directory
def open_directory():
    if os.path.exists(honeyfiles_path):
        subprocess.Popen(f'explorer "{honeyfiles_path}"')
    else:
        print(f"Path {honeyfiles_path} does not exist.")

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
    global is_protection_on, is_yara_on, app

    if is_protection_on:
        stop_honey_thread()

    if is_yara_on:
        stop_yara_scan_thread()
    
    app.destroy()

def main_ui():
    global app
    # Themes
    ctk.set_appearance_mode("System")  
    ctk.set_default_color_theme("dark-blue") 

    # CTk window information
    app = ctk.CTk()  
    app.geometry("450x250")
    app.title("RansomPyShield")
    app.protocol("WM_DELETE_WINDOW", on_closing)

    # Button Section
    # Help Button
    help_button = ctk.CTkButton(master=app, text="Panduan Penggunaan", command=help_ui)
    help_button.grid(row=0, column=2, padx=20, pady=10)

    # Button Toggle for both protection and Yara scan
    protection_button = ctk.CTkButton(master=app, text="Protection-[OFF]", command=lambda: toggle_protection(protection_button), fg_color="red")
    protection_button.grid(row=0, column=1, padx=20, pady=10)

    blacklist_button = ctk.CTkButton(master=app, text="Blacklist-[OFF]", command=lambda: toggle_blacklist(blacklist_button), fg_color="red")
    blacklist_button.grid(row=1, column=1, padx=20, pady=10)

    # Open RansomPyShield folder 
    open_dir_button = ctk.CTkButton(master=app, text="Folder Honeypot", command=open_directory)
    open_dir_button.grid(row=1, column=2, padx=20, pady=10)

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