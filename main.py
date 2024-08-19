import os
import ctypes
import elevate
import threading
import subprocess
import time
import customtkinter as ctk
#other script
import honeymanager as hm
import foldermonitor as fm
import getRules as gr
import yarascan as ys

# Variabel global untuk mengelola status toggle
is_protection_on = False
is_yara_on = False
protection_thread = None

#Other Folder
appdata_path = os.getenv('LOCALAPPDATA')
honeyfiles_path = os.path.join(appdata_path, "RansomPyShield", "Honey")
rules_path = os.path.join(appdata_path, "RansomPyShield", "Rules")
#getRules
github_url = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware/raw/main/Rule.zip"
extract_to = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules")

# Membuat folder RansomPyShield jika belum ada
if not os.path.exists(honeyfiles_path and rules_path):
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
        print("Requesting Admin Access , you can close this window")
        elevate.elevate()

# other script
def antiransomware():
    fm.main()

# Run antiransomware in a separate thread
def run_honey_thread():
    global protection_thread
    ctypes.windll.kernel32.SetConsoleTitleW("RansomPyShield Log , v10.07.2024 [Protection ON]")
    os.system("cls")
    print("Realtime Monitor ON [Honeypot]")
    # Bersihkan dan salin file ke folder "Honey"
    hm.clean_and_copy_honey_files()
    time.sleep(2) #let the thread finish clean and copy Honeypot files
    protection_thread = threading.Thread(target=antiransomware)
    protection_thread.start()

# Stop the antiransomware thread
def stop_honey_thread():
    fm.stop_monitoring()
    if protection_thread:
        protection_thread.join()
    ctypes.windll.kernel32.SetConsoleTitleW("RansomPyShield Log , v10.07.2024 [Protection OFF]")
    os.system("cls")
    print("Realtime Monitor OFF") 

# Toggle Honey status
def toggle_honey(honeybutton):
    global is_protection_on
    if is_protection_on:
        is_protection_on = False
        honeybutton.configure(text="Honeypot Monitor-[OFF]", fg_color="red")
        stop_honey_thread()
    else:
        is_protection_on = True
        honeybutton.configure(text="Honeypot Monitor-[ON]", fg_color="green")
        run_honey_thread()

# Start Yara
def run_yara_scan_thread():
    global yara_thread
    ctypes.windll.kernel32.SetConsoleTitleW("RansomPyShield Log , v10.07.2024 [Yara Scan ON]")
    print("Yara Scan ON")
    yara_thread = threading.Thread(target=ys.monitor_processes)
    yara_thread.start()

# Stop YARA
def stop_yara_scan_thread():
    if yara_thread:
        ys.stop_monitoring()  # Hentikan loop di YARA scan
        yara_thread.join()
    ctypes.windll.kernel32.SetConsoleTitleW("RansomPyShield Log , v10.07.2024 [Yara Scan OFF]")
    print("Yara Scan OFF")

def toggle_yara_exploit(yarabutton):
    global is_yara_on
    if is_yara_on:
        is_yara_on = False
        yarabutton.configure(text="Yara Scan & Exploit Blocker-[OFF]", fg_color="red")
        stop_yara_scan_thread()
    else:
        is_yara_on = True
        yarabutton.configure(text="Yara Scan & Exploit Blocker-[ON]", fg_color="green")
        run_yara_scan_thread()

# Open directory
def open_directory():
    if os.path.exists(honeyfiles_path):
        subprocess.Popen(f'explorer "{honeyfiles_path}"')
    else:
        print(f"Path {honeyfiles_path} does not exist.")

#UI Section
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
            Jika kalian melihat folder yg bernama Honey itu adalah
            folder milik Aplikasi ini , tolong jgn di hapus ataupun
            di sentuh karena akan mengurangi efektivitas dan memicu 
            keamanan dari aplikasi ini
            """
    label = ctk.CTkLabel(master=frame, text=text, justify="left", anchor="w")
    label.pack()

    app.mainloop()

def main_ui():
    #Themes
    ctk.set_appearance_mode("System")  
    ctk.set_default_color_theme("dark-blue") 

    app = ctk.CTk()  # CTk window information
    app.geometry("450x250")
    app.title("RansomPyShield")

    #Button Section
    # Help Button
    help_button = ctk.CTkButton(master=app, text="Panduan Penggunaan", command=help_ui)
    help_button.grid(row=0, column=2, padx=20, pady=10)

    # Button Toggle
    honeybutton = ctk.CTkButton(master=app, text="Honeypot Monitor-[OFF]", command=lambda: toggle_honey(honeybutton), fg_color="red")
    honeybutton.grid(row=0, column=1, padx=20, pady=10)

    yarabutton = ctk.CTkButton(master=app, text="Yara Scan & Exploit Blocker-[OFF]", command=lambda: toggle_yara_exploit(yarabutton), fg_color="red")
    yarabutton.grid(row=1, column=1, padx=20, pady=10)

    # Open RansomPyShield folder 
    open_dir_button = ctk.CTkButton(master=app, text="Folder Honeypot", command=lambda: open_directory())
    open_dir_button.grid(row=1, column=2, padx=20, pady=10)
    text = '''
            ©Devin Nathaniel(XiAnzheng)@2024
            Universitas Gunadarma
            https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware
            '''
    label = ctk.CTkLabel(master=app, text=text, justify="left", anchor="w")
    label.place(relx=0.5, rely=0.7, anchor=ctk.CENTER)

    app.mainloop()

if __name__ == "__main__":
    run_with_uac() #get Admin Access if run as script
    ctypes.windll.kernel32.SetConsoleTitleW("RansomPyShield Log , v10.07.2024 [Protection OFF]")
    hm.create_files_folders()
    gr.download_and_extract_github_file(github_url, extract_to)
    main_ui()