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

# Variabel global untuk mengelola status toggle
is_protection_on = False
protection_thread = None

#variabel lain
appdata_path = os.getenv('LOCALAPPDATA')
honeyfiles_path = os.path.join(appdata_path, "RansomPyShield")

# Membuat folder RansomPyShield jika belum ada
if not os.path.exists(honeyfiles_path):
    try:
        os.makedirs(honeyfiles_path)
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
def run_antiransomware_thread():
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
def stop_antiransomware_thread():
    fm.stop_monitoring()
    if protection_thread:
        protection_thread.join()
    ctypes.windll.kernel32.SetConsoleTitleW("RansomPyShield Log , v10.07.2024 [Protection OFF]")
    os.system("cls")
    print("Realtime Monitor OFF") 

# Toggle protection status
def toggle_protection(button):
    global is_protection_on
    if is_protection_on:
        is_protection_on = False
        button.configure(text="Antiransomware-[OFF]", fg_color="red")
        stop_antiransomware_thread()
    else:
        is_protection_on = True
        button.configure(text="Antiransomware-[ON]", fg_color="green")
        run_antiransomware_thread()

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
    app.geometry("500x300")
    app.title("RansomPyShield")

    #Button Section
    # Help Button
    help_button = ctk.CTkButton(master=app, text="Panduan Penggunaan", command=help_ui)
    help_button.place(relx=0.5, rely=0.2, anchor=ctk.CENTER)

    # Button Toggle
    button = ctk.CTkButton(master=app, text="Antiransomware-[OFF]", command=lambda: toggle_protection(button), fg_color="red")
    button.place(relx=0.25, rely=0.5, anchor=ctk.CENTER)

    # Open RansomPyShield folder 
    open_dir_button = ctk.CTkButton(master=app, text="Folder Honeypot", command=lambda: open_directory())
    open_dir_button.place(relx=0.75, rely=0.5, anchor=ctk.CENTER)

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
    print("Realtime Monitor OFF") 
    hm.create_files_folders()
    main_ui()