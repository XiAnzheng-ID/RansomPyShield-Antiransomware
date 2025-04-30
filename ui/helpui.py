import customtkinter as ctk

# UI Section
def help_ui():
    ctk.set_appearance_mode("System")  
    ctk.set_default_color_theme("dark-blue")

    app = ctk.CTk()
    app.geometry("500x300")
    app.title("How To Use")
    
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