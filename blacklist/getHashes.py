import requests
import os
import threading
import time

def download_file_from_github(url, save_directory):
    try:
        # Mendapatkan nama file dari URL
        filename = url.split('/')[-1]

        # Membuat direktori jika belum ada
        os.makedirs(save_directory, exist_ok=True)

        # Mendownload file
        response = requests.get(url)
        response.raise_for_status()  # Memastikan request berhasil

        # Menyimpan file
        file_path = os.path.join(save_directory, filename)
        with open(file_path, 'wb') as file:
            file.write(response.content)

        print('Blacklist Hashes Successfully updated')
    except requests.exceptions.RequestException as e:
        print(f'Error saat mendownload file: {e}')
    except Exception as e:
        print(f'Error: {e}')

def check_for_updates(url, save_directory):
    while True:
        print("Checking for updates")
        download_file_from_github(url, save_directory)
        time.sleep(3600)  # Tidur selama 1 jam (3600 detik)

if __name__ == "__main__":
    # Ganti dengan URL file GitHub yang ingin didownload
    github_file_url = 'https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware/raw/main/hashes.txt'
    # Ganti dengan direktori yang ingin Anda simpan
    save_dir = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield")

    # Memulai thread untuk memeriksa pembaruan
    update_thread = threading.Thread(target=check_for_updates, args=(github_file_url, save_dir))
    update_thread.daemon = True  # Membuat thread sebagai daemon
    update_thread.start()

    # Menghindari program utama untuk langsung keluar
    while True:
        time.sleep(1)  # Tidur selama 1 detik agar thread bisa berjalan
