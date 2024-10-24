import os
import ctypes
import shutil
import psutil

folder_name = "Honey"
file_name = "Honey.txt"

def create_files_folders():
    
    folders = ["Desktop", "Downloads", "Documents", "Pictures", "Videos", "Music", "C:\\Users", os.path.expanduser('~')]
    for folder in folders:
        path = os.path.join(os.path.expanduser("~"), folder)
        if not os.path.exists(path):
            os.makedirs(path)

        # Honey folder in each folder
        honey_folder_path = os.path.join(path, folder_name)
        if not os.path.exists(honey_folder_path):
            os.makedirs(honey_folder_path)

        # Hide Honey folder
        if not is_hidden(honey_folder_path):
            ctypes.windll.kernel32.SetFileAttributesW(honey_folder_path, 2) 

        # Honey.txt on each folder
        honey_txt_path = os.path.join(path, file_name)
        if not os.path.exists(honey_txt_path):
            with open(honey_txt_path, "w") as file:
                for i in range(1000):
                    file.write(f"Hello from Honey.txt in {folder}! (Line {i+1})\n")

        # Hide Honey.txt
        if not is_hidden(honey_txt_path):
            ctypes.windll.kernel32.SetFileAttributesW(honey_txt_path, 2) 
  
    # Honey folder and Honey.txt on all drives
    for drive in get_all_drives():
        if os.access(drive, os.W_OK):  # Check if drive is writable
            honey_folder_path_drive = os.path.join(drive, folder_name)
            if not os.path.exists(honey_folder_path_drive):
                os.makedirs(honey_folder_path_drive)

            # Hide Honey folder on drive
            if not is_hidden(honey_folder_path_drive):
                ctypes.windll.kernel32.SetFileAttributesW(honey_folder_path_drive, 2)

            # Honey.txt on each drive
            honey_txt_path_drive = os.path.join(drive, file_name)
            if not os.path.exists(honey_txt_path_drive):
                with open(honey_txt_path_drive, "w") as file:
                    for i in range(1000):
                        file.write(f"Hello from {file_name} on drive {drive}! (Line {i+1})\n")

            # Hide Honey.txt on drive
            if not is_hidden(honey_txt_path_drive):
                ctypes.windll.kernel32.SetFileAttributesW(honey_txt_path_drive, 2)

def get_all_drives():
    drives = [drive.device.split()[0] for drive in psutil.disk_partitions()]
    return drives

def is_hidden(path):
    try:
        attributes = os.stat(path).st_file_attributes
        return attributes & 2 != 0  
    except FileNotFoundError:
        return False  

def clean_and_copy_honey_files():
    folders = ["Desktop", "Downloads", "Documents", "Pictures", "Videos", "Music", "C:\\Users", os.path.expanduser('~')]
    honeyfiles_path = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Honey")

    if not os.path.exists(honeyfiles_path):
        print(f"Path {honeyfiles_path} does not exist.")
        os.system("exit")
        return

    for folder in folders:
        honey_folder_path = os.path.join(os.path.expanduser("~"), folder, folder_name)
        if os.path.exists(honey_folder_path):
            clean_and_copy(honey_folder_path, honeyfiles_path)

    # Honey folder on all drives
    for drive in get_all_drives():
        if os.access(drive, os.W_OK):  # Check if drive is writable
            honey_folder_path_drive = os.path.join(drive, folder_name)
            if os.path.exists(honey_folder_path_drive):
                clean_and_copy(honey_folder_path_drive, honeyfiles_path)

def clean_and_copy(destination, source):
    # Hapus semua isi folder Honey
    for filename in os.listdir(destination):
        file_path = os.path.join(destination, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f'Failed to delete {file_path}. Reason: {e}')
            
    # Salin file dari Honeyfiles ke Honey
    for filename in os.listdir(source):
        src_file = os.path.join(source, filename)
        dest_file = os.path.join(destination, filename)
        try:
            if os.path.isdir(src_file):
                shutil.copytree(src_file, dest_file)
            else:
                shutil.copy(src_file, dest_file)
        except Exception as e:
            print(f'Failed to copy {src_file} to {dest_file}. Reason: {e}')
