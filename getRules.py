import os
import requests
import zipfile

def download_and_extract_github_file(github_url, extract_to):
    # Nama file yang akan didownload
    zip_filename = "Rule.zip"

    # Download file dari GitHub
    response = requests.get(github_url)
    if response.status_code == 200:
        # Download rules
        with open(zip_filename, "wb") as file:
            file.write(response.content)
        

        # Extract zip to extract_to
        with zipfile.ZipFile(zip_filename, 'r') as zip_ref:
            zip_ref.extractall(extract_to)

        # Delete zip after extract extract
        os.remove(zip_filename)
        print("Yara Rules updated successfully")

    else:
        print(f"Failed to update Yara Rules. Status code: {response.status_code}")

if __name__ == "__main__":
    # URL file zip dari GitHub
    github_url = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware/raw/main/Rule.zip"
    
    # Folder tujuan untuk mengextract file
    extract_to = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules")

    # Membuat folder tujuan jika belum ada
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)

    download_and_extract_github_file(github_url, extract_to)