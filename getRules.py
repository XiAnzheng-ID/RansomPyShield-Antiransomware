import os
import requests
import zipfile

def get_rules(github_url, zip_filename, extract_to):
    # Download file dari GitHub
    response = requests.get(github_url)
    if response.status_code == 200:
        # Download rules
        with open(zip_filename, "wb") as file:
            file.write(response.content)
        
        # Extract zip to extract_to
        with zipfile.ZipFile(zip_filename, 'r') as zip_ref:
            zip_ref.extractall(extract_to)

        # Delete zip after extract
        os.remove(zip_filename)

    else:
        print(f"Failed to update Yara Rules. Status code: {response.status_code}")

if __name__ == "__main__":
    # URLs file zip dari GitHub
    rule = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware/raw/main/Rule.zip"
    yaraForge = "https://github.com/YARAHQ/yara-forge/releases/download/20240818/yara-forge-rules-extended.zip"
    
    # Nama file yang akan diunduh
    zip_rule = "Rule.zip"
    zip_yaraForge = "yara-forge-rules-extended.zip"
    
    # Folder tujuan untuk mengextract file
    extract_to = os.path.join(os.getenv('LOCALAPPDATA'), "RansomPyShield", "Rules")

    # Membuat folder tujuan jika belum ada
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)

    # Download dan extract dari dua URL yang berbeda
    get_rules(rule, zip_rule, extract_to)
    get_rules(yaraForge, zip_yaraForge, extract_to)
    print("All Yara Rules has been updated successfully")
