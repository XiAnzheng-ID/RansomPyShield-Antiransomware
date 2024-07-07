# RansomPyShield - Antiransomware

TO BE RELEASE AFTER MY UNI ACCEPTED MY PAPER AND THESIS!
Whats this for? this is my driverless Antiransomware app using Honeypot technique & YARA Rule

⚠️THIS IS ONLY ACT AS A SECOND OR THIRD LAYER PROTECTION DO NOT USE THIS AS YOUR PRIMARY PROTECTION!!!!
YOU HAVE BEEN WARNED⚠️

### Video Proof
* <a href="https://www.youtube.com/watch?v=9rO8qLU-3vE">Beta 1</a>
* <a href="https://www.youtube.com/watch?v=Gk2ERkQ_MAs">Optimization Test</a>

### How My Script work?
> First my script will create a Honeypot folder called "Honey" (which i recommend to change it before you use or compile it, someday a Ransomware Criminal may see this Repo and skip the Honeypot folder
> Then user will put their Bait and Dummy file which my script will monitor it as long the script still running
> After user turn on the Realtime Protection my script will take a snapshot of the current running process
> if something touch the Honeypot folder it will kill all process that newly spawned or running after the snapshot

# How to Use?
1. Run my App/Script , dont turn on the feature yet
2. Enable Show Hidden Folder from File Explorer, then open my "Honey" Folder at:
* Desktop
* Download
* Document
* Pictures
* Music
* Videos
* C:\\
3. Then fill the "Honey" Folder with dummy file, the more file in there the better my Script will work
4. Turn on my Antiransomware Feature
5. ⚠️REPEAT FROM STEP 3 IF THE DUMMY FILE GOT ENCRYPTED , DONT FORGET TO CLOSE MY APP FIRST ⚠️

# WEAKNESS/KNOWN BUG AND FEATURE
### FEATURES:
* Driverless protection (Rootkit and spyware worry free :D)
* Easy GUI
* Free and Open Source you can Edit and Compile it to your liking or even made your own version for added protection

### Known Weakness and Bug:
* Will close other app and process during detection
* Ransomware sometimes still can Encrypt some of your file (because my app is signature less , behaviour less , and depends on the honeypot files)
* Doest detect fileless ransomware eg(Screenlocker or Disklocker like Petya) (i may or not may know how to add detection against this type of Ransomware)
* Some ransomware can bypass this app by killing this app process or check where's my honeypot file and skip it (i probably know how to fix this?)
* Depends heavily with Windows API library (You need to optimize and rewrite the script again to use on other OS)

# To Be Added on my second thesis
* YARA Rules (This should fix some of the known problem)

# Tips for fixing some of the weakness
* Rename the folder name of my honeypot folder in the code and check my code and change the logic of my script!
* Compile my Script using Nuitka into one 1 file executable this can help prevent some Ransomware/Malware kill the Compiled app
```bash
python -m nuitka --onefile --windows-uac-admin --enable-plugin=tk-inter --remove-output main.py
```
Why? CX_Freeze and PyInstaller only pack our script with Python Intepreter which a lot of ransomware will Encrypt .py extension file \
Tho there are some Ransomware that encrypt .pyd files the onefile make sure that this app unpack itself in /temp \
Which Ransomware either dont Encrypt or Need time to access that directory which give time this app to detect and kill the Ransomware

# Tested against (Windows 10) :
* Wannacry
* Lockbit 3.0(Black)
* Cerber
* Fantom
* BlackChiper (Modified Lockbit 3.0 that attack Indonesia Goverment)
