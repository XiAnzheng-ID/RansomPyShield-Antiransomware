# RansomPyShield - Antiransomware

Whats this for? this is my driverless Antiransomware app using Honeypot technique , YARA Rules , And Other stuff

⚠️THIS IS ONLY ACT AS A SECOND OR THIRD LAYER PROTECTION DO NOT USE THIS AS YOUR PRIMARY PROTECTION!!!!
YOU HAVE BEEN WARNED⚠️

⚠️Some Yara Rules that been used by this project are from other public repo and people , credit to their respective owner(check the yara files for more information about them)⚠️

### Video Proof
* <a href="https://www.youtube.com/watch?v=9rO8qLU-3vE">Beta 1</a>
* <a href="https://www.youtube.com/watch?v=Gk2ERkQ_MAs">Optimization Test</a>
* <a href="https://www.youtube.com/watch?v=WKGnyCcJn8c">QoL Update</a>
* <a href="https://www.youtube.com/watch?v=RsOikfXwLHg">Stable Release</a>

### How My Script work?
First my script will create a Honeypot folder called "Honey" (which i recommend to change it before you use or compile it, someday a Ransomware Criminal may see this Repo and skip the Honeypot folder) \
Then user will put their Bait and Dummy file which my script will monitor it as long the script still running \
After user turn on the Realtime Protection my script will take a snapshot of the current running process \
If something touch the Honeypot folder it will kill all process that newly spawned or running after the snapshot

# How to Use?
1. Run my App/Script , dont turn on the feature yet
2. Press "Open Honeypot Folder"
3. Then fill the Folder with dummy file
4. Turn on my Antiransomware Feature
5. Let my app do the work
6. ⚠️REPEAT FROM STEP 3 IF THE DUMMY FILE GOT ENCRYPTED IN THEN RansomPyShield FOLDER ⚠️

# WEAKNESS/KNOWN BUG AND FEATURE
### FEATURES:
* Driverless protection (Rootkit and spyware worry free :D)
* Easy GUI
* Free and Open Source you can Edit and Compile it to your liking or even made your own version for added protection
* Honeypot
* YARA Rules that can be updated automatically (Custom curated By Me from other Public Repo and Place)
* Exploit Blocker(Based on YARA Rules)
* Suspicious Generic Ransomware & Bypass Technique detection (Based on Yara Rules)
* Convention Engine Yara Rules

### Known Weakness and Bug:
* Will close other app and process during detection
* Ransomware sometimes still can Encrypt some of your file
* Doest detect fileless ransomware eg(Screenlocker or Disklocker like Petya) (This is because my app dependd heavily on Yara Rules to detect em)
* Some ransomware can bypass this app by killing this app process or check where's my honeypot file and skip it (i probably know how to fix this?)
* Depends heavily with Windows API library (You need to optimize and rewrite the script again to use on other OS)

# To Be Added (Ideas)
* Machine-Learning (this might take a long time because i need to learn about ML)
* Custom Personal Yara Rule usage
* File & Folder Behaviour Detection
* Whitelist or Blacklist rules
* Memory Dump (Hoping that the Key is in the Memory for further analysis and decryption)

# Tips for fixing some of the weakness
* Rename the folder name of my honeypot folder in the code and check my code and change the logic of my script to your liking!
* Compile my Script using Nuitka into one file executable this can help prevent some Ransomware/Malware kill the Compiled app
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
* BrainChiper (Modified Lockbit 3.0 that attack Indonesia Goverment)
