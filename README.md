# RansomPyShield - Antiransomware

Whats this for? this is my driverless Antiransomware app using Honeypot technique , YARA Rules , And Other stuff

⚠️THIS IS ONLY ACT AS A SECOND OR THIRD LAYER PROTECTION DO NOT USE THIS AS YOUR PRIMARY PROTECTION!!!!
YOU HAVE BEEN WARNED⚠️

⚠️Some Yara Rules that been used by this project are from other public repo and people , credit to their respective owner(check the yara files for more information about them)⚠️

Report any False Positive and Missed Detection if you can , i really appriciate it

### Video Proof
* <a href="https://www.youtube.com/watch?v=9rO8qLU-3vE">Beta 1</a>
* <a href="https://www.youtube.com/watch?v=Gk2ERkQ_MAs">Optimization Test</a>
* <a href="https://www.youtube.com/watch?v=WKGnyCcJn8c">QoL Update</a>
* <a href="https://www.youtube.com/watch?v=RsOikfXwLHg">Stable Release</a>
* <a href="https://www.youtube.com/watch?v=rz8vNeoxVVE">Yara Implementation</a>

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
6. ⚠️REPEAT FROM STEP 3 IF THE DUMMY FILE GOT ENCRYPTED IN THE RansomPyShield FOLDER ⚠️

To use your own custom Yara Rules just create a new .yar file with name "Custom" in C:\Users\\(Your Username)\AppData\Local\RansomPyShield\Rules

Got a screenlocker that my app wont detect? dont worry just Press Ctrl + Shift + K , this will kill all new running process after the process snapshot

# WEAKNESS/KNOWN BUG AND FEATURE
### FEATURES:
* Driverless protection (Rootkit and spyware worry free :D)
* Easy GUI
* Free and Open Source you can Edit and Compile it to your liking or even made your own version for added protection
* Honeypot
* YARA Rules that can be updated automatically (<a href="https://github.com/InQuest/awesome-yara">Custom curated By Me from other Public Repo and Place(InQuest awesome-yara)</a>)
* Exploit Blocker(Based on YARA Rules)
* Suspicious Generic Ransomware & Bypass Technique detection (Based on Yara Rules)
* Convention Engine Yara Rules (<a href="https://github.com/stvemillertime/ConventionEngine/tree/master">Convention Engine Github</a>)
* Blacklist based on Sha256 hash from Malware Bazaar "Query tag" API (<a href="https://bazaar.abuse.ch/">Malware Bazaar</a>)
* Whitelist (Hardcoded on script to make it hard for threat actor to modify the whitelist system , ill find a workaround to make it easier)
* Support your own custom yara rules
* Panic Button (got a Screenlocker? dont worry press Ctrl + Shift + K)
* Suspicious Exec/Command Filter (this will watch all cmd call and compare with my blacklisted keyword that shouldnt be used in a regular user session)

### Known Weakness and Bug:
* there is a chance of False Positive , if this happen just close this app then run the blocked app again (report if this happen)
* Will close other app and process during detection
* Ransomware sometimes still can Encrypt some of your file
* Some Fileless Ransomware can bypass this app(Screenlocker or Disklocker/wiper like Petya) (This is because my app depends heavily on Yara Rules , Honeypot , Hash)
* Some ransomware can bypass this app by killing this app process or check where's my honeypot file and skip it (i probably know how to fix this?)
* Depends heavily with Windows API library (You need to optimize and rewrite the script again to use on other OS)
* if you turn off then turning on the Realtime Protection again the Yara Scan feature wont work anymore (for now just re open the app)
* Spaghetti Code (this one i wont fix :P , this was only my side lil project for my uni assignment but ill try to maintain it as long as possible)
* Still cant detect old Honeypot folder (for now just delete any hidden folder that you dont make manually when the app/script doest running)

# To Be Added (Ideas)
* Machine-Learning (this might take a long time because i need to learn about ML and create a custom Dataset)
* File & Folder Behaviour Detection
* Memory Dump (Hoping that the Key is in the Memory for further analysis and decryption)
* Registry Recovery & Protection
* Simple Anti-Tamper & Self-Defense Mechanism

# Tips for fixing some of the weakness
* Rename the folder name of my honeypot folder in the my code
* Compile my Script using Nuitka this can help prevent some Ransomware/Malware kill the Compiled app
```bash
python -m nuitka --onefile --windows-uac-admin --enable-plugin=tk-inter --remove-output RansomPyShield.py
```
or 
```bash
python -m nuitka --standalone --windows-uac-admin --enable-plugin=tk-inter --remove-output RansomPyShield.py
```
after that put it somewhere else like Program Files or Appdata or wherever you want \
try to put in a place where ransomware will not or rarely target 

Note: Using the onefile option will probably trigger some AV Protection eg Bitdefender \
Why we do all this? CX_Freeze and PyInstaller only pack our script with Python Intepreter which a lot of ransomware will Encrypt .py extension file \
Do remember that this will not protect the compiled app from getting killed or bypassed by some Advanced or targeted Ransomware attack

# Tested against (Windows 10) :
* Wannacry
* Lockbit 3.0(Black)
* Cerber
* Fantom
* BrainChiper (Modified Lockbit 3.0 that attack Indonesia Goverment)
* And some other random Ransomware
