# RansomPyShield - Antiransomware
Whats this for? this is my pre-configure and driverless Antiransomware app/script using Honeypot technique , YARA Rules , Machine Learning and other stuff
That aim to detect and prevent a total lockdown during a Zero day Ransomware attack where your EDR or Security Solution failed to detect it or Miss Configuration
(Dont worry this app can also Detect already known Ransomware using Yara and Malware Bazaar API)

### ⚠️DISCLAIMER⚠️
* THIS IS ONLY ACT AS A SECOND OR THIRD LAYER PROTECTION DO NOT USE THIS AS YOUR PRIMARY PROTECTION!!!!
* Some Advanced Targeted Ransomware Attack can still bypass this app
* Some Yara Rules that been used by this project are from other public repo and people , credit to their respective owner(check the yara files for more information about them)
* This Tool only act as a Lastline of defense incase there is a miss configuration or a failure of your EDR/Security Solution
* There is a chance some of your files still be encrypted (first and second deep folder&file from root volume is expected to be encrypted during zero day unknown attack)
* Made to be compatible/run with other EDR/Security Program (Report if any EDR/AV detecting or this script behave strange)
* Machine Learning will only kill the detected Process (To Prevent critical file deletion/quarantine)
* Memory Scanner will only quarantined known Signature (To Prevent critical file deletion/quarantine)

(Compile your own version for added protection or again use other EDR/Security Solution)
Report any False Positive and Missed Detection if you can , i really appriciate it

### Video Proof
* <a href="https://www.youtube.com/watch?v=9rO8qLU-3vE">Beta 1</a>
* <a href="https://www.youtube.com/watch?v=Gk2ERkQ_MAs">Optimization Test</a>
* <a href="https://www.youtube.com/watch?v=WKGnyCcJn8c">QoL Update</a>
* <a href="https://www.youtube.com/watch?v=RsOikfXwLHg">Stable Release</a>
* <a href="https://www.youtube.com/watch?v=rz8vNeoxVVE">Yara Implementation</a>
* <a href="https://www.youtube.com/watch?v=wyfi-wtBG_I">Machine Learning</a>

### How My Script work?
* First my script will create a Honeypot folder called "Honey" (which i recommend to change it before you use or compile it, someday a Ransomware Criminal may see this Repo and skip the Honeypot folder) 
* Then user will put their Bait and Dummy file which my script will monitor it as long the script still running 
* After user turn on the Realtime Protection my script will take a snapshot of the current running process, if something touch the Honeypot folder it will kill all process that newly spawned or running after the snapshot

In short : Blacklist > Yara > Behaviour > Honeypot (Lastline of defense)

Execution Watcher will watch all CMD & PS and compare it with my Blacklisted keyword will try to kill those malicious call before it can execute the command

Optional Feature : Panic Button incase some undetected Screenlocker managed to lock the screen & TrustGuard for Windows Hardening

# How to Use?
1. Download Sigcheck from <a href="https://learn.microsoft.com/id-id/sysinternals/downloads/sigcheck">Sysinternals</a>
2. Download blint.exe from <a href="https://github.com/owasp-dep-scan/blint">blint Github</a>
3. Put Sigcheck and blint in the same directory as the script/compiled script
4. Run my App/Script , dont turn on the feature yet
5. Press "Open Honeypot Folder"
6. Then fill the Folder with dummy file
7. Open Settings and turn on any feature you need
8. Let my app do the work

Note:
*To use your own custom Yara Rules just create a new .yar file with name "Custom.yar" in C:\Users\\(Your Username)\AppData\Local\RansomPyShield\Rules
*Got a screenlocker that my app wont detect? dont worry just Press Ctrl + Shift + K , this will kill all new running process after the process snapshot

# WEAKNESS/KNOWN BUG AND FEATURE
### FEATURES:
* Driverless protection (Rootkit and spyware worry free :D)
* Easy GUI
* Free and Open Source you can Edit and Compile it to your liking or even made your own version for added protection
* Honeypot
* Machine Learning trained by myself (XGBoost-Custom Hyperparameter) , that can be update anytime after i do re-train (<a href="https://github.com/XiAnzheng-ID/RansomPyShield-Model">My Machine Learning Model</a>)
* YARA Rules that can be updated automatically (<a href="https://github.com/InQuest/awesome-yara">Custom curated By Me from other Public Repo and Place(InQuest awesome-yara)</a>)
* Exploit Blocker(Based on YARA Rules)
* Suspicious Generic Ransomware & Bypass Technique detection (Based on Yara Rules)
* Convention Engine Yara Rules (<a href="https://github.com/stvemillertime/ConventionEngine/tree/master">Convention Engine Github</a>)
* Blacklist based on Sha256 hash from Malware Bazaar "Query tag" API (<a href="https://bazaar.abuse.ch/">Malware Bazaar</a>)
* ~~Whitelist~~ (Removed , i will try to find a better solution)
* Support your own custom yara rules
* Panic Button (got a Screenlocker? dont worry press Ctrl + Shift + K)
* Suspicious Exec/Command Filter (this will watch all cmd & PS call and compare with my blacklisted keyword that shouldnt be used in a regular user session)
* Folder Behaviour Activity
* TrustGuard (Block all executable with High Entropy, Packed(Yara Rule), Leaked Digital Signer(Yara Rule), Unsigned)

### Known Weakness and Bug:
* there is a chance of False Positive , if this happen just turn off features on settings (report if this happen)
* May/Will close other app and process during detection
* Ransomware sometimes still can Encrypt some of your file
* Some Screenlocker Ransomware can bypass this app (This is because my app depends heavily on Yara Rules , Honeypot , Hash, Machine-Learning)
* Some ransomware can bypass this app by killing this app process or check where's my honeypot file and skip it (i probably know how to fix this?)
* Depends heavily with Windows API library (You need to optimize and rewrite the script again to use on other OS)
* Spaghetti Code (this one i wont fix :P , this was only my side lil project for my uni assignment but ill try to maintain and it as long as possible)
* Still cant detect old Honeypot folder (for now just delete any hidden folder that you dont make manually when the app/script doest running)
* ~~Whitelist still hardcoded on code~~ (Removed , i will try to find a better solution)
* You need Sigcheck from sysinternals for the TrustGuard else it will crash
* You need blint.exe from owasp-dep-scan's Github for the Machine Learning else it will reduced accuracy and increase False Positive
* Machine Learning feature will crash and break if i added new feature during re-training and update the github
* Machine Learning kinda slow because how i use blint.exe instead of the blint library (blint library keep giving me error during pip install , may change in the future)

# To Be Added (Ideas)
* Memory Dump (Hoping that the Key is in the Memory for further analysis and decryption)
* Registry Recovery & Protection
* Simple Anti-Tamper & Self-Defense Mechanism

# Tips for fixing some of the weakness
* Rename the folder name of my honeypot folder in the my code
* Compile my Script using Nuitka this can help prevent some Ransomware/Malware kill the Compiled app
```bash
python -m nuitka --onefile --windows-uac-admin --enable-plugin=tk-inter --include-package=xgboost --remove-output --windows-console-mode=disable RansomPyShield.py
```
or 
```bash
python -m nuitka --standalone --windows-uac-admin --enable-plugin=tk-inter --include-package=xgboost --remove-output --windows-console-mode=disable RansomPyShield.py
```
or 
```bash
python -m nuitka --app --windows-uac-admin --enable-plugin=tk-inter --include-package=xgboost --remove-output 
--windows-console-mode=disable RansomPyShield.py
```
if you still need console for debugging or other stuff just remove the --windows-console-mode=disable argument

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
* And some other random Ransomware & Screenlocker
