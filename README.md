# RansomPyShield - Antiransomware

TO BE RELEASE AFTER MY UNI ACCEPTED MY PAPER AND THESIS!
Whats this for? this is my driverless Antiransomware app using Honeypot technique & YARA Rule

⚠️THIS IS ONLY ACT AS A SECOND OR THIRD LAYER PROTECTION DO NOT USE THIS AS YOUR PRIMARY PROTECTION!!!!
YOU HAVE BEEN WARNED⚠️

## Video Proof
* <a href="https://www.youtube.com/watch?v=9rO8qLU-3vE">Beta 1</a>
* <a href="https://www.youtube.com/watch?v=Gk2ERkQ_MAs">Optimization Test</a>

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
* Sometimes close other app and process during detection 
* Could Miss detection (because point 6)
* Could trigger Bluescreen ( <0.01% chance , why? check Point 1 ) (hey atleast your file doest encrypted i guess?)
* Ransomware sometimes still can Encrypt some of your file (because my app is signature less , behaviour less , and depends on the honeypot files)
* Doest detect fileless ransomware eg(Screenlocker or Disklocker like Petya) (this will be fixed when YARA Rule added on my second thesis)
* Some ransomware can bypass this app by killing the process or check where's my honeypot file and skip it (i probably know how to fix this?)
* Bug on terminal Menu(i will fix it as soon as possible or when GUI is ready)

# To Be Added on my second thesis
* YARA Rules (This should fix some of the known problem)

# Tips for fixing some of the weakness
* Rename the folder name of my honeypot folder in the code or check my code and change the logic of my script!
* Compile my Script using Nuitka this can help prevent some Ransomware/Malware kill the Compiled app (why? CX_Freeze and PyInstaller only pack our script with Python Intepreter which a lot of ransomware will Encrypt .py extension file )

# Tested against (Windows 10) :
* Wannacry
* Lockbit 3.0(Black)
* Cerber
* Fantom
