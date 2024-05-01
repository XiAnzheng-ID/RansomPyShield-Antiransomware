# RansomPyShield by XiAnzheng

TO BE RELEASE AFTER MY UNI ACCEPTED MY PAPER AND THESIS!
Whats this for? this is my driverless Antiransomware app using Honeypot technique & YARA Rule

THIS IS ONLY ACT AS A SECOND OR THIRD LAYER PROTECTION DO NOT USE THIS AS YOUR PRIMARY PROTECTION!!!!
YOU HAVE BEEN WARNED

# WEAKNESS/KNOWN BUG AND FEATURE
## FEATURE:
* Driverless protection (Rootkit and spyware worry free :D)
* Easy GUI
* Free and Open Source you can Edit and Compile it to your liking or even made your own version for added protection

## Known Weakness and Bug:
* Sometimes close other app and process during detection 
* Could Miss detection (because point 6)
* Could trigger Bluescreen ( <0.5% chance , why? check Point 1 ) (hey atleast your file doest encrypted i guess?)
* Ransomware sometimes still can Encrypt some of your file (because my app is signature less , behaviour less , and depends on the honeypot files)
* Doest detect fileless ransomware eg(Screenlocker or Disklocker like Petya) (this will be fixed when YARA Rule added on my second thesis)
* Some ransomware can bypass this app by killing the process or check where's my honeypot file and skip it (i probably know how to fix this?)

# To Be Added on my second thesis
* Real-time scanning using YARA Rules (This should fix some of the known problem)

# Tips for fixing some of the weakness
* rename the folder name of my honeypot folder in the code or check my code and change the logic of my script!
