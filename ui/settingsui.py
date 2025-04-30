import customtkinter as ctk
import winsound , ctypes
from honeypot.honeymanager import clean_and_copy_honey_files
from honeypot.foldermonitor import start_honeypot_monitor , stop_honeypot_monitor
from yaramodule.yarascanfile import start_monitoring , stop_monitoring
from yaramodule.yarascan import start_yara_monitor , stop_yara_monitor
from blacklist.blacklistscan import start_hash_monitor , stop_hash_monitor
from protectmodule.trustguard import start_trustguard_monitor , stop_trustguard_monitor
from protectmodule.execwatcher import start_monitoring_cmd , stop_monitoring_cmd
from protectmodule.behaviour import start_behaviour_monitoring , stop_behaviour_monitoring

def settings_ui():
    ctk.set_appearance_mode("System")  
    ctk.set_default_color_theme("dark-blue")

    app = ctk.CTk()
    app.geometry("500x300")
    app.title("Settings")

    #Honeypot Monitoring
    def honeypot_switch_callback():
        if honeypot_switch.get() == "on":
            clean_and_copy_honey_files()
            start_honeypot_monitor()
        else:
            stop_honeypot_monitor()

    honeypot_switch = ctk.StringVar(value="off")
    honeypot_switch = ctk.CTkSwitch(master=app,
                                     text="Honeypot Monitoring",
                                     variable=honeypot_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=honeypot_switch_callback)
    honeypot_switch.pack(padx=20, pady=10)
    
    # YARA Switch
    def yara_switch_callback():
        if yara_switch.get() == "on":
            start_monitoring()
            start_yara_monitor()
        else:
            stop_monitoring()
            stop_yara_monitor()

    yara_switch = ctk.StringVar(value="off")
    yara_switch = ctk.CTkSwitch(master=app,
                                     text="Yara Scan",
                                     variable=yara_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=yara_switch_callback)
    yara_switch.pack(padx=20, pady=10)

    #Black-List
    def blacklist_switch_callback():
        if blacklist_switch.get() == "on":
            start_hash_monitor()
        else:
            stop_hash_monitor()

    blacklist_switch = ctk.StringVar(value="off")
    blacklist_switch = ctk.CTkSwitch(master=app,
                                     text="Malwarebazaar Hash Blacklist",
                                     variable=blacklist_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=blacklist_switch_callback)
    blacklist_switch.pack(padx=20, pady=10)

    #Execution Watcher
    def protect_switch_callback():
        if protect_switch.get() == "on":
            winsound.MessageBeep(winsound.MB_ICONASTERISK) 
            ctypes.windll.user32.MessageBoxW(0, "This feature may break any app that using the blacklisted commands", "Execution Watcher", 0x40 | 0x1000) 
            start_monitoring_cmd()
        else:
            stop_monitoring_cmd()

    protect_switch = ctk.StringVar(value="off")
    protect_switch = ctk.CTkSwitch(master=app,
                                     text="Execution Watcher",
                                     variable=protect_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=protect_switch_callback)
    protect_switch.pack(padx=20, pady=10)

    #Folder Behaviour
    def behaviour_switch_callback():
        if behaviour_switch.get() == "on":
            start_behaviour_monitoring()
        else:
            stop_behaviour_monitoring()

    behaviour_switch = ctk.StringVar(value="off")
    behaviour_switch = ctk.CTkSwitch(master=app,
                                     text="Folder Behaviour",
                                     variable=behaviour_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=behaviour_switch_callback)
    behaviour_switch.pack(padx=20, pady=10)

    #TrustGuard
    def trustguard_switch_callback():
        if trustguard_switch.get() == "on":
            start_trustguard_monitor()
        else:
            stop_trustguard_monitor()

    trustguard_switch = ctk.StringVar(value="off")
    trustguard_switch = ctk.CTkSwitch(master=app,
                                     text="TrustGuard",
                                     variable=trustguard_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=trustguard_switch_callback)
    trustguard_switch.pack(padx=20, pady=10)

    app.mainloop()

if __name__ == "__main__":
    settings_ui()