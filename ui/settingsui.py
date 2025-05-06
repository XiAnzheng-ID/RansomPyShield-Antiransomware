import winsound , ctypes , time
import customtkinter as ctk
from honeypot.honeymanager import clean_and_copy_honey_files
from honeypot.foldermonitor import start_honeypot_monitor , stop_honeypot_monitor
from yaramodule.yarascan import start_yara_monitor , stop_yara_monitor
from blacklist.blacklistscan import start_hash_monitor , stop_hash_monitor
from protectmodule.trustguard import start_trustguard_monitor , stop_trustguard_monitor
from protectmodule.execwatcher import start_monitoring_cmd , stop_monitoring_cmd
from protectmodule.behaviour import start_behaviour_monitoring , stop_behaviour_monitoring
from machinelearning.runmodel import start_ml_monitoring , stop_ml_monitoring

switch_states = {
    "honeypot": "off",
    "yara": "off",
    "blacklist": "off",
    "execwatcher": "off",
    "behaviour": "off",
    "trustguard": "off",
    "machinelearning": "off"
}

def settings_ui():
    ctk.set_appearance_mode("System")  
    ctk.set_default_color_theme("dark-blue")

    app = ctk.CTk()
    app.geometry("500x300")
    app.resizable(False, False)
    app.title("Settings")

    #Honeypot Monitoring
    def honeypot_switch_callback(honeypot_switch):
        switch_states["honeypot"] = honeypot_switch.get()
        if honeypot_switch.get() == "on":
            clean_and_copy_honey_files()
            time.sleep(2)
            start_honeypot_monitor()
        else:
            stop_honeypot_monitor()

    honeypot_switch = ctk.StringVar(value=switch_states["honeypot"])
    honeypot_switch = ctk.CTkSwitch(master=app,
                                     text="Honeypot",
                                     variable=honeypot_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=lambda: honeypot_switch_callback(honeypot_switch))
    honeypot_switch.pack(padx=20, pady=10)
    
    # YARA Switch
    def yara_switch_callback(yara_switch):
        switch_states["yara"] = yara_switch.get()
        if yara_switch.get() == "on":
            start_yara_monitor()
        else:
            stop_yara_monitor()

    yara_switch = ctk.StringVar(value=switch_states["yara"])
    yara_switch = ctk.CTkSwitch(master=app,
                                     text="Yara Scan",
                                     variable=yara_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=lambda: yara_switch_callback(yara_switch))
    yara_switch.pack(padx=20, pady=10)

    #Machinelearning
    def machinelearning_switch_callback(machinelearning_switch):
        switch_states["machinelearning"] = machinelearning_switch.get()
        if machinelearning_switch.get() == "on":
            start_ml_monitoring()
        else:
            stop_ml_monitoring()

    machinelearning_switch = ctk.StringVar(value=switch_states["machinelearning"])
    machinelearning_switch = ctk.CTkSwitch(master=app,
                                     text="Machinelearning",
                                     variable=machinelearning_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=lambda:machinelearning_switch_callback(machinelearning_switch))
    machinelearning_switch.pack(padx=20, pady=10)

    #Black-List
    def blacklist_switch_callback(blacklist_switch):
        switch_states["blacklist"] = blacklist_switch.get()
        if blacklist_switch.get() == "on":
            start_hash_monitor()
        else:
            stop_hash_monitor()

    blacklist_switch = ctk.StringVar(value=switch_states["blacklist"])
    blacklist_switch = ctk.CTkSwitch(master=app,
                                     text="Malwarebazaar Hash Blacklist",
                                     variable=blacklist_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=lambda:blacklist_switch_callback(blacklist_switch))
    blacklist_switch.pack(padx=20, pady=10)

    #Execution Watcher
    def exec_switch_callback(exec_switch):
        switch_states["execwatcher"] = exec_switch.get()
        if exec_switch.get() == "on":
            winsound.MessageBeep(winsound.MB_ICONASTERISK) 
            ctypes.windll.user32.MessageBoxW(0, "This feature may break any app that using the blacklisted commands", "Execution Watcher", 0x40 | 0x1000) 
            start_monitoring_cmd()
        else:
            stop_monitoring_cmd()

    exec_switch = ctk.StringVar(value=switch_states["execwatcher"])
    exec_switch = ctk.CTkSwitch(master=app,
                                     text="Execution Watcher",
                                     variable=exec_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=lambda: exec_switch_callback(exec_switch))
    exec_switch.pack(padx=20, pady=10)

    #Folder Behaviour
    def behaviour_switch_callback(behaviour_switch):
        switch_states["behaviour"] = behaviour_switch.get()
        if behaviour_switch.get() == "on":
            start_behaviour_monitoring()
        else:
            stop_behaviour_monitoring()

    behaviour_switch = ctk.StringVar(value=switch_states["behaviour"])
    behaviour_switch = ctk.CTkSwitch(master=app,
                                     text="Folder Behaviour",
                                     variable=behaviour_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=lambda: behaviour_switch_callback(behaviour_switch))
    behaviour_switch.pack(padx=20, pady=10)

    #TrustGuard
    def trustguard_switch_callback(trustguard_switch):
        switch_states["trustguard"] = trustguard_switch.get()
        if trustguard_switch.get() == "on":
            start_trustguard_monitor()
        else:
            stop_trustguard_monitor()

    trustguard_switch = ctk.StringVar(value=switch_states["trustguard"])
    trustguard_switch = ctk.CTkSwitch(master=app,
                                     text="TrustGuard",
                                     variable=trustguard_switch,
                                     onvalue="on",
                                     offvalue="off",
                                     command=lambda: trustguard_switch_callback(trustguard_switch))
    trustguard_switch.pack(padx=20, pady=10)

    app.mainloop()

if __name__ == "__main__":
    settings_ui()