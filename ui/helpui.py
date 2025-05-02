import customtkinter as ctk

# UI Section
def help_ui():
    ctk.set_appearance_mode("System")  
    ctk.set_default_color_theme("dark-blue")

    app = ctk.CTk()
    app.geometry("500x300")
    app.title("How To Use")
    
    frame = ctk.CTkScrollableFrame(app, 
                                   width=500,
                                   height=300,
                                   orientation="vertical",
                                   label_text="Panduan Penggunaan",
                                   label_anchor="center")
    frame.pack()
    
    text = """
          How to Use:

          1. Click "Honeypot Folder" in the App.
          2. Place decoy files (for Ransomware) into the provided folder.
          3. Turn on the feature by clicking "Antiransomware".
          4. Let the app run (minimize if needed).
          5. Continue your normal activities.

          If Ransomware is Detected:
          1. A warning message (MessageBox) or Notification will appear.
          2. Check the Log Terminal for details (if you prefer it).
          3. If files in the Honeypot folder are encrypted, you can replace them. Otherwise, leave them.

          Notifications and the Log Terminal will only appear when Ransomware activity 
          is detected. If nothing appears, your device is likely safe.

          Recommended Decoy File Types:
          - Documents or Text
          - Images or Photos
          - Videos or Movies
          - Audio or Music
          - Archives or Backups
          - Source Code or Scripts
          - Adobe or other design files
          - Some Ransomware targets executable (.exe) files.

          Note:
          Hidden folders might belong to this App. Please do not delete or modify them, 
          as this can reduce the App's effectiveness and security.
    """
    label = ctk.CTkLabel(master=frame, text=text, justify="left", anchor="w")
    label.pack()

    app.mainloop()