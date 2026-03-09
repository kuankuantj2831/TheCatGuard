import sys
import os
import shutil
import ctypes
import subprocess
import win32com.client
from PyQt6.QtWidgets import QApplication, QMessageBox

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def create_shortcut(target, location, name):
    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(os.path.join(location, f"{name}.lnk"))
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = os.path.dirname(target)
        shortcut.IconLocation = target
        shortcut.save()
    except Exception as e:
        print(f"Failed to create shortcut: {e}")

def main():
    app = QApplication(sys.argv)

    if not is_admin():
        # Re-run as admin
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    # Define paths
    # Because we used --add-data "dist/TheCatGuard;The Cat Guard", the files are at:
    # sys._MEIPASS / "The Cat Guard"
    
    if hasattr(sys, '_MEIPASS'):
        source_dir = os.path.join(sys._MEIPASS, "The Cat Guard")
    else:
        # Dev mode fallback
        source_dir = os.path.join(os.getcwd(), "dist", "The Cat Guard")

    dest_dir = os.path.expandvars(r"%ProgramFiles%\The Cat Guard")
    
    msg = QMessageBox()
    msg.setWindowTitle("The Cat Guard Setup")
    msg.setText(f"Install 'The Cat Guard' to:\n{dest_dir}?\n\nThis will install the Active Defense service.")
    msg.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
    if msg.exec() != QMessageBox.StandardButton.Ok:
        sys.exit()

    try:
        # 1. Stop existing service if any
        subprocess.run(f'sc stop TheCatGuard', shell=True, capture_output=True)
        subprocess.run(f'sc delete TheCatGuard', shell=True, capture_output=True)
        
        # 2. Copy files
        if os.path.exists(dest_dir):
            try:
                shutil.rmtree(dest_dir)
            except Exception as e:
                # Might be locked
                QMessageBox.critical(None, "Error", f"Failed to clean target directory.\nPlease stop 'The Cat Guard' service manually.\n{e}")
                sys.exit(1)
                
        shutil.copytree(source_dir, dest_dir)
        
        # 3. Install Service
        svc_exe = os.path.join(dest_dir, "TheCatGuardSvc.exe")
        subprocess.run(f'"{svc_exe}" --startup auto install', shell=True, check=True)
        subprocess.run(f'"{svc_exe}" start', shell=True, check=True)
        
        # 4. Create Shortcuts
        gui_exe = os.path.join(dest_dir, "TheCatGuard.exe")
        desktop = os.path.expanduser(r"~\Desktop")
        start_menu = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs")
        
        create_shortcut(gui_exe, desktop, "The Cat Guard")
        create_shortcut(gui_exe, start_menu, "The Cat Guard")
        
        QMessageBox.information(None, "Success", "Installation Complete!\nThe Cat Guard is now protecting your system.")
        
        # Launch GUI
        subprocess.Popen(f'"{gui_exe}"', shell=True)

    except Exception as e:
        QMessageBox.critical(None, "Installation Failed", f"An error occurred during installation:\n{e}")

if __name__ == "__main__":
    main()
