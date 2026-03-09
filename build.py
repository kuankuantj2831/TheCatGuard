import os
import subprocess
import shutil
import sys

def run_command(command):
    print(f"Running: {command}")
    try:
        subprocess.check_call(command, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Error building: {e}")
        sys.exit(1)

def main():
    # 0. Kill existing processes to release file locks
    try:
        subprocess.run("taskkill /F /IM TheCatGuard.exe", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run("taskkill /F /IM TheCatGuardSvc.exe", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run("taskkill /F /IM TheCatGuard_Setup.exe", shell=True, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # 1. Clean previous build
    if os.path.exists("dist"):
        try:
            shutil.rmtree("dist")
        except Exception as e:
            print(f"Warning: Could not clean dist folder: {e}")
            
    if os.path.exists("build"):
        try:
            shutil.rmtree("build")
        except Exception as e:
            print(f"Warning: Could not clean build folder: {e}")

    print("Building The Cat Guard GUI...")
    # Build GUI
    python_exe = sys.executable
    run_command(f'"{python_exe}" -m PyInstaller --clean --noconsole --onedir --name TheCatGuard --add-data "assets;assets" main.py')

    print("Building The Cat Guard Service...")
    # Build Service
    run_command(f'"{python_exe}" -m PyInstaller --clean --noconsole --onedir --name TheCatGuardSvc --hidden-import=win32timezone --hidden-import=core.service core/service.py')

    # Merge dist folders? 
    # PyInstaller creates dist/TheCatGuard and dist/TheCatGuardSvc.
    # We want them in the same folder to share the same install location.
    # Actually, it's easier to just copy the Service EXE to the GUI folder and hope dependencies match, 
    # OR (Safest) just keep them separate directories and copy both, 
    # OR build into the same directory using --distpath.
    
    # Safe approach: Merge contents. 
    source_svc = "dist/TheCatGuardSvc"
    dest_dir = "dist/TheCatGuard"
    
    print("Merging Service into Main Distribution...")
    for item in os.listdir(source_svc):
        s = os.path.join(source_svc, item)
        d = os.path.join(dest_dir, item)
        if os.path.isdir(s):
            # Checking if dir exists
            if not os.path.exists(d):
                shutil.copytree(s, d)
        else:
            # If file doesn't exist, copy it. If it exists, it's likely a shared DLL, simpler to skip or overwrite.
            if not os.path.exists(d):
                shutil.copy2(s, d)

    # Now dist/TheCatGuard contains everything.
    
    print("Building Setup.exe...")
    # Compile installer.py, embedding the entire dist/TheCatGuard folder
    # Note: --add-data format is "source;dest" on Windows
    # We are adding the whole folder "dist/TheCatGuard" to "DATA/TheCatGuard" inside the installer
    run_command(f'"{python_exe}" -m PyInstaller --noconsole --onefile --name TheCatGuard_Setup --add-data "dist/TheCatGuard;The Cat Guard" installer.py')

    print("Build Complete! Check dist/TheCatGuard_Setup.exe")

if __name__ == "__main__":
    main()
