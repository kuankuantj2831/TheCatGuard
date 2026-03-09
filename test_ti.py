import sys
import os
import time

# Ensure core module is importable
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.utils import is_admin
from core.privileges import TrustedInstaller

def test_ti_escalation():
    if not is_admin():
        print("Please run this script as Administrator first!")
        return

    print("Attempting to launch CMD as TrustedInstaller...")
    
    # We will try to launch a command prompt. 
    # If successful, whoami /groups in that prompt should show "TrustedInstaller".
    # Since RunAsTI launches hidden by default in our code, let's try to launch something visible or check logs.
    # For now, let's just run a benign command and check return status.
    
    success = TrustedInstaller.run_as_ti("cmd.exe /c echo 'Running as TrustedInstaller' > ti_test.txt")
    
    if success:
        print("Success! Process launched. Check for ti_test.txt")
    else:
        print("Failed to launch process.")

if __name__ == "__main__":
    test_ti_escalation()
