import threading
import time
import winreg
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
from .utils import get_logger

logger = get_logger()

class StartupFolderEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            logger.warning(f"SECURITY ALERT: New file created in Startup folder: {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            logger.info(f"File modified in Startup folder: {event.src_path}")

class FileMonitor:
    def __init__(self):
        self.observer = None
        self.startup_path = os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup')

    def start(self):
        if not os.path.exists(self.startup_path):
            logger.error(f"Startup folder not found: {self.startup_path}")
            return
        
        self.observer = Observer()
        event_handler = StartupFolderEventHandler()
        self.observer.schedule(event_handler, self.startup_path, recursive=False)
        self.observer.start()
        logger.info(f"File Monitor started on {self.startup_path}")

    def stop(self):
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=3.0)
        self.observer = None

class ProcessMonitor:
    def __init__(self):
        self.running = False
        self.thread = None
        self.known_pids = set()

    def start(self):
        self.running = True
        try:
            self.known_pids = set(p.pid for p in psutil.process_iter())
        except Exception as e:
            logger.error(f"Error initializing process list: {e}")
            
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Process Monitor started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)

    def _monitor_loop(self):
        while self.running:
            try:
                current_pids = set(p.pid for p in psutil.process_iter())
                new_pids = current_pids - self.known_pids
                
                for pid in new_pids:
                    try:
                        if not self.running: break
                        p = psutil.Process(pid)
                        logger.debug(f"New Process: {p.name()} (PID: {pid})")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                self.known_pids = current_pids
            except Exception as e:
                logger.error(f"Process monitor error: {e}")
                
            time.sleep(1) # Poll every second

class RegistryMonitor:
    def __init__(self):
        self.running = False
        self.thread = None
        self.watched_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        self.known_values = {}  # (hkey, path) -> set of value names

    def start(self):
        self.running = True
        self._snapshot()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Registry Monitor started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)

    def _snapshot(self):
        for hkey, path in self.watched_keys:
            self.known_values[(hkey, path)] = self._get_values(hkey, path)

    def _get_values(self, hkey_root, path):
        values = set()
        try:
            key = winreg.OpenKey(hkey_root, path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, _, _ = winreg.EnumValue(key, i)
                    values.add(name)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass # Key might not exist
        return values

    def _monitor_loop(self):
        while self.running:
            for hkey, path in self.watched_keys:
                if not self.running: break
                
                current_values = self._get_values(hkey, path)
                old_values = self.known_values.get((hkey, path), set())
                
                new_entries = current_values - old_values
                hive_name = "HKCU" if hkey == winreg.HKEY_CURRENT_USER else "HKLM"
                for name in new_entries:
                    logger.warning(f"SECURITY ALERT: New Startup Registry Key: [{hive_name}] {path} -> {name}")
                
                self.known_values[(hkey, path)] = current_values
            
            time.sleep(2) # Poll every 2 seconds

class USBMonitor:
    def __init__(self):
        self.running = False
        self.thread = None
        self.wmi = None

    def start(self):
        import wmi # Lazy import
        self.running = True
        try:
            self.wmi = wmi.WMI()
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            logger.info("USB Monitor started")
        except Exception as e:
            logger.error(f"Failed to start USB Monitor: {e}")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)

    def _monitor_loop(self):
        if not self.wmi:
            logger.error("USB Monitor: WMI not initialized, cannot monitor.")
            return

        logger.info("Listening for USB device events...")

        # Polling approach for USB drive detection
        known_drives = set()
        try:
            known_drives = set(
                d.Caption for d in self.wmi.Win32_LogicalDisk(DriveType=2)
                if d.Caption
            )
        except Exception as e:
            logger.warning(f"USB Monitor: initial drive scan failed: {e}")

        error_count = 0
        while self.running:
            try:
                current_drives = set(
                    d.Caption for d in self.wmi.Win32_LogicalDisk(DriveType=2)
                    if d.Caption
                )
                new_drives = current_drives - known_drives
                for drive in new_drives:
                    logger.warning(f"SECURITY ALERT: USB Drive Inserted: {drive}")

                removed_drives = known_drives - current_drives
                for drive in removed_drives:
                    logger.info(f"USB Drive Removed: {drive}")

                known_drives = current_drives
                error_count = 0
            except Exception as e:
                error_count += 1
                if error_count <= 3:
                    logger.warning(f"USB Monitor error ({error_count}/3): {e}")
                elif error_count == 4:
                    logger.error("USB Monitor: repeated errors, suppressing further messages.")

            time.sleep(3)


class MonitorManager:
    """Manages all monitors centrally."""
    def __init__(self):
        self.file_monitor = FileMonitor()
        self.process_monitor = ProcessMonitor()
        self.registry_monitor = RegistryMonitor()
        self.usb_monitor = USBMonitor()
        self._running = False

    def start_all(self):
        if self._running:
            return
        self._running = True
        logger.info("Starting all monitors...")
        self.file_monitor.start()
        self.process_monitor.start()
        self.registry_monitor.start()
        self.usb_monitor.start()
        logger.info("All monitors started.")

    def stop_all(self):
        if not self._running:
            return
        self._running = False
        logger.info("Stopping all monitors...")
        try:
            self.process_monitor.stop()
        except Exception as e:
            logger.error(f"Error stopping process monitor: {e}")
        try:
            self.registry_monitor.stop()
        except Exception as e:
            logger.error(f"Error stopping registry monitor: {e}")
        try:
            self.usb_monitor.stop()
        except Exception as e:
            logger.error(f"Error stopping USB monitor: {e}")
        try:
            self.file_monitor.stop()
        except Exception as e:
            logger.error(f"Error stopping file monitor: {e}")
        logger.info("All monitors stopped.")

    @property
    def is_running(self):
        return self._running
