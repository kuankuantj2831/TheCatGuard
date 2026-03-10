import threading
import time
import winreg
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
from .utils import get_logger, is_admin
from . import config

logger = get_logger()

_ETW_AVAILABLE = False
if is_admin():
    try:
        import etw
        _ETW_AVAILABLE = True
    except ImportError:
        pass

# ─── 可疑文件扩展名（USB 扫描用） ───
_SUSPICIOUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse',
    '.wsf', '.wsh', '.ps1', '.scr', '.pif', '.com',
}

# ─── 系统进程白名单：进程名 -> 合法路径前缀列表 ───
_SYSTEM_PROCESS_PATHS = {
    'svchost.exe':   [r'C:\Windows\System32', r'C:\Windows\SysWOW64'],
    'csrss.exe':     [r'C:\Windows\System32'],
    'lsass.exe':     [r'C:\Windows\System32'],
    'services.exe':  [r'C:\Windows\System32'],
    'smss.exe':      [r'C:\Windows\System32'],
    'wininit.exe':   [r'C:\Windows\System32'],
    'winlogon.exe':  [r'C:\Windows\System32'],
    'explorer.exe':  [r'C:\Windows'],
    'taskhostw.exe': [r'C:\Windows\System32'],
    'conhost.exe':   [r'C:\Windows\System32'],
    'dllhost.exe':   [r'C:\Windows\System32', r'C:\Windows\SysWOW64'],
    'spoolsv.exe':   [r'C:\Windows\System32'],
    'dwm.exe':       [r'C:\Windows\System32'],
}


class StartupFolderEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            logger.warning(f"SECURITY ALERT: 启动目录新增文件: {event.src_path}")
            # 检查 .lnk 快捷方式指向可疑位置
            if event.src_path.lower().endswith('.lnk'):
                logger.warning(f"SECURITY ALERT: 新增启动快捷方式，请检查其目标: {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            logger.info(f"启动目录文件被修改: {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            logger.info(f"启动目录文件被删除: {event.src_path}")


class FileMonitor:
    def __init__(self):
        self.observer = None
        # 监控当前用户 + 所有用户的启动目录
        self.startup_paths = [
            os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
            r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        ]

    def start(self):
        self.observer = Observer()
        event_handler = StartupFolderEventHandler()
        monitored = []
        for path in self.startup_paths:
            if os.path.isdir(path):
                self.observer.schedule(event_handler, path, recursive=False)
                monitored.append(path)
        if monitored:
            self.observer.start()
            logger.info(f"文件监控已启动，监控 {len(monitored)} 个启动目录")
        else:
            logger.error("未找到任何启动目录")

    def stop(self):
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=3.0)
        self.observer = None


class ProcessMonitor:
    """进程监控：管理员时用 ETW 实时事件，否则回退 psutil 轮询"""
    def __init__(self):
        self.running = False
        self.thread = None
        self._etw_session = None
        self.known_pids = set()

    def start(self):
        self.running = True
        if _ETW_AVAILABLE:
            self._start_etw()
        else:
            self._start_polling()

    def _start_etw(self):
        try:
            PROCESS_GUID = etw.GUID('{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}')
            providers = [etw.ProviderInfo('Microsoft-Windows-Kernel-Process', PROCESS_GUID)]
            self._etw_session = etw.ETW(
                providers=providers,
                event_callback=self._etw_callback,
                event_id_filters=[1],  # ProcessStart only
            )
            self._etw_session.start()
            logger.info("进程监控已启动 [ETW 实时模式]")
        except Exception as e:
            logger.warning(f"ETW 进程监控启动失败，回退轮询: {e}")
            self._etw_session = None
            self._start_polling()

    def _etw_callback(self, event_tuples, context):
        for ev in event_tuples:
            try:
                d = dict(ev) if not isinstance(ev, dict) else ev
                image = d.get('ImageName', '')
                pid = d.get('ProcessID', '?')
                name = os.path.basename(str(image)).lower()
                if not name:
                    continue
                alert = self._check_image(name, str(image), pid)
                if alert:
                    logger.warning(alert)
            except Exception:
                pass

    def _start_polling(self):
        try:
            self.known_pids = set(p.pid for p in psutil.process_iter())
        except Exception:
            pass
        self.thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.thread.start()
        logger.info("进程监控已启动 [轮询模式]")

    def stop(self):
        self.running = False
        if self._etw_session:
            try:
                self._etw_session.stop()
            except Exception:
                pass
            self._etw_session = None
        if self.thread:
            self.thread.join(timeout=1.0)

    def _check_image(self, name, exe_path, pid):
        """检查进程路径是否可疑"""
        # 白名单跳过
        if config.is_process_whitelisted(name) or config.is_path_whitelisted(exe_path):
            return None
        # 黑名单直接告警
        if config.is_process_blacklisted(name):
            return f"SECURITY ALERT: 黑名单进程已启动 {name} (PID:{pid}): {exe_path}"
        if name in _SYSTEM_PROCESS_PATHS:
            exe_norm = os.path.normcase(os.path.normpath(exe_path))
            if not any(exe_norm.startswith(os.path.normcase(p)) for p in _SYSTEM_PROCESS_PATHS[name]):
                return f"SECURITY ALERT: 可疑伪装系统进程 {name} (PID:{pid}) 路径异常: {exe_path}"
        exe_lower = exe_path.lower()
        temp_dirs = [os.path.expandvars(r'%TEMP%').lower(), os.path.expandvars(r'%APPDATA%').lower(), r'c:\users\public']
        if any(exe_lower.startswith(d) for d in temp_dirs):
            if name not in ('setup.exe', 'installer.exe'):
                return f"SECURITY ALERT: 从临时目录启动的进程 {name} (PID:{pid}): {exe_path}"
        return None

    def _check_process(self, proc):
        try:
            return self._check_image(proc.name().lower(), proc.exe(), proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return None

    def _poll_loop(self):
        interval = config.get("process_poll_interval", 1)
        while self.running:
            try:
                current_pids = set(p.pid for p in psutil.process_iter())
                for pid in current_pids - self.known_pids:
                    if not self.running:
                        break
                    try:
                        p = psutil.Process(pid)
                        alert = self._check_process(p)
                        if alert:
                            logger.warning(alert)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                self.known_pids = current_pids
            except Exception as e:
                logger.error(f"Process monitor error: {e}")
            time.sleep(interval)


class RegistryMonitor:
    def __init__(self):
        self.running = False
        self.thread = None
        # 扩展监控范围：覆盖主要自启动注册表位置
        self.watched_keys = [
            # Run / RunOnce
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            # Winlogon Shell / Userinit 劫持
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            # 映像劫持 (IFEO)
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
            # AppInit_DLLs 注入
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows"),
        ]
        # (hkey, path) -> {name: (data, type)} — 同时记录值名和值数据
        self.known_values = {}

    def start(self):
        self.running = True
        self._snapshot()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("注册表监控已启动")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)

    def _snapshot(self):
        for hkey, path in self.watched_keys:
            self.known_values[(hkey, path)] = self._get_values(hkey, path)

    def _get_values(self, hkey_root, path):
        """返回 {name: (data, type)} 字典，同时记录值的数据以检测篡改"""
        values = {}
        try:
            key = winreg.OpenKey(hkey_root, path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, data, vtype = winreg.EnumValue(key, i)
                    values[name] = (data, vtype)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass
        return values

    def _hive_name(self, hkey):
        return "HKCU" if hkey == winreg.HKEY_CURRENT_USER else "HKLM"

    def _monitor_loop(self):
        interval = config.get("registry_poll_interval", 2)
        while self.running:
            for hkey, path in self.watched_keys:
                if not self.running:
                    break

                current = self._get_values(hkey, path)
                old = self.known_values.get((hkey, path), {})
                hive = self._hive_name(hkey)

                # 检测新增键值
                for name in current.keys() - old.keys():
                    data = current[name][0]
                    logger.warning(
                        f"SECURITY ALERT: 注册表新增启动项: [{hive}] {path} -> "
                        f"{name} = {data!r}"
                    )

                # 检测值被篡改（名称相同但数据变了）
                for name in current.keys() & old.keys():
                    if current[name] != old[name]:
                        logger.warning(
                            f"SECURITY ALERT: 注册表启动项被修改: [{hive}] {path} -> "
                            f"{name}: {old[name][0]!r} => {current[name][0]!r}"
                        )

                # 检测被删除的键值
                for name in old.keys() - current.keys():
                    logger.info(
                        f"注册表启动项被删除: [{hive}] {path} -> {name}"
                    )

                self.known_values[(hkey, path)] = current

            time.sleep(interval)


class USBMonitor:
    def __init__(self):
        self.running = False
        self.thread = None
        self.wmi = None

    def start(self):
        import wmi
        self.running = True
        try:
            self.wmi = wmi.WMI()
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            logger.info("USB 监控已启动")
        except Exception as e:
            logger.error(f"Failed to start USB Monitor: {e}")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)

    def _scan_drive(self, drive_letter):
        """扫描新插入的 USB 驱动器，检查 autorun.inf 和可疑文件"""
        root = drive_letter + "\\"

        # 1. 检查 autorun.inf
        autorun_path = os.path.join(root, "autorun.inf")
        if os.path.isfile(autorun_path):
            logger.warning(f"SECURITY ALERT: USB {drive_letter} 存在 autorun.inf！")
            try:
                with open(autorun_path, 'r', errors='ignore') as f:
                    content = f.read(2048)
                logger.warning(f"autorun.inf 内容: {content[:500]}")
            except Exception:
                pass

        # 2. 扫描根目录可疑可执行文件
        suspicious = []
        try:
            for entry in os.scandir(root):
                if entry.is_file():
                    ext = os.path.splitext(entry.name)[1].lower()
                    if ext in _SUSPICIOUS_EXTENSIONS:
                        suspicious.append(entry.name)
        except (PermissionError, OSError):
            pass

        if suspicious:
            file_list = ', '.join(suspicious[:10])
            extra = f" 等共 {len(suspicious)} 个" if len(suspicious) > 10 else ""
            logger.warning(
                f"SECURITY ALERT: USB {drive_letter} 根目录发现可疑文件: "
                f"{file_list}{extra}"
            )

    def _reconnect_wmi(self):
        """重新初始化 WMI 连接"""
        try:
            import wmi
            self.wmi = wmi.WMI()
            return True
        except Exception:
            return False

    def _monitor_loop(self):
        if not self.wmi:
            logger.error("USB Monitor: WMI not initialized, cannot monitor.")
            return

        known_drives = set()
        try:
            known_drives = set(
                d.Caption for d in self.wmi.Win32_LogicalDisk(DriveType=2)
                if d.Caption
            )
        except Exception as e:
            logger.warning(f"USB Monitor: 初始扫描失败: {e}，尝试重连...")
            if self._reconnect_wmi():
                try:
                    known_drives = set(
                        d.Caption for d in self.wmi.Win32_LogicalDisk(DriveType=2)
                        if d.Caption
                    )
                except Exception:
                    pass

        error_count = 0
        while self.running:
            try:
                current_drives = set(
                    d.Caption for d in self.wmi.Win32_LogicalDisk(DriveType=2)
                    if d.Caption
                )
                new_drives = current_drives - known_drives
                for drive in new_drives:
                    logger.warning(f"SECURITY ALERT: 检测到 USB 设备插入: {drive}")
                    self._scan_drive(drive)

                removed_drives = known_drives - current_drives
                for drive in removed_drives:
                    logger.info(f"USB 设备已移除: {drive}")

                known_drives = current_drives
                error_count = 0
            except Exception as e:
                error_count += 1
                if error_count == 1:
                    logger.warning(f"USB Monitor: WMI 查询失败，尝试重连...")
                    self._reconnect_wmi()
                elif error_count == 3:
                    logger.error("USB Monitor: 持续失败，已静默。将每30秒重试一次。")
                # 失败多次后降低轮询频率
                if error_count >= 3:
                    time.sleep(30)
                    continue

            time.sleep(3)


# ─── 本地/私有地址，不应触发告警 ───
import ipaddress as _ipaddress

def _is_local_ip(ip_str):
    """判断 IP 是否为回环或私有地址"""
    try:
        addr = _ipaddress.ip_address(ip_str)
        return addr.is_loopback or addr.is_private or addr.is_link_local
    except ValueError:
        return False


class NetworkMonitor:
    """网络连接监控：检测可疑外连"""

    # 同一 (进程名, IP) 的告警冷却时间（秒）
    _ALERT_COOLDOWN = 60

    @staticmethod
    def _safe_ports():
        return set(config.get("safe_ports", [80, 443, 53, 67, 68, 123, 5353, 1900]))

    def __init__(self):
        self.running = False
        self.thread = None
        self.known_conns = set()
        self._alert_history = {}  # (name, ip) -> last_alert_time

    def start(self):
        self.running = True
        self._snapshot()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("网络监控已启动")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)

    def _snapshot(self):
        self.known_conns = self._get_connections()

    def _get_connections(self):
        conns = set()
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.status == 'ESTABLISHED' and c.raddr:
                    conns.add((c.pid, c.raddr.ip, c.raddr.port))
        except (psutil.AccessDenied, OSError):
            pass
        return conns

    def _should_alert(self, name, ip):
        """同一 (进程, IP) 在冷却期内只告警一次"""
        key = (name, ip)
        now = time.time()
        last = self._alert_history.get(key, 0)
        if now - last < self._ALERT_COOLDOWN:
            return False
        self._alert_history[key] = now
        return True

    def _monitor_loop(self):
        while self.running:
            try:
                current = self._get_connections()
                new_conns = current - self.known_conns
                for pid, ip, port in new_conns:
                    if not self.running:
                        break
                    # 跳过本地回环和私有地址
                    if _is_local_ip(ip):
                        continue
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        name = "unknown"
                    if config.is_ip_whitelisted(ip):
                        continue
                    if port not in self._safe_ports():
                        if self._should_alert(name, ip):
                            logger.warning(
                                f"SECURITY ALERT: 可疑网络连接 {name}(PID:{pid}) -> {ip}:{port}"
                            )
                    else:
                        logger.debug(f"网络连接: {name}(PID:{pid}) -> {ip}:{port}")
                self.known_conns = current
            except Exception as e:
                logger.error(f"Network monitor error: {e}")
            time.sleep(config.get("network_poll_interval", 3))


class MonitorManager:
    """Manages all monitors centrally."""
    def __init__(self):
        self.file_monitor = FileMonitor()
        self.process_monitor = ProcessMonitor()
        self.registry_monitor = RegistryMonitor()
        self.usb_monitor = USBMonitor()
        self.network_monitor = NetworkMonitor()
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
        self.network_monitor.start()
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
        try:
            self.network_monitor.stop()
        except Exception as e:
            logger.error(f"Error stopping network monitor: {e}")
        logger.info("All monitors stopped.")

    @property
    def is_running(self):
        return self._running
