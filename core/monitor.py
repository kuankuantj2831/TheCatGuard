import threading
import time
import winreg
import ctypes
import ctypes.wintypes
import hashlib
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
from .utils import get_logger, is_admin
from . import config
from .heuristic_detector import BehavioralHeuristicDetector
from .process_injection_detector import ProcessInjectionDetector

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
        # 向360学习：添加行为启发式和注入检测
        self.heuristic_detector = BehavioralHeuristicDetector()
        self.injection_detector = ProcessInjectionDetector()

    @staticmethod
    def _terminate_process(pid, name=""):
        """强制终止可疑进程"""
        try:
            p = psutil.Process(pid)
            p.kill()
            logger.warning(f"DEFENSE: 已击杀可疑进程 {name}(PID:{pid})")
        except psutil.NoSuchProcess:
            pass  # 进程已经退出
        except psutil.AccessDenied:
            logger.error(f"DEFENSE: 无权击杀进程 {name}(PID:{pid})，权限不足")
        except Exception as e:
            logger.error(f"DEFENSE: 击杀进程失败 {name}(PID:{pid}): {e}")

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
                if isinstance(ev, dict):
                    d = ev
                elif hasattr(ev, 'items'):
                    d = dict(ev)
                elif hasattr(ev, '__getitem__'):
                    d = dict(ev)
                else:
                    continue
                image = str(d.get('ImageName', '') or '')
                pid = d.get('ProcessID', '?')
                name = os.path.basename(image).lower()
                if not name:
                    continue
                alert = self._check_image(name, image, pid)
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
        """检查进程路径是否可疑，黑名单进程直接击杀"""
        # 白名单跳过
        if config.is_process_whitelisted(name) or config.is_path_whitelisted(exe_path):
            return None
        # 黑名单直接击杀 + 告警
        if config.is_process_blacklisted(name):
            self._terminate_process(pid, name)
            return f"SECURITY ALERT: 黑名单进程已击杀 {name} (PID:{pid}): {exe_path}"
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
            name = proc.name().lower()
            exe_path = proc.exe()
            pid = proc.pid

            # 基础路径检查
            alert = self._check_image(name, exe_path, pid)
            if alert:
                return alert

            # 向360学习：行为启发式检测
            if config.get("heuristic_detection.enabled", True):
                risk_score, behaviors = self.heuristic_detector.score_process_behavior(pid, name)
                threshold = config.get("heuristic_detection.risk_threshold", 50)
                if risk_score >= threshold:
                    behaviors_str = ", ".join(behaviors) if behaviors else "未知行为"
                    logger.warning(
                        f"SECURITY ALERT: 进程行为可疑 {name}(PID:{pid}) - 风险评分:{risk_score}/100, 触发行为:{behaviors_str}"
                    )

            # 向360学习：进程注入检测
            if config.get("injection_detection.enabled", True):
                suspicious_injections = self.injection_detector.detect_remote_thread_injection(pid)
                if suspicious_injections:
                    for inj in suspicious_injections:
                        logger.critical(
                            f"SECURITY ALERT: 检测到进程注入 {name}(PID:{pid}) <- {inj['source_name']}(PID:{inj['source_pid']}) - {inj['reason']}"
                        )

            return None
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
        logger.debug("进程监控轮询线程已退出")


class RegistryMonitor:
    """注册表主动防御：监控关键注册表位置，检测篡改并自动回滚"""
    def __init__(self):
        self.running = False
        self.thread = None
        self.protect_mode = True  # True = 自动回滚，False = 仅告警
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
        # 关键系统值白名单 — 这些值被修改时必须回滚
        self._critical_values = {
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"): {
                "Shell": "explorer.exe",
                "Userinit": r"C:\Windows\system32\userinit.exe,",
            },
        }
        # (hkey, path) -> {name: (data, type)} — 同时记录值名和值数据
        self.known_values = {}

    def start(self):
        self.running = True
        self.protect_mode = config.get("registry_protect", True)
        self._snapshot()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info(f"注册表监控已启动 [保护模式: {'开启' if self.protect_mode else '关闭'}]")

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

    def _rollback_value(self, hkey, path, name, data, vtype):
        """回滚注册表值到之前的状态"""
        try:
            key = winreg.OpenKey(hkey, path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, name, 0, vtype, data)
            winreg.CloseKey(key)
            hive = self._hive_name(hkey)
            logger.warning(
                f"DEFENSE: 注册表已回滚: [{hive}] {path} -> {name} = {data!r}"
            )
            return True
        except Exception as e:
            logger.error(f"DEFENSE: 注册表回滚失败: {e}")
            return False

    def _delete_value(self, hkey, path, name):
        """删除未授权的注册表新增值"""
        try:
            key = winreg.OpenKey(hkey, path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            hive = self._hive_name(hkey)
            logger.warning(
                f"DEFENSE: 已删除未授权注册表项: [{hive}] {path} -> {name}"
            )
            return True
        except Exception as e:
            logger.error(f"DEFENSE: 删除注册表项失败: {e}")
            return False

    def _is_critical_tamper(self, hkey, path, name, new_data):
        """检查是否为关键系统值被篡改"""
        critical = self._critical_values.get((hkey, path), {})
        if name in critical:
            expected = critical[name]
            if isinstance(new_data, str):
                return new_data.lower().strip() != expected.lower().strip()
        return False

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
                    # 保护模式：自动删除未授权的新增启动项
                    if self.protect_mode:
                        self._delete_value(hkey, path, name)
                        current = self._get_values(hkey, path)  # 刷新

                # 检测值被篡改（名称相同但数据变了）
                for name in current.keys() & old.keys():
                    if current[name] != old[name]:
                        logger.warning(
                            f"SECURITY ALERT: 注册表启动项被修改: [{hive}] {path} -> "
                            f"{name}: {old[name][0]!r} => {current[name][0]!r}"
                        )
                        # 关键系统值被篡改 → 强制回滚
                        if self._is_critical_tamper(hkey, path, name, current[name][0]):
                            logger.critical(
                                f"DEFENSE: 关键系统注册表被篡改！正在回滚 {name}"
                            )
                            self._rollback_value(hkey, path, name, old[name][0], old[name][1])
                            current = self._get_values(hkey, path)
                        elif self.protect_mode:
                            # 普通启动项被修改 → 回滚
                            self._rollback_value(hkey, path, name, old[name][0], old[name][1])
                            current = self._get_values(hkey, path)

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
            # 监控 TCP ESTABLISHED + UDP 连接
            for c in psutil.net_connections(kind='inet'):
                if c.raddr:
                    if c.status == 'ESTABLISHED' or c.type == 2:  # 2 = SOCK_DGRAM (UDP)
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


# ═══════════════════════════════════════════════════════════
#  MBR 保护模块 — 备份 MBR 并定期校验，被篡改时自动恢复
# ═══════════════════════════════════════════════════════════

class MBRProtector:
    """MBR（主引导记录）主动防御

    原理：
    1. 启动时读取磁盘前 512 字节（MBR）并保存为基线
    2. 定期重新读取 MBR 与基线比对哈希
    3. 如果哈希不一致 → MBR 被篡改 → 自动从备份恢复
    需要管理员/SYSTEM 权限才能读写 PhysicalDrive。
    """

    MBR_SIZE = 512  # 标准 MBR 大小
    BACKUP_DIR = os.path.join(os.environ.get("APPDATA", ""), "TheCatGuard", "mbr_backup")

    def __init__(self):
        self.running = False
        self.thread = None
        self._baseline_hash = None
        self._baseline_data = None
        self._drive_path = r"\\.\PhysicalDrive0"

    def start(self):
        if not is_admin():
            logger.warning("MBR 保护需要管理员权限，跳过")
            return
        self.running = True
        # 建立基线
        if self._init_baseline():
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            logger.info("MBR 保护已启动 [实时校验模式]")
        else:
            logger.error("MBR 保护启动失败：无法读取 MBR 基线")
            self.running = False

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3.0)

    def _read_mbr(self) -> bytes | None:
        """通过 Windows API 读取 MBR（前 512 字节）"""
        try:
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3

            handle = ctypes.windll.kernel32.CreateFileW(
                self._drive_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if handle == -1 or handle == ctypes.wintypes.HANDLE(-1).value:
                err = ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()
                logger.error(f"MBR: 无法打开 {self._drive_path}，错误码: {err}")
                return None

            try:
                buf = ctypes.create_string_buffer(self.MBR_SIZE)
                bytes_read = ctypes.wintypes.DWORD(0)
                ok = ctypes.windll.kernel32.ReadFile(
                    handle, buf, self.MBR_SIZE, ctypes.byref(bytes_read), None
                )
                if ok and bytes_read.value == self.MBR_SIZE:
                    return buf.raw
                else:
                    logger.error(f"MBR: ReadFile 失败，读取 {bytes_read.value} 字节")
                    return None
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception as e:
            logger.error(f"MBR: 读取异常: {e}")
            return None

    def _write_mbr(self, data: bytes) -> bool:
        """通过 Windows API 写入 MBR（恢复用）"""
        if len(data) != self.MBR_SIZE:
            return False
        try:
            GENERIC_WRITE = 0x40000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3

            handle = ctypes.windll.kernel32.CreateFileW(
                self._drive_path,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if handle == -1 or handle == ctypes.wintypes.HANDLE(-1).value:
                return False

            try:
                bytes_written = ctypes.wintypes.DWORD(0)
                ok = ctypes.windll.kernel32.WriteFile(
                    handle, data, self.MBR_SIZE, ctypes.byref(bytes_written), None
                )
                return bool(ok and bytes_written.value == self.MBR_SIZE)
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception as e:
            logger.error(f"MBR: 写入异常: {e}")
            return False

    def _hash_mbr(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _init_baseline(self) -> bool:
        """读取当前 MBR 作为基线，并保存备份文件"""
        data = self._read_mbr()
        if not data:
            return False

        self._baseline_data = data
        self._baseline_hash = self._hash_mbr(data)

        # 保存到磁盘备份
        try:
            os.makedirs(self.BACKUP_DIR, exist_ok=True)
            backup_path = os.path.join(self.BACKUP_DIR, "mbr_baseline.bin")
            hash_path = os.path.join(self.BACKUP_DIR, "mbr_baseline.sha256")

            # 只在首次或哈希不同时写入
            if not os.path.exists(backup_path):
                with open(backup_path, "wb") as f:
                    f.write(data)
                with open(hash_path, "w") as f:
                    f.write(self._baseline_hash)
                logger.info(f"MBR 基线已保存: {self._baseline_hash[:16]}...")
            else:
                # 验证磁盘备份与当前一致
                with open(backup_path, "rb") as f:
                    saved = f.read()
                if self._hash_mbr(saved) != self._baseline_hash:
                    logger.warning("MBR 备份文件与当前 MBR 不一致，更新备份")
                    with open(backup_path, "wb") as f:
                        f.write(data)
                    with open(hash_path, "w") as f:
                        f.write(self._baseline_hash)
        except OSError as e:
            logger.warning(f"MBR 备份保存失败: {e}")

        logger.info(f"MBR 基线哈希: {self._baseline_hash[:16]}...")
        return True

    def _restore_mbr(self) -> bool:
        """从基线恢复 MBR"""
        if not self._baseline_data:
            # 尝试从磁盘备份恢复
            backup_path = os.path.join(self.BACKUP_DIR, "mbr_baseline.bin")
            if os.path.exists(backup_path):
                try:
                    with open(backup_path, "rb") as f:
                        self._baseline_data = f.read()
                except OSError:
                    return False
            else:
                return False

        logger.critical("DEFENSE: 正在恢复 MBR...")
        if self._write_mbr(self._baseline_data):
            logger.critical("DEFENSE: MBR 已成功恢复！")
            return True
        else:
            logger.critical("DEFENSE: MBR 恢复失败！系统可能处于危险状态！")
            return False

    def _monitor_loop(self):
        interval = config.get("mbr_check_interval", 5)
        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            current = self._read_mbr()
            if not current:
                continue

            current_hash = self._hash_mbr(current)
            if current_hash != self._baseline_hash:
                logger.critical(
                    f"SECURITY ALERT: MBR 被篡改！"
                    f"基线: {self._baseline_hash[:16]}... "
                    f"当前: {current_hash[:16]}..."
                )
                # 自动恢复
                if self._restore_mbr():
                    # 验证恢复结果
                    verify = self._read_mbr()
                    if verify and self._hash_mbr(verify) == self._baseline_hash:
                        logger.critical("DEFENSE: MBR 恢复验证通过")
                    else:
                        logger.critical("DEFENSE: MBR 恢复后验证失败！")


# ═══════════════════════════════════════════════════════════
#  系统文件完整性保护 — 监控关键系统文件哈希
# ═══════════════════════════════════════════════════════════

class SystemFileProtector:
    """系统关键文件完整性监控

    原理：
    1. 启动时对关键系统文件计算 SHA256 哈希作为基线
    2. 定期重新计算哈希并与基线比对
    3. 发现篡改时告警，并可调用 sfc /scannow 修复
    """

    # 关键系统文件列表
    CRITICAL_FILES = [
        # 系统核心
        r"C:\Windows\System32\ntoskrnl.exe",
        r"C:\Windows\System32\hal.dll",
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\System32\ntdll.dll",
        # 登录/认证
        r"C:\Windows\System32\winlogon.exe",
        r"C:\Windows\System32\lsass.exe",
        r"C:\Windows\System32\userinit.exe",
        r"C:\Windows\System32\csrss.exe",
        # 服务管理
        r"C:\Windows\System32\services.exe",
        r"C:\Windows\System32\svchost.exe",
        # 网络
        r"C:\Windows\System32\drivers\tcpip.sys",
        r"C:\Windows\System32\drivers\afd.sys",
        # 安全
        r"C:\Windows\System32\bcryptprimitives.dll",
        r"C:\Windows\System32\crypt32.dll",
        # 引导
        r"C:\Windows\System32\winload.exe",
        r"C:\Windows\System32\bootmgr",
        # hosts 文件
        r"C:\Windows\System32\drivers\etc\hosts",
        # 命令行
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ]

    BASELINE_DIR = os.path.join(os.environ.get("APPDATA", ""), "TheCatGuard", "sysfile_baseline")

    def __init__(self):
        self.running = False
        self.thread = None
        self._baseline = {}  # filepath -> sha256
        self._sfc_running = False

    def start(self):
        self.running = True
        self._init_baseline()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info(f"系统文件完整性保护已启动 [监控 {len(self._baseline)} 个文件]")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3.0)

    def _compute_hash(self, filepath: str) -> str | None:
        """计算文件 SHA256"""
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None

    def _init_baseline(self):
        """建立系统文件哈希基线"""
        os.makedirs(self.BASELINE_DIR, exist_ok=True)
        baseline_file = os.path.join(self.BASELINE_DIR, "baseline.txt")

        # 尝试加载已有基线
        saved_baseline = {}
        if os.path.exists(baseline_file):
            try:
                with open(baseline_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if "|" in line:
                            h, p = line.split("|", 1)
                            saved_baseline[p] = h
            except OSError:
                pass

        # 计算当前哈希
        for filepath in self.CRITICAL_FILES:
            if not os.path.exists(filepath):
                continue
            current_hash = self._compute_hash(filepath)
            if not current_hash:
                continue

            if filepath in saved_baseline:
                # 使用已保存的基线（首次启动时的干净状态）
                self._baseline[filepath] = saved_baseline[filepath]
            else:
                # 新文件，当前哈希作为基线
                self._baseline[filepath] = current_hash

        # 保存基线
        self._save_baseline()
        logger.info(f"系统文件基线已建立: {len(self._baseline)} 个文件")

    def _save_baseline(self):
        """保存基线到磁盘"""
        try:
            baseline_file = os.path.join(self.BASELINE_DIR, "baseline.txt")
            with open(baseline_file, "w") as f:
                for filepath, h in sorted(self._baseline.items()):
                    f.write(f"{h}|{filepath}\n")
        except OSError as e:
            logger.warning(f"基线保存失败: {e}")

    def _run_sfc(self):
        """运行 sfc /scannow 修复系统文件"""
        if self._sfc_running or not is_admin():
            return
        self._sfc_running = True
        try:
            import subprocess
            logger.critical("DEFENSE: 正在运行 sfc /scannow 修复系统文件...")
            result = subprocess.run(
                ["sfc", "/scannow"],
                capture_output=True, text=True, timeout=600,
            )
            if result.returncode == 0:
                logger.info("DEFENSE: sfc /scannow 完成")
            else:
                logger.warning(f"DEFENSE: sfc 返回码 {result.returncode}")
        except Exception as e:
            logger.error(f"DEFENSE: sfc 运行失败: {e}")
        finally:
            self._sfc_running = False

    def _monitor_loop(self):
        interval = config.get("sysfile_check_interval", 30)
        while self.running:
            time.sleep(interval)
            if not self.running:
                break

            tampered = []
            for filepath, baseline_hash in self._baseline.items():
                if not self.running:
                    break
                if not os.path.exists(filepath):
                    logger.critical(
                        f"SECURITY ALERT: 系统文件被删除！{filepath}"
                    )
                    tampered.append(filepath)
                    continue

                current_hash = self._compute_hash(filepath)
                if not current_hash:
                    continue

                if current_hash != baseline_hash:
                    logger.critical(
                        f"SECURITY ALERT: 系统文件被篡改！{filepath} "
                        f"(基线: {baseline_hash[:16]}... 当前: {current_hash[:16]}...)"
                    )
                    tampered.append(filepath)

            if tampered:
                logger.critical(
                    f"DEFENSE: 检测到 {len(tampered)} 个系统文件被篡改，"
                    f"启动 SFC 修复..."
                )
                # 在后台线程运行 SFC
                sfc_thread = threading.Thread(target=self._run_sfc, daemon=True)
                sfc_thread.start()

    def refresh_baseline(self):
        """手动刷新基线（系统更新后调用）"""
        self._baseline.clear()
        for filepath in self.CRITICAL_FILES:
            if not os.path.exists(filepath):
                continue
            h = self._compute_hash(filepath)
            if h:
                self._baseline[filepath] = h
        self._save_baseline()
        logger.info(f"系统文件基线已刷新: {len(self._baseline)} 个文件")


class MonitorManager:
    """Manages all monitors centrally."""
    def __init__(self):
        self.file_monitor = FileMonitor()
        self.process_monitor = ProcessMonitor()
        self.registry_monitor = RegistryMonitor()
        self.usb_monitor = USBMonitor()
        self.network_monitor = NetworkMonitor()
        self.mbr_protector = MBRProtector()
        self.sysfile_protector = SystemFileProtector()
        self._running = False

    def start_all(self):
        if self._running:
            return
        self._running = True
        logger.info("Starting all monitors...")
        monitors = [
            ("file", self.file_monitor),
            ("process", self.process_monitor),
            ("registry", self.registry_monitor),
            ("usb", self.usb_monitor),
            ("network", self.network_monitor),
            ("mbr", self.mbr_protector),
            ("sysfile", self.sysfile_protector),
        ]
        for name, mon in monitors:
            try:
                mon.start()
            except Exception as e:
                logger.error(f"{name} monitor 启动失败: {e}")
        logger.info("All monitors started.")

    def stop_all(self):
        if not self._running:
            return
        self._running = False
        logger.info("Stopping all monitors...")
        monitors = [
            ("process", self.process_monitor),
            ("registry", self.registry_monitor),
            ("usb", self.usb_monitor),
            ("file", self.file_monitor),
            ("network", self.network_monitor),
            ("mbr", self.mbr_protector),
            ("sysfile", self.sysfile_protector),
        ]
        for name, mon in monitors:
            try:
                mon.stop()
            except Exception as e:
                logger.error(f"Error stopping {name} monitor: {e}")
        # 确保所有监控线程在超时内退出
        for name, mon in monitors:
            t = getattr(mon, 'thread', None)
            if t and t.is_alive():
                t.join(timeout=3.0)
                if t.is_alive():
                    logger.warning(f"{name} monitor 线程未能在超时内退出")
        logger.info("All monitors stopped.")

    @property
    def is_running(self):
        return self._running
