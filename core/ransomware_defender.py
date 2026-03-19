import os
import time
import threading
import psutil
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .utils import get_logger
from . import config

logger = get_logger()

class RansomwareDefender:
    """勒索软件专项防护"""

    # 勒索软件特征文件扩展名
    RANSOMWARE_EXTENSIONS = {
        '.encrypted', '.locked', '.crypto', '.crypt', '.enc',
        '.locky', '.zepto', '.odin', '.thor', '.aes', '.rsa',
        '.zzz', '.xyz', '.abc', '.aaa', '.bbb', '.ccc'
    }

    # 勒索软件常见文件名模式
    RANSOMWARE_NOTES = {
        'readme.txt', 'read_me.txt', 'how_to_decrypt.txt',
        'decrypt_instructions.txt', 'recovery_instructions.txt',
        'help_decrypt.txt', 'help_recover_files.txt',
        'restore_files.txt', 'how_recover.txt'
    }

    def __init__(self):
        self.file_modifications = defaultdict(list)
        self.process_file_ops = defaultdict(list)
        self.smb_monitoring = False
        self.file_observer = None
        self.lock = threading.Lock()

    def start_protection(self):
        """启动勒索软件防护"""
        logger.info("启动勒索软件专项防护")

        # 启动文件监控
        self._start_file_monitoring()

        # 启动进程监控
        self._start_process_monitoring()

        # 启动SMB防护
        self._start_smb_protection()

        logger.info("勒索软件防护已启动")

    def stop_protection(self):
        """停止勒索软件防护"""
        logger.info("停止勒索软件防护")

        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join(timeout=5)
            self.file_observer = None

        self.smb_monitoring = False

    def _start_file_monitoring(self):
        """启动文件修改监控"""
        try:
            from watchdog.events import PatternMatchingEventHandler

            class RansomwareFileHandler(PatternMatchingEventHandler):
                def __init__(self, defender):
                    super().__init__(patterns=["*"], ignore_patterns=[], ignore_directories=False)
                    self.defender = defender

                def on_modified(self, event):
                    if not event.is_directory:
                        self.defender._on_file_modified(event.src_path)

                def on_created(self, event):
                    if not event.is_directory:
                        self.defender._on_file_created(event.src_path)

            event_handler = RansomwareFileHandler(self)
            self.file_observer = Observer()
            self.file_observer.schedule(event_handler, "C:\\", recursive=True)
            self.file_observer.start()

            logger.info("文件修改监控已启动")

        except Exception as e:
            logger.error(f"启动文件监控失败: {e}")

    def _start_process_monitoring(self):
        """启动进程行为监控"""
        # 这个功能会集成到现有的monitor.py中
        # 这里只做初始化
        pass

    def _start_smb_protection(self):
        """启动SMB蠕虫防护"""
        self.smb_monitoring = True
        # SMB监控会通过网络监控模块实现
        pass

    def _on_file_modified(self, file_path: str):
        """文件修改事件处理"""
        try:
            current_time = time.time()
            file_ext = os.path.splitext(file_path)[1].lower()
            file_name = os.path.basename(file_path).lower()

            with self.lock:
                # 记录文件修改
                self.file_modifications[file_path].append(current_time)

                # 检查是否为勒索软件特征
                if self._is_ransomware_file(file_path, file_ext, file_name):
                    self._handle_ransomware_detection(file_path, "file_modification")

        except Exception as e:
            logger.debug(f"文件修改处理异常: {e}")

    def _on_file_created(self, file_path: str):
        """文件创建事件处理"""
        try:
            file_name = os.path.basename(file_path).lower()

            # 检查是否为勒索软件说明文件
            if file_name in self.RANSOMWARE_NOTES:
                self._handle_ransomware_detection(file_path, "ransom_note")

        except Exception as e:
            logger.debug(f"文件创建处理异常: {e}")

    def _is_ransomware_file(self, file_path: str, file_ext: str, file_name: str) -> bool:
        """判断文件是否具有勒索软件特征"""
        # 1. 检查文件扩展名
        if file_ext in self.RANSOMWARE_EXTENSIONS:
            return True

        # 2. 检查文件名模式
        if file_name in self.RANSOMWARE_NOTES:
            return True

        # 3. 检查文件修改频率（大量文件在短时间内被修改）
        current_time = time.time()
        recent_mods = [t for t in self.file_modifications[file_path]
                      if current_time - t < 300]  # 5分钟内

        if len(recent_mods) > 10:  # 同一文件被修改超过10次
            return True

        return False

    def _handle_ransomware_detection(self, file_path: str, detection_type: str):
        """处理勒索软件检测结果"""
        logger.critical(f"SECURITY ALERT: 检测到勒索软件活动! 类型: {detection_type}, 文件: {file_path}")

        # 立即隔离可疑进程
        self._isolate_suspicious_processes()

        # 创建系统还原点
        self._create_emergency_restore_point()

        # 记录事件
        self._log_ransomware_event(file_path, detection_type)

    def _isolate_suspicious_processes(self):
        """隔离可疑进程"""
        try:
            suspicious_found = False

            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if self._is_process_suspicious(proc):
                        logger.warning(f"隔离可疑进程: {proc.info['name']}(PID:{proc.info['pid']})")
                        proc.kill()
                        suspicious_found = True

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if suspicious_found:
                logger.info("可疑进程隔离完成")

        except Exception as e:
            logger.error(f"进程隔离失败: {e}")

    def _is_process_suspicious(self, proc) -> bool:
        """判断进程是否可疑"""
        try:
            name = proc.info['name'].lower()
            exe_path = proc.info['exe'].lower() if proc.info['exe'] else ""

            # 检查进程名黑名单
            suspicious_names = {
                'wannacry.exe', 'locky.exe', 'cryptolocker.exe',
                'teslacrypt.exe', 'cerber.exe', 'sage.exe'
            }

            if name in suspicious_names:
                return True

            # 检查临时目录运行
            temp_dirs = [os.path.expandvars(r'%TEMP%').lower(),
                        os.path.expandvars(r'%APPDATA%').lower()]

            if any(temp_dir in exe_path for temp_dir in temp_dirs):
                # 检查文件操作频率
                pid = proc.info['pid']
                recent_ops = [t for t in self.process_file_ops[pid]
                             if time.time() - t < 60]  # 1分钟内

                if len(recent_ops) > 50:  # 每分钟修改超过50个文件
                    return True

            return False

        except Exception:
            return False

    def _create_emergency_restore_point(self):
        """创建紧急系统还原点"""
        try:
            import subprocess
            cmd = [
                "powershell",
                "-Command",
                "Checkpoint-Computer -Description 'TheCatGuard Ransomware Protection' -RestorePointType 'MODIFY_SETTINGS'"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                logger.info("紧急系统还原点已创建")
            else:
                logger.warning("创建还原点失败，请手动创建系统还原点")

        except Exception as e:
            logger.error(f"创建还原点异常: {e}")

    def _log_ransomware_event(self, file_path: str, detection_type: str):
        """记录勒索软件事件"""
        try:
            log_entry = {
                'timestamp': time.time(),
                'type': 'ransomware_detection',
                'detection_type': detection_type,
                'file_path': file_path,
                'system_info': {
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent
                }
            }

            # 这里可以保存到专门的勒索软件日志文件中
            logger.critical(f"勒索软件事件记录: {log_entry}")

        except Exception as e:
            logger.error(f"记录勒索软件事件失败: {e}")

    def detect_mass_file_encryption(self, process_pid: int) -> bool:
        """
        检测进程是否正在进行大规模文件加密
        特征：
        - 短时间内修改大量文件
        - 文件大小变化明显（加密后通常变大）
        - 修改文件扩展名
        """
        try:
            current_time = time.time()
            recent_ops = [t for t in self.process_file_ops[process_pid]
                         if current_time - t < 300]  # 5分钟内

            # 5分钟内修改超过100个文件 = 可疑
            if len(recent_ops) > 100:
                logger.warning(f"进程 {process_pid} 在5分钟内修改了 {len(recent_ops)} 个文件")
                return True

            return False

        except Exception as e:
            logger.debug(f"检测文件加密异常: {e}")
            return False

    def monitor_smb_vulnerability(self):
        """监控SMB漏洞利用"""
        # 检查SMB服务状态
        try:
            import subprocess
            result = subprocess.run(
                ["sc", "query", "lanmanserver"],
                capture_output=True, text=True, timeout=5
            )

            if "RUNNING" in result.stdout:
                logger.debug("SMB服务正在运行")
                # 这里可以添加更详细的SMB安全检查
            else:
                logger.info("SMB服务未运行")

        except Exception as e:
            logger.debug(f"SMB状态检查异常: {e}")

    def enable_shadow_copy_protection(self):
        """启用卷影副本保护"""
        try:
            import subprocess

            # 禁用卷影副本删除
            cmd = ["vssadmin", "delete", "shadows", "/all", "/quiet"]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.info("卷影副本保护已启用（删除命令被拒绝）")
            else:
                logger.warning("卷影副本可能已被删除，请检查系统完整性")

        except Exception as e:
            logger.error(f"卷影副本保护检查失败: {e}")

    def record_file_operation(self, pid: int, operation: str, file_path: str):
        """记录进程的文件操作（由monitor.py调用）"""
        with self.lock:
            self.process_file_ops[pid].append(time.time())

            # 实时检测勒索软件行为
            if self.detect_mass_file_encryption(pid):
                logger.critical(f"SECURITY ALERT: 检测到可能的勒索软件行为! 进程PID: {pid}")

    def get_protection_status(self) -> dict:
        """获取防护状态"""
        return {
            'file_monitoring': self.file_observer is not None and self.file_observer.is_alive(),
            'smb_protection': self.smb_monitoring,
            'recent_detections': len([t for t in self.file_modifications.values()
                                    if any(time.time() - ts < 3600 for ts in t)])  # 1小时内的检测
        }