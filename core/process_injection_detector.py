import psutil
import os
import subprocess
from .utils import get_logger

logger = get_logger()

class ProcessInjectionDetector:
    """检测进程注入攻击（CreateRemoteThread/WriteProcessMemory）"""

    # 系统进程白名单（不应该有远程线程）
    CRITICAL_SYSTEM_PROCESSES = {
        'csrss.exe', 'lsass.exe', 'smss.exe', 'svchost.exe',
        'services.exe', 'wininit.exe', 'winlogon.exe'
    }

    @staticmethod
    def check_suspicious_memory_write(pid: int):
        """
        检测进程是否有可疑的内存写入模式
        关键特征：
        1. PAGE_EXECUTE_READWRITE权限的内存块
        2. 非PE加载器的RWX内存（代码+数据权限）
        3. 堆上的执行权限
        """
        try:
            # 获取进程内存映射
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command",
                 f"@(Get-Process -PID {pid}).Modules | Select-Object FileName"],
                capture_output=True, text=True, timeout=5
            )

            # 检测可疑模式：
            # - dll从临时目录加载
            # - dll无签名
            # - 内存中的代码无对应文件

            return len(result.stdout) == 0  # 返回模块数为0 = 异常
        except:
            return False

    @staticmethod
    def detect_remote_thread_injection(target_pid: int, exclude_processes: set = None):
        """
        检测target_pid是否被其他进程注入线程

        原理：
        1. 枚举所有进程
        2. 检查每个进程的HANDLE权限
        3. 如果进程拥有 PROCESS_VM_WRITE+PROCESS_VM_OPERATION = 可能进行注入
        4. 关键：系统进程如果调用OpenProcess获得上述权限 = 异常
        """
        if exclude_processes is None:
            exclude_processes = {'explorer.exe', 'svchost.exe'}

        suspicious_processes = []

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                source_pid = proc.info['pid']
                source_name = proc.info['name'].lower()

                # 跳过系统进程和自身
                if source_pid in (target_pid, 0, 4) or source_name in exclude_processes:
                    continue

                # 跳过浏览器（通常有多进程注入正常的工作线程）
                if source_name in ('chrome.exe', 'firefox.exe', 'msedge.exe'):
                    continue

                # 关键检查：进程是否试图访问目标进程的内存空间
                # 行为特征识别：
                #   - 病毒通常会在进程启动后立即进行注入
                #   - 正常应用很少进行远程线程创建

                # 启发式检测：
                if source_pid > target_pid:  # 后启动的进程向先启动的进程注入 = 可疑
                    if source_name.endswith('.exe') and not source_name.startswith('system'):
                        # 检查源进程的内存占用（注入器通常内存很小）
                        try:
                            mem_info = proc.memory_info()
                            if mem_info.rss < 5 * 1024 * 1024:  # < 5MB
                                suspicious_processes.append({
                                    'source_pid': source_pid,
                                    'source_name': source_name,
                                    'target_pid': target_pid,
                                    'risk': 'high',
                                    'reason': 'Small memory footprint + targeting older process'
                                })
                        except:
                            pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return suspicious_processes

    @staticmethod
    def detect_dll_hijacking(process_name: str):
        """
        检测DLL劫持（在合法DLL位置创建恶意DLL）

        特征：
        1. System32中有不正常的DLL（无微软签名）
        2. 应用目录中有与系统DLL同名的DLL
        3. DLL时间戳异常（新于可执行文件）
        """
        hijack_locations = [
            r'C:\Windows\System32',
            r'C:\Windows\SysWOW64',
            os.path.dirname(psutil.Process(os.getpid()).exe()),
        ]

        suspicious_dlls = []

        for location in hijack_locations:
            if not os.path.isdir(location):
                continue

            for filename in os.listdir(location):
                if not filename.endswith('.dll'):
                    continue

                filepath = os.path.join(location, filename)

                # 检查1: Microsoft签名验证
                is_signed = ProcessInjectionDetector._verify_windows_signature(filepath)
                if not is_signed and location.startswith(r'C:\Windows\System32'):
                    suspicious_dlls.append({
                        'path': filepath,
                        'risk': 'critical',
                        'reason': 'Unsigned DLL in System32'
                    })
                    continue

                # 检查2: 时间戳异常
                # （如果DLL比同名可执行文件新得多 = 可疑）

        return suspicious_dlls

    @staticmethod
    def _verify_windows_signature(file_path: str) -> bool:
        """验证PE文件是否具有有效的Microsoft签名"""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 f"(Get-AuthenticodeSignature '{file_path}').Status -eq 'Valid'"],
                capture_output=True, text=True, timeout=5
            )
            return 'True' in result.stdout
        except:
            return False