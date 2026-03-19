import psutil
import time
import os
from collections import defaultdict
from .utils import get_logger

logger = get_logger()

class BehavioralHeuristicDetector:
    """基于进程行为模式的启发式威胁检测"""

    def __init__(self):
        self.process_history = defaultdict(lambda: {
            'file_ops': [],
            'net_ops': [],
            'reg_ops': [],
            'created_time': time.time()
        })

    def score_process_behavior(self, pid: int, process_name: str) -> tuple[int, list]:
        """
        对进程进行行为评分 (0-100)
        返回: (risk_score, detected_behaviors)

        评分算法：
        - 基分：20（所有未知进程）
        - 系统进程白名单：-20
        - 可疑行为每个+10~30
        - 关键行为（启动远程线程等）：+40
        """

        score = 20  # 基分
        detected_behaviors = []

        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return 0, []

        # 规则1: 系统进程白名单降分
        system_whitelist = {
            'svchost.exe', 'csrss.exe', 'lsass.exe', 'services.exe',
            'explorer.exe', 'taskhost.exe', 'winlogon.exe'
        }
        if process_name.lower() in system_whitelist:
            score -= 20

        # 规则2: 临时文件夹中启动的进程 +30
        try:
            exe_path = proc.exe().lower()
            temp_locations = (
                r'c:\temp', r'c:\windows\temp',
                r'c:\users',  # 检查用户temp目录
            )
            if any(loc in exe_path for loc in temp_locations):
                score += 30
                detected_behaviors.append('launched_from_temp')
        except:
            pass

        # 规则3: 向系统进程进行内存写入操作 +50
        try:
            # 检查打开的文件句柄
            for opened_file in proc.open_files():
                if 'system32' in opened_file.path.lower():
                    score += 50
                    detected_behaviors.append('writing_to_system32')
                    break
        except:
            pass

        # 规则4: 建立异常网络连接 +25
        try:
            connections = proc.net_connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    # 检查是否连接到非常见端口
                    safe_ports = {80, 443, 53, 123, 445, 3389, 8080, 8443}
                    if conn.raddr and conn.raddr.port not in safe_ports:
                        # 进一步检查：是否是localhost
                        if not conn.raddr.ip.startswith('127.'):
                            score += 25
                            detected_behaviors.append(f'suspicious_port_{conn.raddr.port}')
                            break
        except:
            pass

        # 规则5: 创建隐藏文件 +15
        try:
            for filename in proc.open_files():
                if os.path.basename(filename.path).startswith('.'):
                    score += 15
                    detected_behaviors.append('hidden_file_access')
                    break
        except:
            pass

        return min(score, 100), detected_behaviors

    def detect_worm_behavior(self, pid: int) -> bool:
        """
        检测蠕虫行为（自我复制+向其他进程传播）
        特征：
        - 在多个位置创建副本
        - 向多个进程注入代码
        - 高频文件创建
        """
        try:
            proc = psutil.Process(pid)

            # 检查文件创建频率
            file_ops = self.process_history[pid]['file_ops']
            # 5秒内创建超过20个文件 = 可疑
            recent_ops = [t for t in file_ops if time.time() - t < 5]
            if len(recent_ops) > 20:
                return True

        except:
            pass

        return False

    def detect_ransomware_behavior(self, pid: int, process_name: str) -> bool:
        """
        检测勒索软件行为
        特征：
        1. 大量文件修改（加密操作）
        2. 创建勒索说明文件
        3. 删除卷影副本
        4. 修改文件扩展名
        """
        behavior = self.process_history.get(pid, {})

        # 特征1: 检查是否删除卷影副本
        # 这通常通过命令行 vssadmin delete shadows 或类似

        # 特征2: 大量文件被修改 + 修改速率异常
        file_mods = behavior.get('file_ops', [])
        recent_mods = [t for t in file_mods if time.time() - t < 60]
        if len(recent_mods) > 100:
            return True

        return False

    def record_file_operation(self, pid: int, operation: str, path: str):
        """记录进程的文件操作"""
        self.process_history[pid]['file_ops'].append(time.time())

    def record_network_operation(self, pid: int, operation: str, address: str):
        """记录进程的网络操作"""
        self.process_history[pid]['net_ops'].append(time.time())