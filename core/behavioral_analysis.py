"""
行为分析模块 - 实时进程行为分析和异常检测
- 进程行为特征提取（文件访问、网络连接、系统调用）
- 基于历史数据的异常检测（启发式评分）
- 进程族分析和沙箱检测
"""
import os
import json
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import psutil
from .utils import get_logger

logger = get_logger()


class BehaviorAnalyzer:
    """进程行为分析引擎"""
    
    def __init__(self, max_history=1000, anomaly_threshold=70):
        """
        初始化行为分析器
        
        Args:
            max_history: 每个进程的最大历史记录条数
            anomaly_threshold: 异常分数阈值（0-100）
        """
        self.max_history = max_history
        self.anomaly_threshold = anomaly_threshold
        
        # 进程行为历史：pid -> deque of behavior records
        self.process_behaviors = defaultdict(
            lambda: deque(maxlen=max_history)
        )
        
        # 进程风险评分缓存
        self.process_scores = {}
        self.score_lock = threading.Lock()
        
        # 异常事件日志
        self.anomalies = deque(maxlen=100)
        
        # 基线数据（正常进程行为特征）
        self.baseline = self._load_baseline()
        self._update_baseline_thread()
    
    def _load_baseline(self):
        """加载或初始化基线数据"""
        baseline = {
            "normal_file_extensions": [
                ".txt", ".log", ".ini", ".cfg", ".json", ".xml",
                ".dll", ".exe", ".sys", ".tmp", ".dat"
            ],
            "normal_registry_paths": [
                "HKEY_LOCAL_MACHINE\\Software",
                "HKEY_CURRENT_USER\\Software",
                "HKEY_LOCAL_MACHINE\\System"
            ],
            "suspicious_file_extensions": [
                ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".pif"
            ],
            "high_risk_processes": [
                "cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe",
                "regsvcs.exe", "regasm.exe", "nslookup.exe", "whoami.exe"
            ]
        }
        return baseline
    
    def _update_baseline_thread(self):
        """定期更新基线数据"""
        def run():
            while True:
                time.sleep(3600)  # 每小时更新一次
                try:
                    self._recalculate_baseline()
                except Exception as e:
                    logger.error(f"基线更新失败: {e}")
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
    
    def record_behavior(self, pid, process_name, behavior_type, details):
        """
        记录进程行为
        
        Args:
            pid: 进程ID
            process_name: 进程名
            behavior_type: 行为类型 (file_access, network, registry, etc.)
            details: 行为详情字典
        """
        record = {
            "timestamp": datetime.now(),
            "type": behavior_type,
            "details": details,
            "risk_score": self._calculate_behavior_risk(behavior_type, details)
        }
        
        self.process_behaviors[pid].append(record)
        
        # 更新风险评分
        self._update_process_score(pid, process_name)
    
    def _calculate_behavior_risk(self, behavior_type, details):
        """
        计算单个行为的风险分数
        
        Returns:
            risk_score (0-100)
        """
        risk = 0
        
        if behavior_type == "file_access":
            # 文件访问风险评分
            file_path = details.get("path", "").lower()
            access_type = details.get("type", "read")
            
            # 风险路径检测
            high_risk_paths = [
                "\\windows\\system32",
                "\\windows\\drivers",
                "\\programdata\\microsoft\\windows",
                "\\users\\", "\\appdata\\"
            ]
            
            for path in high_risk_paths:
                if path in file_path:
                    risk += 20
                    break
            
            # 风险文件类型检测
            for ext in self.baseline["suspicious_file_extensions"]:
                if file_path.endswith(ext):
                    risk += 30
                    break
            
            # 写入操作权重较高
            if access_type == "write":
                risk += 10
            
        elif behavior_type == "network":
            # 网络连接风险评分
            dest_ip = details.get("dest_ip")
            dest_port = details.get("dest_port", 0)
            
            # 检查系统保留端口
            if dest_port < 1024 and dest_port not in [80, 443, 53]:
                risk += 25
            
            # 检查内网IP
            if self._is_private_ip(dest_ip):
                risk += 15
            
            # 检查已知C&C IP（应该从威胁情报数据库加载）
            risk += 10
            
        elif behavior_type == "registry":
            # 注册表修改风险评分
            reg_path = details.get("path", "").upper()
            reg_type = details.get("type", "read")
            
            # 风险注册表路径
            high_risk_reg = [
                "RUN", "RUNONCE", "STARTUP", "SERVICES",
                "SHELL", "SHELLOPENCOMMAND"
            ]
            
            for pattern in high_risk_reg:
                if pattern in reg_path:
                    risk += 25
                    break
            
            # 写入操作权重较高
            if reg_type == "write":
                risk += 15
        
        elif behavior_type == "process_injection":
            risk = 85  # 进程注入是高风险行为
            
        elif behavior_type == "dll_injection":
            risk = 80
        
        return min(risk, 100)
    
    def _is_private_ip(self, ip):
        """检查是否为私有IP"""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            
            octets = [int(p) for p in parts]
            
            # 10.0.0.0/8
            if octets[0] == 10:
                return True
            # 172.16.0.0/12
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            # 192.168.0.0/16
            if octets[0] == 192 and octets[1] == 168:
                return True
            # 127.0.0.0/8 (本地回环)
            if octets[0] == 127:
                return True
            
            return False
        except:
            return False
    
    def _update_process_score(self, pid, process_name):
        """
        基于历史行为更新进程风险评分
        
        Returns:
            overall_score (0-100)
        """
        if pid not in self.process_behaviors:
            return 0
        
        behaviors = list(self.process_behaviors[pid])
        if not behaviors:
            return 0
        
        # 计算多个维度的评分
        scores = {
            "behavior_risk": 0,
            "frequency_risk": 0,
            "pattern_risk": 0
        }
        
        # 1. 行为风险评分（平均行为风险）
        if behaviors:
            avg_risk = sum(b["risk_score"] for b in behaviors) / len(behaviors)
            scores["behavior_risk"] = min(avg_risk * 1.2, 100)
        
        # 2. 频率风险评分（短时间内频繁操作）
        recent_behaviors = [b for b in behaviors 
                          if (datetime.now() - b["timestamp"]).seconds < 60]
        if len(recent_behaviors) > 10:
            scores["frequency_risk"] = min(len(recent_behaviors) * 5, 100)
        
        # 3. 模式风险评分（异常操作组合）
        behavior_types = [b["type"] for b in behaviors[-10:]]
        if len(set(behavior_types)) > 5:  # 多种操作类型
            scores["pattern_risk"] = 50
        
        # 总体评分（加权平均）
        overall_score = (
            scores["behavior_risk"] * 0.5 +
            scores["frequency_risk"] * 0.3 +
            scores["pattern_risk"] * 0.2
        )
        
        with self.score_lock:
            self.process_scores[pid] = {
                "overall_score": overall_score,
                "details": scores,
                "timestamp": datetime.now(),
                "process_name": process_name
            }
        
        # 检查异常
        if overall_score > self.anomaly_threshold:
            self._log_anomaly(pid, process_name, overall_score, behaviors)
        
        return overall_score
    
    def _log_anomaly(self, pid, process_name, score, behaviors):
        """记录异常行为"""
        anomaly = {
            "timestamp": datetime.now(),
            "pid": pid,
            "process_name": process_name,
            "score": score,
            "recent_behaviors": [
                {
                    "type": b["type"],
                    "risk": b["risk_score"],
                    "time": b["timestamp"].isoformat()
                }
                for b in list(behaviors)[-5:]
            ]
        }
        self.anomalies.append(anomaly)
        logger.warning(f"检测到异常行为：{process_name}(PID:{pid})，分数：{score:.1f}")
    
    def _recalculate_baseline(self):
        """根据最近的行为重新计算基线"""
        # 这里可以实现更复杂的基线学习算法
        # 例如：统计最常见的行为类型、文件访问模式等
        pass
    
    def get_process_risk_score(self, pid):
        """获取进程当前风险评分"""
        with self.score_lock:
            if pid in self.process_scores:
                score_data = self.process_scores[pid]
                # 检查评分是否过期（5分钟）
                if (datetime.now() - score_data["timestamp"]).seconds < 300:
                    return score_data["overall_score"]
            return 0
    
    def get_anomalies(self, limit=10):
        """获取最近的异常行为记录"""
        return list(self.anomalies)[-limit:]
    
    def get_process_summary(self, pid):
        """获取进程的行为摘要"""
        with self.score_lock:
            if pid not in self.process_scores:
                return None
            
            score_data = self.process_scores[pid]
            behaviors = list(self.process_behaviors[pid])
            
            # 统计行为类型分布
            behavior_dist = defaultdict(int)
            for b in behaviors[-20:]:
                behavior_dist[b["type"]] += 1
            
            return {
                "pid": pid,
                "process_name": score_data["process_name"],
                "risk_score": score_data["overall_score"],
                "score_details": score_data["details"],
                "behavior_count": len(behaviors),
                "behavior_distribution": dict(behavior_dist),
                "last_update": score_data["timestamp"].isoformat()
            }
    
    def is_suspicious(self, pid):
        """判断进程是否可疑"""
        score = self.get_process_risk_score(pid)
        return score > self.anomaly_threshold


class SandboxDetector:
    """沙箱环境检测器"""
    
    @staticmethod
    def detect_sandbox():
        """
        检测是否在虚拟机/沙箱环境运行
        
        Returns:
            (is_sandboxed, sandbox_type)
        """
        sandbox_indicators = []
        
        try:
            # 检查 BIOS 制造商
            import subprocess
            result = subprocess.run(
                ["wmic", "bios", "get", "manufacturer"],
                capture_output=True,
                text=True,
                timeout=5
            )
            bios_info = result.stdout.lower()
            
            vm_indicators = ["vmware", "virtualbox", "hyper-v", "xen", "qemu"]
            for vm in vm_indicators:
                if vm in bios_info:
                    sandbox_indicators.append(vm)
            
        except Exception as e:
            logger.debug(f"BIOS检查失败: {e}")
        
        # 检查虚拟网卡
        try:
            adapters = psutil.net_if_addrs()
            virtual_adapters = []
            
            for adapter_name in adapters.keys():
                if any(vm in adapter_name.lower() for vm in ["vmware", "vbox", "hyper-v"]):
                    virtual_adapters.append(adapter_name)
            
            if virtual_adapters:
                sandbox_indicators.append(f"virtual_adapters: {virtual_adapters}")
        
        except Exception as e:
            logger.debug(f"网卡检查失败: {e}")
        
        # 检查内存大小（沙箱通常内存较小）
        try:
            total_mem_gb = psutil.virtual_memory().total / (1024**3)
            if total_mem_gb < 2:
                sandbox_indicators.append(f"low_memory: {total_mem_gb:.1f}GB")
        except:
            pass
        
        is_sandboxed = len(sandbox_indicators) > 0
        sandbox_type = " + ".join(sandbox_indicators) if sandbox_indicators else "none"
        
        return is_sandboxed, sandbox_type


class ProcessFamilyAnalyzer:
    """进程族关系分析"""
    
    def __init__(self):
        self.process_tree = {}
    
    def build_process_tree(self):
        """构建进程树"""
        self.process_tree = {}
        
        try:
            for proc in psutil.process_iter(["pid", "ppid", "name"]):
                try:
                    pid = proc.info["pid"]
                    ppid = proc.info["ppid"]
                    name = proc.info["name"]
                    
                    self.process_tree[pid] = {
                        "name": name,
                        "ppid": ppid,
                        "children": []
                    }
                except:
                    pass
            
            # 构建父子关系
            for pid, proc_info in self.process_tree.items():
                ppid = proc_info["ppid"]
                if ppid and ppid in self.process_tree:
                    self.process_tree[ppid]["children"].append(pid)
        
        except Exception as e:
            logger.error(f"进程树构建失败: {e}")
    
    def get_process_ancestors(self, pid, depth=10):
        """获取进程的祖先链"""
        ancestors = []
        current_pid = pid
        
        for _ in range(depth):
            if current_pid not in self.process_tree:
                break
            
            proc_info = self.process_tree[current_pid]
            ancestors.append({
                "pid": current_pid,
                "name": proc_info["name"]
            })
            
            ppid = proc_info["ppid"]
            if not ppid:
                break
            current_pid = ppid
        
        return ancestors
    
    def get_process_descendants(self, pid, depth=10):
        """获取进程的所有后代进程"""
        descendants = []
        
        def traverse(p, d):
            if d == 0:
                return
            
            if p not in self.process_tree:
                return
            
            proc_info = self.process_tree[p]
            for child_pid in proc_info["children"]:
                descendants.append({
                    "pid": child_pid,
                    "name": self.process_tree[child_pid]["name"],
                    "depth": depth - d
                })
                traverse(child_pid, d - 1)
        
        traverse(pid, depth)
        return descendants


# 全局行为分析器实例
_analyzer = None


def get_behavior_analyzer():
    """获取全局行为分析器实例"""
    global _analyzer
    if _analyzer is None:
        _analyzer = BehaviorAnalyzer()
    return _analyzer


def record_process_behavior(pid, process_name, behavior_type, details):
    """记录进程行为的便捷函数"""
    analyzer = get_behavior_analyzer()
    analyzer.record_behavior(pid, process_name, behavior_type, details)


def get_process_risk_score(pid):
    """获取进程风险评分的便捷函数"""
    analyzer = get_behavior_analyzer()
    return analyzer.get_process_risk_score(pid)
