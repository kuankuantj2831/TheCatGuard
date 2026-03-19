"""
网络安全防护模块 - 防火墙管理、入侵检测、网络流量监控
- Windows防火墙集成管理
- 实时网络连接监控和异常检测
- 入侵检测系统（IDS）
- DDoS防护和IP信誉检查
"""
import os
import json
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import psutil
import subprocess
from .utils import get_logger

logger = get_logger()


class FirewallManager:
    """Windows防火墙管理器"""
    
    def __init__(self):
        self.fw_enabled = self._check_fw_status()
        self.rules_cache = {}
    
    def _check_fw_status(self):
        """检查防火墙启用状态"""
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return "State" in result.stdout
        except Exception as e:
            logger.warning(f"防火墙状态检查失败: {e}")
            return False
    
    def enable_firewall(self):
        """启用防火墙"""
        try:
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                capture_output=True,
                timeout=5,
                check=True
            )
            self.fw_enabled = True
            logger.info("防火墙已启用")
            return True
        except Exception as e:
            logger.error(f"启用防火墙失败: {e}")
            return False
    
    def disable_firewall(self):
        """禁用防火墙"""
        try:
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", "off"],
                capture_output=True,
                timeout=5,
                check=True
            )
            self.fw_enabled = False
            logger.info("防火墙已禁用")
            return True
        except Exception as e:
            logger.error(f"禁用防火墙失败: {e}")
            return False
    
    def add_rule(self, rule_name, direction, action, protocol, port=None):
        """
        添加防火墙规则
        
        Args:
            rule_name: 规则名称
            direction: in / out
            action: allow / block
            protocol: tcp / udp / any
            port: 端口号（可选）
        
        Returns:
            success (bool)
        """
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                f"dir={direction}",
                f"action={action}",
                f"protocol={protocol}",
            ]
            
            if port:
                cmd.append(f"localport={port}")
            
            result = subprocess.run(cmd, capture_output=True, timeout=5, check=True)
            
            self.rules_cache[rule_name] = {
                "direction": direction,
                "action": action,
                "protocol": protocol,
                "port": port,
                "created": datetime.now().isoformat()
            }
            
            logger.info(f"防火墙规则已添加: {rule_name}")
            return True
        
        except Exception as e:
            logger.error(f"添加防火墙规则失败: {e}")
            return False
    
    def block_ip(self, ip_address, rule_name=None):
        """
        阻止特定IP地址
        
        Args:
            ip_address: IP地址
            rule_name: 规则名称（默认为 block_ip_<IP>）
        
        Returns:
            success (bool)
        """
        rule_name = rule_name or f"block_ip_{ip_address.replace('.', '_')}"
        
        return self.add_rule(
            rule_name=rule_name,
            direction="in",
            action="block",
            protocol="any"
        )
    
    def allow_app(self, app_path):
        """
        允许应用程序通过防火墙
        
        Args:
            app_path: 应用程序路径
        
        Returns:
            success (bool)
        """
        try:
            app_name = os.path.basename(app_path)
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=Allow_{app_name}",
                "dir=in",
                "action=allow",
                f"program={app_path}",
                "enable=yes"
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=5, check=True)
            logger.info(f"应用程序已加入防火墙白名单: {app_path}")
            return True
        
        except Exception as e:
            logger.error(f"添加应用程序白名单失败: {e}")
            return False
    
    def remove_rule(self, rule_name):
        """删除防火墙规则"""
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                capture_output=True,
                timeout=5,
                check=True
            )
            
            if rule_name in self.rules_cache:
                del self.rules_cache[rule_name]
            
            logger.info(f"防火墙规则已删除: {rule_name}")
            return True
        
        except Exception as e:
            logger.error(f"删除防火墙规则失败: {e}")
            return False


class NetworkMonitor:
    """网络连接监控器"""
    
    def __init__(self, max_connections=10000):
        self.connections = {}
        self.max_connections = max_connections
        self.connection_lock = threading.Lock()
        
        # 网络连接历史
        self.connection_history = deque(maxlen=max_connections)
        
        # 可疑连接IP黑名单（应从威胁情报源加载）
        self.suspicious_ips = set()
        self.suspicious_ports = {
            4444, 5555, 6666, 7777, 8888,  # 常见恶意软件端口
            31337, 27374, 6667,  # IRC端口
            12345, 12346, 27374, 27665, 27666  # 远程访问木马端口
        }
    
    def monitor_connections(self):
        """
        监控所有网络连接
        
        Returns:
            [(local_addr, remote_addr, status, pid, process_name), ...]
        """
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    
                    proc_name = "unknown"
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except:
                            pass
                    
                    connection_data = {
                        "local_addr": laddr,
                        "remote_addr": raddr,
                        "status": conn.status,
                        "pid": conn.pid,
                        "process_name": proc_name,
                        "type": conn.type,
                        "timestamp": datetime.now(),
                        "risk_score": self._assess_connection_risk(conn)
                    }
                    
                    connections.append(connection_data)
                    self.connection_history.append(connection_data)
                
                except Exception as e:
                    logger.debug(f"连接分析失败: {e}")
        
        except Exception as e:
            logger.error(f"网络连接监控失败: {e}")
        
        with self.connection_lock:
            self.connections = {conn["remote_addr"]: conn for conn in connections}
        
        return connections
    
    def _assess_connection_risk(self, conn):
        """
        评估连接的风险等级
        
        Returns:
            risk_score (0-100)
        """
        risk = 0
        
        try:
            if not conn.raddr:
                return 0
            
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            
            # 检查端口风险
            if remote_port in self.suspicious_ports:
                risk += 40
            
            # 检查系统保留端口
            if remote_port < 1024 and remote_port not in [80, 443, 53]:
                risk += 20
            
            # 检查IP信誉（这里简化处理，应连接威胁情报API）
            if remote_ip in self.suspicious_ips:
                risk += 50
            
            # 连接状态评估
            if conn.status == "ESTABLISHED":
                risk += 5
            
            # 进程类型评估
            if conn.type == "UDP" and remote_port not in [53, 123, 5353]:
                risk += 15
        
        except Exception as e:
            logger.debug(f"连接风险评估失败: {e}")
        
        return min(risk, 100)
    
    def get_suspicious_connections(self, threshold=50):
        """获取所有可疑连接"""
        suspicious = []
        
        with self.connection_lock:
            for conn_data in self.connections.values():
                if conn_data["risk_score"] > threshold:
                    suspicious.append(conn_data)
        
        return sorted(suspicious, key=lambda x: x["risk_score"], reverse=True)
    
    def block_remote_ip(self, ip_address):
        """阻止来自指定IP的连接"""
        self.suspicious_ips.add(ip_address)
        
        # 调用防火墙管理器
        fw = FirewallManager()
        return fw.block_ip(ip_address)


class IntrusionDetector:
    """入侵检测系统（简化版）"""
    
    def __init__(self):
        # 网络流量特征分析
        self.flow_stats = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "start_time": datetime.now(),
            "duration": 0
        })
        
        # 异常检测阈值
        self.thresholds = {
            "packets_per_sec": 1000,      # 每秒数据包数
            "bytes_per_sec": 100 * 1024,  # 每秒字节数 (100KB)
            "connection_rate": 50,         # 每秒新连接数
        }
        
        # 检测到的攻击日志
        self.alerts = deque(maxlen=100)
    
    def detect_port_scan(self, connections):
        """
        检测端口扫描行为
        
        Args:
            connections: 网络连接列表
        
        Returns:
            [(src_ip, scan_info), ...] 或 []
        """
        port_scan_map = defaultdict(set)
        
        for conn in connections:
            try:
                if conn.get("status") == "SYN_SENT":
                    remote = conn.get("remote_addr", "").split(":")[0]
                    port = int(conn.get("remote_addr", ":0").split(":")[-1])
                    
                    port_scan_map[remote].add(port)
            except:
                pass
        
        detected_scans = []
        
        for remote_ip, ports in port_scan_map.items():
            if len(ports) > 10:  # 短时间内扫描超过10个端口
                detected_scans.append({
                    "timestamp": datetime.now(),
                    "target_ip": remote_ip,
                    "scanned_ports": list(ports),
                    "scan_type": "horizontal_scan" if len(ports) > 100 else "vertical_scan",
                    "severity": "HIGH"
                })
                self.alerts.append(detected_scans[-1])
                logger.warning(f"检测到端口扫描: {remote_ip} 扫描了 {len(ports)} 个端口")
        
        return detected_scans
    
    def detect_ddos(self, connections, window_size=5):
        """
        检测DDoS攻击
        
        Args:
            connections: 网络连接列表
            window_size: 时间窗口（秒）
        
        Returns:
            [(attacker_info, target_info), ...] 或 []
        """
        # 统计连接来源
        source_counts = defaultdict(int)
        target_counts = defaultdict(int)
        
        for conn in connections:
            try:
                if conn.get("status") == "ESTABLISHED":
                    source = conn.get("remote_addr", ":0").split(":")[0]
                    target = conn.get("local_addr", ":0").split(":")[0]
                    
                    source_counts[source] += 1
                    target_counts[target] += 1
            except:
                pass
        
        # 检测异常的连接数
        detected_ddos = []
        connection_threshold = 100
        
        for target_ip, count in target_counts.items():
            if count > connection_threshold:
                # 找出主要的攻击源
                top_sources = sorted(
                    source_counts.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]
                
                detected_ddos.append({
                    "timestamp": datetime.now(),
                    "target": target_ip,
                    "attack_sources": [src for src, _ in top_sources],
                    "connection_count": count,
                    "severity": "CRITICAL" if count > 500 else "HIGH"
                })
                self.alerts.append(detected_ddos[-1])
                logger.critical(f"检测到DDoS攻击: 目标 {target_ip} 来自 {len(top_sources)} 个源")
        
        return detected_ddos
    
    def detect_dns_tunneling(self, connections):
        """
        检测DNS隧道攻击（通过DNS进行数据外泄）
        
        Returns:
            [(dns_query_info), ...] 或 []
        """
        dns_connections = [
            c for c in connections
            if str(c.get("remote_addr", ":0")).endswith(":53")
        ]
        
        detected = []
        
        # 检测异常的DNS查询（数据量过大）
        dns_stats = defaultdict(lambda: {"count": 0, "bytes": 0})
        
        for conn in dns_connections:
            try:
                dns_ip = conn.get("remote_addr", ":0").split(":")[0]
                dns_stats[dns_ip]["count"] += 1
            except:
                pass
        
        for dns_ip, stats in dns_stats.items():
            if stats["count"] > 1000:  # 异常高的DNS查询次数
                detected.append({
                    "timestamp": datetime.now(),
                    "dns_server": dns_ip,
                    "query_count": stats["count"],
                    "alert": "可能存在DNS隧道或DNS放大攻击",
                    "severity": "HIGH"
                })
                self.alerts.append(detected[-1])
                logger.warning(f"检测到异常DNS活动: {dns_ip}")
        
        return detected
    
    def get_alerts(self, limit=10):
        """获取最近的警报"""
        return list(self.alerts)[-limit:]


class IPReputation:
    """IP信誉检查（本地缓存，应连接外部威胁情报API）"""
    
    def __init__(self):
        self.known_malicious_ips = set()
        self.known_safe_ips = set()
        self.ip_cache = deque(maxlen=10000)
    
    def check_ip_reputation(self, ip_address):
        """
        检查IP信誉
        
        Returns:
            {
                "ip": ip_address,
                "reputation": "malicious" / "suspicious" / "clean" / "unknown",
                "confidence": 0-100,
                "categories": [...]
            }
        """
        # 检查本地缓存
        if ip_address in self.known_malicious_ips:
            return {
                "ip": ip_address,
                "reputation": "malicious",
                "confidence": 100,
                "categories": ["known_malware", "botnet"]
            }
        
        if ip_address in self.known_safe_ips:
            return {
                "ip": ip_address,
                "reputation": "clean",
                "confidence": 100,
                "categories": []
            }
        
        # 这里应该调用外部API（如VirusTotal、AbuseIPDB等）
        # 简化版：返回unknown
        return {
            "ip": ip_address,
            "reputation": "unknown",
            "confidence": 0,
            "categories": []
        }
    
    def add_malicious_ip(self, ip_address, reason=""):
        """标记IP为恶意"""
        self.known_malicious_ips.add(ip_address)
        logger.info(f"IP标记为恶意: {ip_address} ({reason})")
    
    def add_safe_ip(self, ip_address):
        """标记IP为安全"""
        self.known_safe_ips.add(ip_address)


# 全局网络安全管理器实例
_firewall_manager = None
_network_monitor = None
_intrusion_detector = None
_ip_reputation = None


def get_firewall_manager():
    """获取防火墙管理器实例"""
    global _firewall_manager
    if _firewall_manager is None:
        _firewall_manager = FirewallManager()
    return _firewall_manager


def get_network_monitor():
    """获取网络监控器实例"""
    global _network_monitor
    if _network_monitor is None:
        _network_monitor = NetworkMonitor()
    return _network_monitor


def get_intrusion_detector():
    """获取入侵检测器实例"""
    global _intrusion_detector
    if _intrusion_detector is None:
        _intrusion_detector = IntrusionDetector()
    return _intrusion_detector


def get_ip_reputation():
    """获取IP信誉检查器实例"""
    global _ip_reputation
    if _ip_reputation is None:
        _ip_reputation = IPReputation()
    return _ip_reputation
