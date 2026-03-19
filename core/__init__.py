"""
猫卫士核心模块初始化
"""
from .config import load_config, save_config
from .utils import get_logger

# 基础模块
try:
    from .monitor import ProcessMonitor, RegistryMonitor
except ImportError as e:
    get_logger().warning(f"ProcessMonitor导入失败: {e}")

try:
    from .yara_scanner import YaraScanner
except ImportError as e:
    get_logger().warning(f"YaraScanner导入失败: {e}")

try:
    from .quarantine import QuarantineManager
except ImportError as e:
    get_logger().warning(f"QuarantineManager导入失败: {e}")

# RepairEngine可能不存在或名字不同，尝试导入但不强制
try:
    from .repair import RepairEngine
except (ImportError, AttributeError) as e:
    get_logger().debug(f"RepairEngine导入失败: {e}")

# 高级模块 - 带错误处理
try:
    from .behavioral_analysis import (
        get_behavior_analyzer,
        get_process_risk_score,
        BehaviorAnalyzer,
        SandboxDetector,
        ProcessFamilyAnalyzer
    )
except ImportError as e:
    get_logger().warning(f"behavioral_analysis导入失败: {e}")

try:
    from .network_security import (
        get_firewall_manager,
        get_network_monitor,
        get_intrusion_detector,
        get_ip_reputation,
        FirewallManager,
        NetworkMonitor,
        IntrusionDetector,
        IPReputation
    )
except ImportError as e:
    get_logger().warning(f"network_security导入失败: {e}")

try:
    from .privacy_protection import (
        get_file_encryptor,
        get_privacy_cleaner,
        get_sensitive_data_detector,
        FileEncryptor,
        PrivacyCleaner,
        SensitiveDataDetector
    )
except ImportError as e:
    get_logger().warning(f"privacy_protection导入失败: {e}")

try:
    from .performance_testing import (
        get_profiler,
        get_load_tester,
        get_system_monitor,
        get_benchmark_runner,
        PerformanceProfiler,
        LoadTester,
        SystemMonitor,
        BenchmarkRunner,
        PerformanceTestCase
    )
except ImportError as e:
    get_logger().warning(f"performance_testing导入失败: {e}")

__all__ = [
    # 配置和日志
    "load_config",
    "save_config",
    "get_logger",
    
    # 监控和扫描
    "ProcessMonitor",
    "RegistryMonitor",
    "YaraScanner",
    "QuarantineManager",
    "RepairEngine",
    
    # 行为分析
    "get_behavior_analyzer",
    "get_process_risk_score",
    "BehaviorAnalyzer",
    "SandboxDetector",
    "ProcessFamilyAnalyzer",
    
    # 网络安全
    "get_firewall_manager",
    "get_network_monitor",
    "get_intrusion_detector",
    "get_ip_reputation",
    "FirewallManager",
    "NetworkMonitor",
    "IntrusionDetector",
    "IPReputation",
    
    # 隐私保护
    "get_file_encryptor",
    "get_privacy_cleaner",
    "get_sensitive_data_detector",
    "FileEncryptor",
    "PrivacyCleaner",
    "SensitiveDataDetector",
    
    # 性能测试
    "get_profiler",
    "get_load_tester",
    "get_system_monitor",
    "get_benchmark_runner",
    "PerformanceProfiler",
    "LoadTester",
    "SystemMonitor",
    "BenchmarkRunner",
    "PerformanceTestCase",
]
