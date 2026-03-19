"""
The Cat Guard 集成测试框架
演示和测试所有核心功能模块
"""
import unittest
import sys
import os
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import (
    get_behavior_analyzer,
    get_firewall_manager,
    get_network_monitor,
    get_intrusion_detector,
    get_privacy_cleaner,
    get_file_encryptor,
    get_profiler,
    get_system_monitor,
    get_benchmark_runner
)


class TestBehavioralAnalysis(unittest.TestCase):
    """行为分析模块测试"""
    
    def setUp(self):
        self.analyzer = get_behavior_analyzer()
    
    def test_analyze_normal_behavior(self):
        """测试正常进程行为分析"""
        # 记录正常的文件访问行为
        self.analyzer.record_behavior(
            pid=1234,
            process_name="notepad.exe",
            behavior_type="file_access",
            details={"path": "C:\\Users\\test\\document.txt", "type": "read"}
        )
        
        # 获取风险评分
        score = self.analyzer.get_process_risk_score(1234)
        self.assertLess(score, 50, "正常行为的风险分数应小于50")
    
    def test_analyze_suspicious_behavior(self):
        """测试可疑进程行为检测"""
        # 记录多个可疑行为
        for _ in range(10):
            self.analyzer.record_behavior(
                pid=5678,
                process_name="unknown.exe",
                behavior_type="file_access",
                details={
                    "path": "C:\\Windows\\System32\\sensitive.exe",
                    "type": "write"
                }
            )
        
        # 检查是否被标记为可疑
        is_suspicious = self.analyzer.is_suspicious(5678)
        self.assertTrue(is_suspicious, "多个可疑行为应被检测到")


class TestNetworkSecurity(unittest.TestCase):
    """网络安全防护模块测试"""
    
    def setUp(self):
        self.firewall = get_firewall_manager()
        self.network_monitor = get_network_monitor()
        self.ids = get_intrusion_detector()
    
    def test_firewall_status(self):
        """测试防火墙状态检查"""
        status = self.firewall.fw_enabled
        self.assertIsNotNone(status, "应能检查防火墙状态")
    
    def test_monitor_connections(self):
        """测试网络连接监控"""
        connections = self.network_monitor.monitor_connections()
        self.assertIsInstance(connections, list, "监控应返回连接列表")
    
    def test_get_suspicious_connections(self):
        """测试可疑连接检测"""
        suspicious = self.network_monitor.get_suspicious_connections()
        self.assertIsInstance(suspicious, list, "应返回可疑连接列表")


class TestPrivacyProtection(unittest.TestCase):
    """隐私保护模块测试"""
    
    def setUp(self):
        self.cleaner = get_privacy_cleaner()
        self.encryptor = get_file_encryptor()
    
    def test_detect_browsers(self):
        """测试浏览器检测"""
        browsers = self.cleaner.browsers
        self.assertIsInstance(browsers, dict, "应检测到已安装的浏览器")
    
    def test_cleanup_log(self):
        """测试清理日志记录"""
        # 验证清理日志数据结构
        self.assertEqual(len(self.cleaner.cleanup_log), 0, "初始清理日志应为空")


class TestPerformanceOptimization(unittest.TestCase):
    """性能优化与测试模块测试"""
    
    def setUp(self):
        self.profiler = get_profiler()
        self.monitor = get_system_monitor()
        self.benchmark = get_benchmark_runner()
    
    def test_profile_function(self):
        """测试函数性能分析"""
        def test_func():
            total = 0
            for i in range(1000):
                total += i
            return total
        
        with self.profiler.profile_function("test_func"):
            test_func()
        
        summary = self.profiler.get_summary("test_func")
        self.assertIsNotNone(summary, "应能获取性能分析汇总")
        self.assertEqual(summary["calls"], 1, "应记录函数调用")
    
    def test_system_monitor_snapshot(self):
        """测试系统监控快照"""
        snapshot = self.monitor.capture_snapshot()
        self.assertIsNotNone(snapshot, "应能获取系统快照")
        self.assertIn("process", snapshot, "快照应包含进程信息")
        self.assertIn("system", snapshot, "快照应包含系统信息")
    
    def test_benchmark_registration(self):
        """测试基准测试注册"""
        def bench_func():
            return sum(range(100))
        
        self.benchmark.register_benchmark("test_bench", bench_func, iterations=10)
        self.assertIn("test_bench", self.benchmark.benchmarks, "应注册基准测试")


class TestIntegration(unittest.TestCase):
    """集成测试"""
    
    def test_all_modules_importable(self):
        """测试所有模块可导入"""
        from core import (
            BehaviorAnalyzer,
            FirewallManager,
            NetworkMonitor,
            IntrusionDetector,
            FileEncryptor,
            PrivacyCleaner,
            PerformanceProfiler,
            LoadTester,
            SystemMonitor
        )
        
        self.assertIsNotNone(BehaviorAnalyzer)
        self.assertIsNotNone(FirewallManager)
        self.assertIsNotNone(NetworkMonitor)
        self.assertIsNotNone(IntrusionDetector)
        self.assertIsNotNone(FileEncryptor)
        self.assertIsNotNone(PrivacyCleaner)
        self.assertIsNotNone(PerformanceProfiler)
        self.assertIsNotNone(LoadTester)
        self.assertIsNotNone(SystemMonitor)
    
    def test_config_loads(self):
        """测试配置正确加载"""
        from core import load_config
        config = load_config()
        
        # 检查新增配置选项
        self.assertIn("behavioral_analysis", config)
        self.assertIn("network_security", config)
        self.assertIn("privacy_protection", config)
        self.assertIn("performance_monitoring", config)


class TestPerformanceRequirements(unittest.TestCase):
    """性能需求测试"""
    
    def test_config_load_time(self):
        """配置加载时间应小于100ms"""
        from core import load_config
        profiler = get_profiler()
        
        with profiler.profile_function("load_config"):
            load_config()
        
        summary = profiler.get_summary("load_config")
        self.assertLess(summary["avg_time"], 0.1, "配置加载时间应小于100ms")
    
    def test_monitor_memory_usage(self):
        """系统监控内存使用量"""
        monitor = get_system_monitor()
        snapshot = monitor.capture_snapshot()
        
        memory_mb = snapshot["process"]["memory_rss"] / (1024 * 1024)
        self.assertLess(memory_mb, 500, "进程内存使用应小于500MB")


if __name__ == "__main__":
    # 运行测试
    unittest.main(verbosity=2)
