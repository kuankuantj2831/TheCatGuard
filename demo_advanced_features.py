#!/usr/bin/env python3
"""
The Cat Guard - 新增功能演示脚本
演示如何直接使用新增的高级安全模块
"""

# 注意：运行此脚本前请先安装依赖：pip install -r requirements.txt

import sys
import os

# 添加项目路径
sys.path.insert(0, os.path.dirname(__file__))


def demo_behavioral_analysis():
    """演示行为分析功能"""
    print("\n" + "="*60)
    print("🧠 行为分析模块演示")
    print("="*60)
    
    try:
        from core.behavioral_analysis import BehaviorAnalyzer, SandboxDetector
        
        # 创建分析器
        analyzer = BehaviorAnalyzer()
        print("✓ 行为分析器初始化成功")
        
        # 记录样本行为
        analyzer.record_behavior(
            pid=1234,
            process_name="example.exe",
            behavior_type="file_access",
            details={"path": "C:\\Windows\\System32", "type": "read"}
        )
        print("✓ 进程行为已记录")
        
        # 获取风险评分
        score = analyzer.get_process_risk_score(1234)
        print(f"✓ 进程风险评分: {score:.1f}/100")
        
        # 检测沙箱
        sandbox = SandboxDetector()
        is_sandboxed, sandbox_type = sandbox.detect_sandbox()
        print(f"✓ 沙箱检测: {'是' if is_sandboxed else '否'} ({sandbox_type})")
        
    except ImportError as e:
        print(f"✗ 导入失败: {e}")
        print("  请运行: pip install -r requirements.txt")


def demo_network_security():
    """演示网络安全防护功能"""
    print("\n" + "="*60)
    print("🌐 网络安全防护模块演示")
    print("="*60)
    
    try:
        from core.network_security import (
            FirewallManager, NetworkMonitor, IntrusionDetector, IPReputation
        )
        
        # 防火墙状态
        fw = FirewallManager()
        print(f"✓ 防火墙状态: {'启用' if fw.fw_enabled else '禁用'}")
        
        # 网络监控
        monitor = NetworkMonitor()
        connections = monitor.monitor_connections()
        print(f"✓ 监控到 {len(connections)} 个网络连接")
        
        # 入侵检测
        ids = IntrusionDetector()
        print(f"✓ 入侵检测系统已初始化")
        
        # IP信誉检查
        ip_rep = IPReputation()
        print(f"✓ IP信誉检查器已初始化")
        
    except ImportError as e:
        print(f"✗ 导入失败: {e}")
        print("  请运行: pip install -r requirements.txt")


def demo_privacy_protection():
    """演示隐私保护功能"""
    print("\n" + "="*60)
    print("🔒 隐私保护与数据安全模块演示")
    print("="*60)
    
    try:
        from core.privacy_protection import (
            FileEncryptor, PrivacyCleaner, SensitiveDataDetector
        )
        
        # 文件加密
        encryptor = FileEncryptor()
        print("✓ 文件加密器已初始化")
        print(f"  支持的加密方式: Fernet (AES)")
        
        # 隐私清理
        cleaner = PrivacyCleaner()
        print(f"✓ 隐私清理器已初始化")
        print(f"  检测到的浏览器: {', '.join(cleaner.browsers.keys()) if cleaner.browsers else '无'}")
        
        # 敏感数据检测
        detector = SensitiveDataDetector()
        print(f"✓ 敏感数据检测器已初始化")
        print(f"  支持检测类型: {', '.join(detector.sensitive_patterns.keys())}")
        
    except ImportError as e:
        print(f"✗ 导入失败: {e}")
        print("  请运行: pip install -r requirements.txt")


def demo_performance_testing():
    """演示性能测试功能"""
    print("\n" + "="*60)
    print("📊 性能优化与测试模块演示")
    print("="*60)
    
    try:
        from core.performance_testing import (
            PerformanceProfiler, LoadTester, SystemMonitor, BenchmarkRunner
        )
        
        # 性能分析
        profiler = PerformanceProfiler()
        print("✓ 性能分析器已初始化")
        
        # 负载测试
        load_tester = LoadTester(num_threads=4)
        print("✓ 负载测试工具已初始化 (4线程)")
        
        # 系统监控
        monitor = SystemMonitor()
        snapshot = monitor.capture_snapshot()
        if snapshot:
            print("✓ 系统监控快照已采集")
            cpu = snapshot["process"]["cpu_percent"]
            mem = snapshot["process"]["memory_rss"] / (1024*1024)
            print(f"  当前进程 - CPU: {cpu:.1f}%, 内存: {mem:.1f}MB")
        
        # 基准测试
        benchmark = BenchmarkRunner()
        print("✓ 基准测试运行器已初始化")
        
    except ImportError as e:
        print(f"✗ 导入失败: {e}")
        print("  请运行: pip install -r requirements.txt")


def main():
    """主函数"""
    print("\n" + "🐱 "*20)
    print("The Cat Guard - 新增高级功能演示")
    print("🐱 "*20)
    
    demo_behavioral_analysis()
    demo_network_security()
    demo_privacy_protection()
    demo_performance_testing()
    
    print("\n" + "="*60)
    print("✨ 演示完成！")
    print("="*60)
    print("\n📖 详细文档：")
    print("  - ADVANCED_FEATURES.md - 功能详细说明")
    print("  - IMPLEMENTATION_SUMMARY.md - 实现总结")
    print("\n🧪 运行集成测试：")
    print("  python -m pytest tests_integration.py -v\n")


if __name__ == "__main__":
    main()
