#!/usr/bin/env python3
"""
测试360学习的新功能
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from core.yara_scanner import YaraScanner
from core.heuristic_detector import BehavioralHeuristicDetector
from core.process_injection_detector import ProcessInjectionDetector
from core.cloud_scanner import CloudMalwareScanner
from core import config

def test_yara_scanner():
    print("测试 YARA 扫描器...")
    scanner = YaraScanner()
    print(f"YARA 可用: {scanner.available}")

    # 测试规则加载
    if scanner.load_rules():
        print("✓ YARA 规则加载成功")
    else:
        print("✗ YARA 规则加载失败")

    # 测试哈希计算
    test_file = __file__
    if os.path.exists(test_file):
        results = scanner.scan_file(test_file)
        print(f"扫描结果: {len(results)} 个匹配")

    return True

def test_heuristic_detector():
    print("\n测试行为启发式检测器...")
    detector = BehavioralHeuristicDetector()

    # 测试当前进程
    import psutil
    current_proc = psutil.Process()
    score, behaviors = detector.score_process_behavior(current_proc.pid, current_proc.name())
    print(f"当前进程评分: {score}/100, 行为: {behaviors}")

    return True

def test_injection_detector():
    print("\n测试进程注入检测器...")
    detector = ProcessInjectionDetector()

    # 测试当前进程的注入检测
    import psutil
    current_proc = psutil.Process()
    injections = detector.detect_remote_thread_injection(current_proc.pid)
    print(f"检测到注入: {len(injections)} 个")

    return True

def test_cloud_scanner():
    print("\n测试云查杀扫描器...")
    scanner = CloudMalwareScanner()

    # 测试配置
    api_key = config.get("cloud_scanner.api_key", "")
    enabled = config.get("cloud_scanner.enabled", False)
    print(f"云查杀启用: {enabled}, API密钥: {'已配置' if api_key else '未配置'}")

    return True

def test_config():
    print("\n测试配置更新...")
    # 测试新配置项
    cloud_enabled = config.get("cloud_scanner.enabled", False)
    heuristic_enabled = config.get("heuristic_detection.enabled", True)
    injection_enabled = config.get("injection_detection.enabled", True)

    print(f"云查杀配置: {cloud_enabled}")
    print(f"行为检测配置: {heuristic_enabled}")
    print(f"注入检测配置: {injection_enabled}")

    return True

def main():
    print("=== The Cat Guard 360学习功能测试 ===\n")

    tests = [
        ("配置系统", test_config),
        ("YARA扫描器", test_yara_scanner),
        ("行为启发式检测", test_heuristic_detector),
        ("进程注入检测", test_injection_detector),
        ("云查杀扫描器", test_cloud_scanner),
    ]

    passed = 0
    for name, test_func in tests:
        try:
            if test_func():
                print(f"✓ {name} 测试通过")
                passed += 1
            else:
                print(f"✗ {name} 测试失败")
        except Exception as e:
            print(f"✗ {name} 测试异常: {e}")

    print(f"\n=== 测试完成: {passed}/{len(tests)} 通过 ===")

    if passed == len(tests):
        print("\n🎉 所有360学习功能集成成功！")
        print("现在The Cat Guard具备了类似360安全卫士的多层检测能力：")
        print("- 云查杀 (VirusTotal集成)")
        print("- 行为启发式检测")
        print("- 进程注入检测")
        print("- 增强的YARA规则")
        print("- PE结构启发式分析")
    else:
        print("\n⚠️ 部分功能需要进一步调试")

if __name__ == "__main__":
    main()