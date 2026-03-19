"""
性能优化与测试框架 - 性能分析、负载测试、集成测试
- CPU和内存性能分析
- 多线程性能测试
- 集成测试框架
- 性能基线建立和对比
- 瓶颈检测和优化建议
"""
import os
import sys
import time
import threading
import unittest
import json
import psutil
import tracemalloc
import cProfile
import pstats
from io import StringIO
from datetime import datetime
from collections import defaultdict, deque
from contextlib import contextmanager
from .utils import get_logger

logger = get_logger()


class PerformanceProfiler:
    """性能分析器"""
    
    def __init__(self):
        self.profiles = {}
        self.memory_snapshots = {}
        self.cpu_times = defaultdict(list)
    
    @contextmanager
    def profile_function(self, func_name):
        """
        函数性能分析上下文管理器
        
        Usage:
            with profiler.profile_function("my_function"):
                # 需要分析的代码
                pass
        """
        start_time = time.perf_counter()
        start_memory = psutil.Process().memory_info().rss
        
        try:
            yield
        finally:
            end_time = time.perf_counter()
            end_memory = psutil.Process().memory_info().rss
            
            duration = end_time - start_time
            memory_delta = end_memory - start_memory
            
            if func_name not in self.profiles:
                self.profiles[func_name] = {
                    "call_count": 0,
                    "total_time": 0,
                    "min_time": float('inf'),
                    "max_time": 0,
                    "total_memory_delta": 0,
                    "calls": []
                }
            
            profile = self.profiles[func_name]
            profile["call_count"] += 1
            profile["total_time"] += duration
            profile["min_time"] = min(profile["min_time"], duration)
            profile["max_time"] = max(profile["max_time"], duration)
            profile["total_memory_delta"] += memory_delta
            profile["calls"].append({
                "duration": duration,
                "memory_delta": memory_delta,
                "timestamp": datetime.now().isoformat()
            })
    
    def profile_cpu(self, func, *args, **kwargs):
        """
        使用cProfile分析函数
        
        Returns:
            {
                "result": function result,
                "stats": performance statistics
            }
        """
        profiler = cProfile.Profile()
        profiler.enable()
        
        try:
            result = func(*args, **kwargs)
        finally:
            profiler.disable()
        
        # 获取统计信息
        stats_str = StringIO()
        stats = pstats.Stats(profiler, stream=stats_str)
        stats.strip_dirs().sort_stats('cumulative')
        
        return {
            "result": result,
            "stats": self._parse_stats(stats_str.getvalue())
        }
    
    def _parse_stats(self, stats_output):
        """解析cProfile输出"""
        lines = stats_output.split('\n')
        top_functions = []
        
        for line in lines:
            if line.strip() and not line.startswith('   '):
                parts = line.split()
                if len(parts) >= 6 and parts[1].isdigit():
                    try:
                        top_functions.append({
                            "function": ' '.join(parts[:-5]),
                            "calls": int(parts[1]),
                            "cumulative_time": float(parts[-2]),
                            "per_call": float(parts[-1])
                        })
                    except:
                        pass
        
        return top_functions[:10]  # 返回前10个函数
    
    def profile_memory(self, func, *args, **kwargs):
        """
        分析函数内存使用
        
        Returns:
            {
                "result": function result,
                "memory_stats": memory statistics
            }
        """
        tracemalloc.start()
        
        result = func(*args, **kwargs)
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        return {
            "result": result,
            "current_memory": current,
            "peak_memory": peak,
            "memory_delta": current - tracemalloc.get_traced_memory()[0] if tracemalloc.is_tracing() else 0
        }
    
    def get_summary(self, func_name=None):
        """获取性能分析汇总"""
        if func_name:
            if func_name in self.profiles:
                profile = self.profiles[func_name]
                return {
                    "function": func_name,
                    "calls": profile["call_count"],
                    "total_time": profile["total_time"],
                    "avg_time": profile["total_time"] / profile["call_count"] if profile["call_count"] > 0 else 0,
                    "min_time": profile["min_time"],
                    "max_time": profile["max_time"],
                    "total_memory_delta": profile["total_memory_delta"],
                    "avg_memory_delta": profile["total_memory_delta"] / profile["call_count"] if profile["call_count"] > 0 else 0
                }
            return None
        else:
            # 返回所有函数的汇总
            summaries = []
            for func_name, profile in self.profiles.items():
                summary = {
                    "function": func_name,
                    "calls": profile["call_count"],
                    "total_time": profile["total_time"],
                    "avg_time": profile["total_time"] / profile["call_count"] if profile["call_count"] > 0 else 0,
                }
                summaries.append(summary)
            
            # 按总时间排序
            return sorted(summaries, key=lambda x: x["total_time"], reverse=True)


class LoadTester:
    """负载测试工具"""
    
    def __init__(self, num_threads=10):
        self.num_threads = num_threads
        self.results = deque(maxlen=10000)
        self.errors = deque(maxlen=1000)
        self.lock = threading.Lock()
    
    def run_load_test(self, target_func, num_iterations=1000, duration=None):
        """
        运行负载测试
        
        Args:
            target_func: 目标函数
            num_iterations: 每个线程的迭代次数
            duration: 测试持续时间（秒）
        
        Returns:
            {
                "total_requests": int,
                "successful": int,
                "failed": int,
                "avg_response_time": float,
                "min_response_time": float,
                "max_response_time": float,
                "requests_per_second": float
            }
        """
        self.results.clear()
        self.errors.clear()
        
        start_time = time.time()
        threads = []
        
        def worker():
            iterations = 0
            while True:
                if duration and (time.time() - start_time) > duration:
                    break
                if not duration and iterations >= num_iterations:
                    break
                
                try:
                    req_start = time.perf_counter()
                    target_func()
                    req_duration = time.perf_counter() - req_start
                    
                    with self.lock:
                        self.results.append({
                            "duration": req_duration,
                            "timestamp": datetime.now()
                        })
                    
                    iterations += 1
                
                except Exception as e:
                    with self.lock:
                        self.errors.append({
                            "error": str(e),
                            "timestamp": datetime.now()
                        })
                    iterations += 1
        
        # 启动工作线程
        for _ in range(self.num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # 等待所有线程完成
        for t in threads:
            t.join(timeout=max(duration or 1, 60))  # 最多等待60秒
        
        # 计算统计数据
        total_time = time.time() - start_time
        total_requests = len(self.results) + len(self.errors)
        successful = len(self.results)
        failed = len(self.errors)
        
        if self.results:
            response_times = [r["duration"] for r in self.results]
            avg_response_time = sum(response_times) / len(response_times)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
        else:
            avg_response_time = min_response_time = max_response_time = 0
        
        requests_per_second = successful / total_time if total_time > 0 else 0
        
        logger.info(
            f"负载测试完成: 总请求={total_requests}, 成功={successful}, "
            f"失败={failed}, RPS={requests_per_second:.2f}"
        )
        
        return {
            "total_requests": total_requests,
            "successful": successful,
            "failed": failed,
            "success_rate": (successful / total_requests * 100) if total_requests > 0 else 0,
            "avg_response_time": avg_response_time,
            "min_response_time": min_response_time,
            "max_response_time": max_response_time,
            "requests_per_second": requests_per_second,
            "total_duration": total_time
        }


class SystemMonitor:
    """系统监控工具"""
    
    def __init__(self, sample_interval=1):
        self.sample_interval = sample_interval
        self.samples = deque(maxlen=3600)  # 60分钟的样本
        self.process = psutil.Process()
    
    def capture_snapshot(self):
        """获取系统状态快照"""
        try:
            cpu_percent = self.process.cpu_percent(interval=0.1)
            memory_info = self.process.memory_info()
            memory_percent = self.process.memory_percent()
            
            # 获取系统级统计
            cpu_count = psutil.cpu_count()
            virtual_memory = psutil.virtual_memory()
            
            snapshot = {
                "timestamp": datetime.now(),
                "process": {
                    "pid": self.process.pid,
                    "name": self.process.name(),
                    "cpu_percent": cpu_percent,
                    "memory_rss": memory_info.rss,
                    "memory_vms": memory_info.vms,
                    "memory_percent": memory_percent,
                },
                "system": {
                    "cpu_count": cpu_count,
                    "cpu_percent": psutil.cpu_percent(interval=0.1),
                    "memory_percent": virtual_memory.percent,
                    "disk_percent": psutil.disk_usage('/').percent,
                }
            }
            
            self.samples.append(snapshot)
            return snapshot
        
        except Exception as e:
            logger.error(f"系统监控快照获取失败: {e}")
            return None
    
    def get_average_stats(self, sample_count=None):
        """获取平均统计数据"""
        if not self.samples:
            return None
        
        samples = list(self.samples)
        if sample_count:
            samples = samples[-sample_count:]
        
        if not samples:
            return None
        
        avg_cpu = sum(s["process"]["cpu_percent"] for s in samples) / len(samples)
        avg_memory = sum(s["process"]["memory_rss"] for s in samples) / len(samples)
        max_memory = max(s["process"]["memory_rss"] for s in samples)
        
        return {
            "sample_count": len(samples),
            "avg_cpu_percent": avg_cpu,
            "avg_memory_rss": avg_memory,
            "max_memory_rss": max_memory,
            "duration": (samples[-1]["timestamp"] - samples[0]["timestamp"]).total_seconds()
        }


class PerformanceTestCase(unittest.TestCase):
    """基础性能测试用例类"""
    
    def setUp(self):
        """测试前准备"""
        self.profiler = PerformanceProfiler()
    
    def assertPerformance(self, func, max_duration, *args, **kwargs):
        """
        断言函数性能在指定时间内完成
        
        Args:
            func: 要测试的函数
            max_duration: 最大允许执行时间（秒）
        """
        start = time.perf_counter()
        result = func(*args, **kwargs)
        duration = time.perf_counter() - start
        
        self.assertLess(
            duration, max_duration,
            f"Function took {duration:.4f}s, expected < {max_duration}s"
        )
        
        return result
    
    def assertMemoryUsage(self, func, max_memory_mb, *args, **kwargs):
        """
        断言函数内存使用在指定范围内
        
        Args:
            func: 要测试的函数
            max_memory_mb: 最大允许内存使用（MB）
        """
        tracemalloc.start()
        
        result = func(*args, **kwargs)
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        peak_mb = peak / (1024 * 1024)
        self.assertLess(
            peak_mb, max_memory_mb,
            f"Peak memory {peak_mb:.2f}MB exceeded limit {max_memory_mb}MB"
        )
        
        return result


class BenchmarkRunner:
    """基准测试运行器"""
    
    def __init__(self):
        self.benchmarks = {}
        self.baseline = None
    
    def register_benchmark(self, name, func, iterations=100):
        """注册基准测试"""
        self.benchmarks[name] = {
            "func": func,
            "iterations": iterations,
            "results": []
        }
    
    def run_benchmarks(self):
        """运行所有基准测试"""
        results = {}
        
        for name, benchmark in self.benchmarks.items():
            func = benchmark["func"]
            iterations = benchmark["iterations"]
            
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                func()
                times.append(time.perf_counter() - start)
            
            results[name] = {
                "iterations": iterations,
                "total_time": sum(times),
                "avg_time": sum(times) / iterations,
                "min_time": min(times),
                "max_time": max(times),
                "std_dev": self._calculate_std_dev(times)
            }
        
        return results
    
    def _calculate_std_dev(self, values):
        """计算标准差"""
        if not values:
            return 0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5
    
    def establish_baseline(self):
        """建立性能基线"""
        self.baseline = self.run_benchmarks()
        logger.info("性能基线已建立")
        return self.baseline
    
    def compare_with_baseline(self):
        """与基线对比"""
        if not self.baseline:
            logger.warning("未建立性能基线，跳过对比")
            return None
        
        current = self.run_benchmarks()
        comparison = {}
        
        for name, current_result in current.items():
            if name in self.baseline:
                baseline_result = self.baseline[name]
                
                avg_improvement = (
                    (baseline_result["avg_time"] - current_result["avg_time"]) / 
                    baseline_result["avg_time"] * 100
                )
                
                comparison[name] = {
                    "baseline_avg": baseline_result["avg_time"],
                    "current_avg": current_result["avg_time"],
                    "improvement_percent": avg_improvement,
                    "status": "improved" if avg_improvement > 0 else "degraded"
                }
        
        return comparison


# 全局实例
_profiler = None
_load_tester = None
_system_monitor = None
_benchmark_runner = None


def get_profiler():
    """获取性能分析器实例"""
    global _profiler
    if _profiler is None:
        _profiler = PerformanceProfiler()
    return _profiler


def get_load_tester():
    """获取负载测试工具实例"""
    global _load_tester
    if _load_tester is None:
        _load_tester = LoadTester()
    return _load_tester


def get_system_monitor():
    """获取系统监控工具实例"""
    global _system_monitor
    if _system_monitor is None:
        _system_monitor = SystemMonitor()
    return _system_monitor


def get_benchmark_runner():
    """获取基准测试运行器实例"""
    global _benchmark_runner
    if _benchmark_runner is None:
        _benchmark_runner = BenchmarkRunner()
    return _benchmark_runner
