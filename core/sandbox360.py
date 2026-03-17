"""
猫卫士 360 沙箱云集成模块
通过 360 沙箱云 API 进行动态恶意软件分析。
API 文档: https://sandbox.360.cn/api/
"""
import os
import json
import time
import threading
import requests
from .utils import get_logger
from . import config

logger = get_logger()

# 360 沙箱云 API 配置
_SANDBOX_API_URL = "https://api.360.cn/sandbox"
_API_KEY = "082d2ec57b8c543a3e87c6392221bdf6350671f2"

# 威胁等级映射
_THREAT_LEVEL_MAP = {
    0: "安全",      # Clean
    1: "低风险",     # Low
    2: "中风险",     # Medium
    3: "高风险",     # High
    4: "极高风险",   # Critical
    5: "未知",       # Unknown
}


class Sandbox360:
    """360 沙箱云客户端"""

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {_API_KEY}",
            "User-Agent": "TheCatGuard/1.5.0",
        })
        self._timeout = 30
        self._submission_cache = {}  # task_id -> report
        self._cache_lock = threading.Lock()

    def is_available(self) -> bool:
        """检查 360 沙箱云 API 是否可用"""
        try:
            resp = self._session.get(f"{_SANDBOX_API_URL}/ping", timeout=5)
            return resp.status_code == 200
        except Exception as e:
            logger.debug(f"360 沙箱云 API 不可用: {e}")
            return False

    def submit_file(self, filepath: str) -> str:
        """
        提交文件到 360 沙箱云进行分析。
        返回任务 ID (task_id)，失败返回空字符串。
        """
        if not os.path.isfile(filepath):
            logger.warning(f"文件不存在，无法提交沙箱: {filepath}")
            return ""

        try:
            file_size = os.path.getsize(filepath)
            # 沙箱通常限制 100MB
            if file_size > 100 * 1024 * 1024:
                logger.warning(f"文件过大 ({file_size} bytes)，超过沙箱限制")
                return ""

            with open(filepath, "rb") as f:
                files = {"file": (os.path.basename(filepath), f)}
                data = {
                    "apikey": _API_KEY,
                    "product": "TheCatGuard",
                    "timeout": "120",
                }
                resp = self._session.post(
                    f"{_SANDBOX_API_URL}/submitfile",
                    files=files,
                    data=data,
                    timeout=self._timeout,
                )
                resp.raise_for_status()

            result = resp.json()
            if result.get("errno") == 0 and result.get("data", {}).get("task_id"):
                task_id = result["data"]["task_id"]
                logger.info(f"文件已提交沙箱: {os.path.basename(filepath)} (task: {task_id})")
                return task_id
            else:
                logger.warning(f"沙箱提交失败: {result.get('errmsg', '未知错误')}")
                return ""
        except Exception as e:
            logger.error(f"提交文件到沙箱失败: {e}")
            return ""

    def query_status(self, task_id: str) -> dict:
        """
        查询任务执行状态。
        返回 {"status": 0-5, "task_id": str, "timestamp": int}
        0=待处理, 1=处理中, 2=已完成, 3=处理失败, 4=被中断, 5=未知
        """
        if not task_id:
            return {}

        try:
            params = {
                "apikey": _API_KEY,
                "task_id": task_id,
            }
            resp = self._session.get(
                f"{_SANDBOX_API_URL}/getStatus",
                params=params,
                timeout=self._timeout,
            )
            resp.raise_for_status()

            result = resp.json()
            if result.get("errno") == 0:
                data = result.get("data", {})
                return {
                    "status": data.get("status", 5),
                    "task_id": task_id,
                    "timestamp": int(time.time()),
                    "progress": data.get("progress", 0),  # 0-100
                }
            else:
                logger.debug(f"查询沙箱状态失败: {result.get('errmsg')}")
                return {"status": 5, "task_id": task_id}
        except Exception as e:
            logger.error(f"查询沙箱状态异常: {e}")
            return {"status": 5, "task_id": task_id}

    def get_report(self, task_id: str) -> dict:
        """
        获取完整的分析报告。
        返回完整的分析数据，包括威胁检测、行为分析等。
        """
        if not task_id:
            return {}

        # 检查缓存
        with self._cache_lock:
            if task_id in self._submission_cache:
                return self._submission_cache[task_id]

        try:
            params = {
                "apikey": _API_KEY,
                "task_id": task_id,
            }
            resp = self._session.get(
                f"{_SANDBOX_API_URL}/getReport",
                params=params,
                timeout=self._timeout,
            )
            resp.raise_for_status()

            result = resp.json()
            if result.get("errno") == 0:
                report = result.get("data", {})
                # 缓存报告
                with self._cache_lock:
                    self._submission_cache[task_id] = report
                return report
            else:
                logger.debug(f"获取沙箱报告失败: {result.get('errmsg')}")
                return {}
        except Exception as e:
            logger.error(f"获取沙箱报告异常: {e}")
            return {}

    def get_threat_level(self, task_id: str) -> tuple:
        """
        获取威胁等级。
        返回 (threat_level: int 0-5, description: str, confidence: float 0-1)
        """
        report = self.get_report(task_id)
        if not report:
            return (5, "未知", 0.0)

        # 解析威胁等级
        threat_level = report.get("threat_level", 5)
        threat_desc = _THREAT_LEVEL_MAP.get(threat_level, "未知")
        confidence = report.get("confidence", 0.0)

        return (threat_level, threat_desc, confidence)

    def get_behaviors(self, task_id: str) -> list:
        """
        获取恶意行为检测列表。
        返回行为列表 [{name, category, severity}, ...]
        """
        report = self.get_report(task_id)
        if not report:
            return []

        behaviors = report.get("behaviors", [])
        return behaviors

    def wait_for_report(self, task_id: str, timeout: int = 300) -> dict:
        """
        等待沙箱分析完成。
        timeout: 最大等待时间（秒）
        返回完整报告或空字典（超时）
        """
        start = time.time()
        while time.time() - start < timeout:
            status = self.query_status(task_id)
            task_status = status.get("status", 5)

            if task_status == 2:  # 完成
                return self.get_report(task_id)
            elif task_status in (3, 4):  # 失败或中断
                logger.warning(f"沙箱分析异常: status={task_status}")
                return {}

            # 未完成，等待后重试
            logger.debug(f"沙箱分析中... task={task_id} progress={status.get('progress', 0)}%")
            time.sleep(5)

        logger.warning(f"沙箱分析超时 (task={task_id})")
        return {}

    def submit_and_analyze(self, filepath: str, wait: bool = False) -> dict:
        """
        提交文件并立即分析（若 wait=True 则等待结果）。
        返回 {
            "task_id": str,
            "submitted": bool,
            "threat_level": int,
            "report": dict (如果 wait=True)
        }
        """
        task_id = self.submit_file(filepath)
        if not task_id:
            return {"submitted": False, "task_id": ""}

        result = {
            "task_id": task_id,
            "submitted": True,
            "threat_level": 5,  # 初始为未知
            "report": {},
        }

        if wait:
            report = self.wait_for_report(task_id, timeout=300)
            result["report"] = report
            if report:
                threat_level, _, _ = self.get_threat_level(task_id)
                result["threat_level"] = threat_level
                logger.info(
                    f"沙箱分析完成 {os.path.basename(filepath)}: "
                    f"威胁等级={_THREAT_LEVEL_MAP.get(threat_level, '未知')}"
                )

        return result


# 全局沙箱实例（延迟初始化）
_sandbox_instance = None
_sandbox_lock = threading.Lock()


def get_sandbox() -> Sandbox360:
    """获取全局沙箱实例"""
    global _sandbox_instance
    if _sandbox_instance is None:
        with _sandbox_lock:
            if _sandbox_instance is None:
                _sandbox_instance = Sandbox360()
    return _sandbox_instance


def is_sandbox_available() -> bool:
    """检查沙箱是否可用"""
    return get_sandbox().is_available()


def submit_to_sandbox(filepath: str) -> str:
    """提交文件到沙箱，返回任务 ID"""
    return get_sandbox().submit_file(filepath)


def get_sandbox_report(task_id: str, wait: bool = False) -> dict:
    """获取沙箱报告"""
    sandbox = get_sandbox()
    if wait:
        return sandbox.wait_for_report(task_id)
    else:
        return sandbox.get_report(task_id)
