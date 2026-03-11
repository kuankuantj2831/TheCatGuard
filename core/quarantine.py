"""
猫卫士隔离区模块
将可疑文件安全移入隔离目录，支持恢复和永久删除。
隔离文件以 .quarantine 扩展名存储，元数据记录在 JSON 索引中。
"""
import json
import os
import shutil
import time
import uuid
from .utils import get_logger
from . import config
from .yara_scanner import compute_sha256

logger = get_logger()

_INDEX_FILE = "quarantine_index.json"


class QuarantineManager:
    """隔离区管理器"""

    def __init__(self):
        self._qdir = config.get_quarantine_dir()
        self._index_path = os.path.join(self._qdir, _INDEX_FILE)
        self._index = self._load_index()

    def _load_index(self) -> list:
        """加载隔离索引"""
        if os.path.isfile(self._index_path):
            try:
                with open(self._index_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def _save_index(self):
        """保存隔离索引"""
        try:
            with open(self._index_path, "w", encoding="utf-8") as f:
                json.dump(self._index, f, ensure_ascii=False, indent=2)
        except OSError as e:
            logger.error(f"保存隔离索引失败: {e}")

    def quarantine_file(self, filepath: str, reason: str = "") -> bool:
        """
        将文件移入隔离区。
        返回是否成功。
        """
        if not os.path.isfile(filepath):
            logger.warning(f"隔离失败：文件不存在 {filepath}")
            return False

        try:
            file_hash = compute_sha256(filepath)
            file_size = os.path.getsize(filepath)
            qid = uuid.uuid4().hex[:12]
            safe_name = f"{qid}.quarantine"
            dest = os.path.join(self._qdir, safe_name)

            # 移动文件
            shutil.move(filepath, dest)

            # 记录元数据
            entry = {
                "id": qid,
                "original_path": filepath,
                "original_name": os.path.basename(filepath),
                "quarantine_name": safe_name,
                "sha256": file_hash,
                "size": file_size,
                "reason": reason,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._index.append(entry)
            self._save_index()

            logger.info(f"文件已隔离: {filepath} -> {safe_name} (原因: {reason})")
            return True
        except (PermissionError, OSError) as e:
            logger.error(f"隔离文件失败 {filepath}: {e}")
            return False

    # 禁止恢复到的系统关键目录
    _BLOCKED_RESTORE_DIRS = [
        os.path.normcase(r"C:\Windows"),
        os.path.normcase(r"C:\Program Files"),
        os.path.normcase(r"C:\Program Files (x86)"),
    ]

    def restore_file(self, qid: str) -> bool:
        """
        从隔离区恢复文件到原始位置。
        禁止恢复到系统关键目录，防止路径穿越攻击。
        """
        entry = self._find_entry(qid)
        if not entry:
            logger.warning(f"隔离条目不存在: {qid}")
            return False

        src = os.path.join(self._qdir, entry["quarantine_name"])
        dest = os.path.normpath(entry["original_path"])

        # 安全检查：禁止恢复到系统目录
        dest_norm = os.path.normcase(dest)
        for blocked in self._BLOCKED_RESTORE_DIRS:
            if dest_norm.startswith(blocked):
                logger.warning(f"安全拦截：禁止恢复文件到系统目录 {dest}")
                return False

        # 安全检查：禁止路径穿越（.. 组件）
        if ".." in dest.split(os.sep):
            logger.warning(f"安全拦截：恢复路径包含路径穿越 {dest}")
            return False

        if not os.path.isfile(src):
            logger.error(f"隔离文件丢失: {src}")
            return False

        try:
            # 确保目标目录存在
            dest_dir = os.path.dirname(dest)
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)

            # 如果原位置已有同名文件，加后缀
            if os.path.exists(dest):
                base, ext = os.path.splitext(dest)
                dest = f"{base}_restored{ext}"

            shutil.move(src, dest)
            self._index = [e for e in self._index if e["id"] != qid]
            self._save_index()

            logger.info(f"文件已恢复: {dest}")
            return True
        except (PermissionError, OSError) as e:
            logger.error(f"恢复文件失败: {e}")
            return False

    def delete_permanently(self, qid: str) -> bool:
        """永久删除隔离文件"""
        entry = self._find_entry(qid)
        if not entry:
            return False

        src = os.path.join(self._qdir, entry["quarantine_name"])
        try:
            if os.path.isfile(src):
                os.remove(src)
            self._index = [e for e in self._index if e["id"] != qid]
            self._save_index()
            logger.info(f"已永久删除: {entry['original_name']}")
            return True
        except OSError as e:
            logger.error(f"永久删除失败: {e}")
            return False

    def list_quarantined(self) -> list:
        """返回所有隔离条目"""
        return list(self._index)

    def count(self) -> int:
        return len(self._index)

    def _find_entry(self, qid: str):
        for e in self._index:
            if e["id"] == qid:
                return e
        return None
