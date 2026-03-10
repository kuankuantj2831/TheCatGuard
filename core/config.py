"""
猫卫士配置管理模块
JSON 配置文件的读写，支持白名单/黑名单、监控参数、隔离区设置。
"""
import json
import os
import threading
from .utils import get_logger

logger = get_logger()

_CONFIG_DIR = os.path.join(os.path.expandvars("%LOCALAPPDATA%"), "TheCatGuard")
_CONFIG_FILE = os.path.join(_CONFIG_DIR, "config.json")

_DEFAULT_CONFIG = {
    # ── 监控间隔（秒） ──
    "process_poll_interval": 1,
    "registry_poll_interval": 2,
    "network_poll_interval": 3,
    "usb_poll_interval": 3,

    # ── 网络监控：安全端口 ──
    "safe_ports": [80, 443, 53, 67, 68, 123, 5353, 1900],

    # ── 白名单 ──
    "whitelist_processes": [],       # 进程名列表，如 ["chrome.exe", "code.exe"]
    "whitelist_paths": [],           # 路径前缀列表，如 ["C:\\Program Files"]
    "whitelist_network_ips": [],     # IP 列表，如 ["192.168.1.1"]

    # ── 黑名单 ──
    "blacklist_processes": [],       # 进程名列表
    "blacklist_hashes": [],          # SHA256 哈希列表

    # ── YARA ──
    "yara_enabled": True,
    "yara_rules_dir": "",            # 空 = 使用内置规则目录

    # ── 隔离区 ──
    "quarantine_dir": "",            # 空 = 使用默认目录
    "quarantine_auto": False,        # 是否自动隔离可疑文件

    # ── 通知 ──
    "notification_level": "medium",  # low / medium / high
}

_lock = threading.Lock()
_cache = None


def _ensure_dir():
    os.makedirs(_CONFIG_DIR, exist_ok=True)


def load_config() -> dict:
    """加载配置，不存在则创建默认配置"""
    global _cache
    with _lock:
        if _cache is not None:
            return _cache.copy()
        _ensure_dir()
        if os.path.isfile(_CONFIG_FILE):
            try:
                with open(_CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # 合并默认值（新增的配置项自动补全）
                merged = {**_DEFAULT_CONFIG, **data}
                _cache = merged
                return merged.copy()
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"配置文件损坏，使用默认配置: {e}")
        _cache = _DEFAULT_CONFIG.copy()
        save_config(_cache)
        return _cache.copy()


def save_config(config: dict):
    """保存配置到文件"""
    global _cache
    with _lock:
        _ensure_dir()
        try:
            with open(_CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            _cache = config.copy()
        except OSError as e:
            logger.error(f"保存配置失败: {e}")


def get(key: str, default=None):
    """获取单个配置项"""
    cfg = load_config()
    return cfg.get(key, default)


def set_key(key: str, value):
    """设置单个配置项并保存"""
    cfg = load_config()
    cfg[key] = value
    save_config(cfg)


def get_quarantine_dir() -> str:
    """获取隔离区目录路径"""
    cfg = load_config()
    qdir = cfg.get("quarantine_dir", "")
    if not qdir:
        qdir = os.path.join(_CONFIG_DIR, "quarantine")
    os.makedirs(qdir, exist_ok=True)
    return qdir


def get_yara_rules_dir() -> str:
    """获取 YARA 规则目录路径"""
    cfg = load_config()
    rdir = cfg.get("yara_rules_dir", "")
    if not rdir:
        rdir = os.path.join(_CONFIG_DIR, "yara_rules")
    os.makedirs(rdir, exist_ok=True)
    return rdir


def is_process_whitelisted(name: str) -> bool:
    """检查进程名是否在白名单中"""
    cfg = load_config()
    return name.lower() in [p.lower() for p in cfg.get("whitelist_processes", [])]


def is_path_whitelisted(path: str) -> bool:
    """检查路径是否在白名单路径前缀中"""
    cfg = load_config()
    path_lower = os.path.normcase(os.path.normpath(path))
    for wp in cfg.get("whitelist_paths", []):
        if path_lower.startswith(os.path.normcase(os.path.normpath(wp))):
            return True
    return False


def is_ip_whitelisted(ip: str) -> bool:
    """检查 IP 是否在白名单中"""
    cfg = load_config()
    return ip in cfg.get("whitelist_network_ips", [])


def is_process_blacklisted(name: str) -> bool:
    """检查进程名是否在黑名单中"""
    cfg = load_config()
    return name.lower() in [p.lower() for p in cfg.get("blacklist_processes", [])]


def is_hash_blacklisted(sha256: str) -> bool:
    """检查文件哈希是否在黑名单中"""
    cfg = load_config()
    return sha256.lower() in [h.lower() for h in cfg.get("blacklist_hashes", [])]
