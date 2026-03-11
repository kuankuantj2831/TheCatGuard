"""
猫卫士配置管理模块
JSON 配置文件的读写，支持白名单/黑名单、监控参数、隔离区设置。
配置文件使用 HMAC-SHA256 签名防止篡改。
"""
import json
import os
import hmac
import hashlib
import tempfile
import threading
from .utils import get_logger

logger = get_logger()

_CONFIG_DIR = os.path.join(os.path.expandvars("%LOCALAPPDATA%"), "TheCatGuard")
_CONFIG_FILE = os.path.join(_CONFIG_DIR, "config.json")
_HMAC_FILE = os.path.join(_CONFIG_DIR, "config.sig")
# 签名密钥：基于机器 SID + 安装路径派生，防止跨机器伪造
_HMAC_KEY = hashlib.sha256(
    f"{os.path.abspath(__file__)}:{os.path.expandvars('%COMPUTERNAME%')}".encode()
).digest()

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


def load_config(*, _copy=True) -> dict:
    """加载配置，不存在则创建默认配置。内部高频调用可传 _copy=False 避免拷贝。"""
    global _cache
    with _lock:
        if _cache is not None:
            return _cache.copy() if _copy else _cache
        _ensure_dir()
        if os.path.isfile(_CONFIG_FILE):
            try:
                with open(_CONFIG_FILE, "rb") as f:
                    raw = f.read()
                if not _verify_hmac(raw):
                    logger.warning("配置文件签名验证失败！可能被篡改，使用默认配置")
                    # 备份被篡改的文件供取证
                    tampered = _CONFIG_FILE + ".tampered"
                    try:
                        import shutil
                        shutil.copy2(_CONFIG_FILE, tampered)
                    except Exception:
                        pass
                else:
                    data = json.loads(raw.decode("utf-8"))
                    merged = {**_DEFAULT_CONFIG, **data}
                    _cache = merged
                    return merged.copy() if _copy else _cache
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"配置文件损坏，使用默认配置: {e}")
        _cache = _DEFAULT_CONFIG.copy()
        _write_file(_cache)
        return _cache.copy() if _copy else _cache


def _compute_hmac(data: bytes) -> str:
    """计算配置数据的 HMAC-SHA256 签名"""
    return hmac.new(_HMAC_KEY, data, hashlib.sha256).hexdigest()


def _verify_hmac(data: bytes) -> bool:
    """验证配置数据的 HMAC 签名"""
    if not os.path.isfile(_HMAC_FILE):
        return False
    try:
        with open(_HMAC_FILE, "r", encoding="utf-8") as f:
            stored_sig = f.read().strip()
        return hmac.compare_digest(stored_sig, _compute_hmac(data))
    except OSError:
        return False


def _write_file(config: dict):
    """原子写入配置文件 + HMAC 签名（调用方需自行持有 _lock 或确保安全）"""
    try:
        data = json.dumps(config, ensure_ascii=False, indent=2).encode("utf-8")
        # 原子写入：先写临时文件再替换，防止崩溃导致损坏
        fd, tmp_path = tempfile.mkstemp(dir=_CONFIG_DIR, suffix=".tmp")
        try:
            os.write(fd, data)
            os.close(fd)
            fd = -1
            # Windows 上 os.replace 是原子操作
            os.replace(tmp_path, _CONFIG_FILE)
        except Exception:
            if fd >= 0:
                os.close(fd)
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise
        # 写入 HMAC 签名
        sig = _compute_hmac(data)
        with open(_HMAC_FILE, "w", encoding="utf-8") as f:
            f.write(sig)
    except OSError as e:
        logger.error(f"保存配置失败: {e}")


def save_config(config: dict):
    """保存配置到文件"""
    global _cache
    with _lock:
        _ensure_dir()
        _cache = config.copy()
        _write_file(_cache)


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
    cfg = load_config(_copy=False)
    return name.lower() in [p.lower() for p in cfg.get("whitelist_processes", [])]


def is_path_whitelisted(path: str) -> bool:
    """检查路径是否在白名单路径前缀中"""
    cfg = load_config(_copy=False)
    path_lower = os.path.normcase(os.path.normpath(path))
    for wp in cfg.get("whitelist_paths", []):
        if path_lower.startswith(os.path.normcase(os.path.normpath(wp))):
            return True
    return False


def is_ip_whitelisted(ip: str) -> bool:
    """检查 IP 是否在白名单中"""
    cfg = load_config(_copy=False)
    return ip in cfg.get("whitelist_network_ips", [])


def is_process_blacklisted(name: str) -> bool:
    """检查进程名是否在黑名单中"""
    cfg = load_config(_copy=False)
    return name.lower() in [p.lower() for p in cfg.get("blacklist_processes", [])]


def is_hash_blacklisted(sha256: str) -> bool:
    """检查文件哈希是否在黑名单中"""
    cfg = load_config()
    return sha256.lower() in [h.lower() for h in cfg.get("blacklist_hashes", [])]
