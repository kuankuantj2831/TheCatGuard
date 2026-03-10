"""
猫卫士 YARA 规则扫描引擎
支持自定义规则文件，可扫描单个文件或整个目录。
"""
import os
import hashlib
import threading
from .utils import get_logger
from . import config

logger = get_logger()

_YARA_AVAILABLE = False
try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    pass

# ── 内置规则（当用户无自定义规则时使用） ──
_BUILTIN_RULES_SOURCE = r"""
rule SuspiciousAutorun {
    meta:
        description = "Detects autorun.inf files"
        severity = "medium"
    strings:
        $a = "[autorun]" nocase
        $b = "open=" nocase
        $c = "shellexecute=" nocase
    condition:
        $a and ($b or $c)
}

rule SuspiciousBatchCommands {
    meta:
        description = "Detects batch files with suspicious commands"
        severity = "high"
    strings:
        $del_sys = "del /f /s /q" nocase
        $reg_add = "reg add" nocase
        $reg_delete = "reg delete" nocase
        $net_stop = "net stop" nocase
        $taskkill = "taskkill /f" nocase
        $attrib_h = "attrib +h +s" nocase
        $powershell_enc = "-encodedcommand" nocase
        $powershell_bypass = "-executionpolicy bypass" nocase
    condition:
        3 of them
}

rule SuspiciousPowerShell {
    meta:
        description = "Detects PowerShell scripts with suspicious patterns"
        severity = "high"
    strings:
        $download = "downloadstring" nocase
        $download2 = "downloadfile" nocase
        $webclient = "net.webclient" nocase
        $invoke = "invoke-expression" nocase
        $iex = "iex(" nocase
        $hidden = "-windowstyle hidden" nocase
        $bypass = "-ep bypass" nocase
        $encoded = "frombase64string" nocase
    condition:
        2 of them
}

rule SuspiciousVBScript {
    meta:
        description = "Detects VBScript with suspicious patterns"
        severity = "high"
    strings:
        $shell = "wscript.shell" nocase
        $http = "msxml2.xmlhttp" nocase
        $stream = "adodb.stream" nocase
        $exec = ".run " nocase
        $reg = "regwrite" nocase
    condition:
        2 of them
}

rule PossibleKeylogger {
    meta:
        description = "Detects possible keylogger indicators"
        severity = "critical"
    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "SetWindowsHookEx" ascii
        $api3 = "GetKeyState" ascii
        $log = "keylog" nocase
    condition:
        2 of them
}
"""


class YaraScanner:
    """YARA 规则扫描器"""

    def __init__(self):
        self._rules = None
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return _YARA_AVAILABLE

    def load_rules(self) -> bool:
        """加载 YARA 规则（内置 + 用户自定义）"""
        if not _YARA_AVAILABLE:
            logger.warning("yara-python 未安装，YARA 扫描不可用")
            return False

        with self._lock:
            try:
                sources = {"builtin": _BUILTIN_RULES_SOURCE}

                # 加载用户自定义规则文件
                rules_dir = config.get_yara_rules_dir()
                if os.path.isdir(rules_dir):
                    for fname in os.listdir(rules_dir):
                        if fname.endswith(('.yar', '.yara')):
                            fpath = os.path.join(rules_dir, fname)
                            try:
                                with open(fpath, "r", encoding="utf-8") as f:
                                    sources[fname] = f.read()
                            except OSError as e:
                                logger.warning(f"无法读取 YARA 规则文件 {fname}: {e}")

                self._rules = yara.compile(sources=sources)
                rule_count = len(sources)
                logger.info(f"YARA 规则已加载: {rule_count} 个规则源")
                return True
            except yara.SyntaxError as e:
                logger.error(f"YARA 规则语法错误: {e}")
                # 回退到仅内置规则
                try:
                    self._rules = yara.compile(source=_BUILTIN_RULES_SOURCE)
                    logger.info("已回退到内置 YARA 规则")
                    return True
                except Exception:
                    pass
            except Exception as e:
                logger.error(f"YARA 规则加载失败: {e}")
            return False

    def scan_file(self, filepath: str) -> list:
        """
        扫描单个文件，返回匹配结果列表。
        每个结果: {"rule": str, "description": str, "severity": str, "file": str}
        """
        if not self._rules:
            return []

        results = []
        try:
            matches = self._rules.match(filepath, timeout=30)
            for m in matches:
                meta = m.meta if hasattr(m, 'meta') else {}
                results.append({
                    "rule": m.rule,
                    "description": meta.get("description", ""),
                    "severity": meta.get("severity", "medium"),
                    "file": filepath,
                })
        except yara.TimeoutError:
            logger.warning(f"YARA 扫描超时: {filepath}")
        except yara.Error as e:
            logger.debug(f"YARA 扫描错误 {filepath}: {e}")
        except Exception:
            pass
        return results

    def scan_data(self, data: bytes, label: str = "") -> list:
        """扫描内存数据"""
        if not self._rules:
            return []

        results = []
        try:
            matches = self._rules.match(data=data, timeout=30)
            for m in matches:
                meta = m.meta if hasattr(m, 'meta') else {}
                results.append({
                    "rule": m.rule,
                    "description": meta.get("description", ""),
                    "severity": meta.get("severity", "medium"),
                    "file": label,
                })
        except Exception:
            pass
        return results

    def scan_directory(self, dirpath: str, recursive: bool = True,
                       callback=None, stop_event: threading.Event = None) -> list:
        """
        扫描目录下的文件。
        callback(filepath, results): 每扫描一个文件后回调。
        stop_event: 外部可设置以中止扫描。
        返回所有匹配结果。
        """
        if not self._rules:
            return []

        all_results = []
        scan_exts = {'.exe', '.dll', '.bat', '.cmd', '.vbs', '.vbe',
                     '.js', '.jse', '.wsf', '.wsh', '.ps1', '.scr',
                     '.pif', '.com', '.inf', '.lnk'}

        for root, dirs, files in os.walk(dirpath):
            if stop_event and stop_event.is_set():
                break
            for fname in files:
                if stop_event and stop_event.is_set():
                    break
                ext = os.path.splitext(fname)[1].lower()
                if ext not in scan_exts:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    # 跳过过大的文件（>50MB）
                    if os.path.getsize(fpath) > 50 * 1024 * 1024:
                        continue
                    results = self.scan_file(fpath)
                    if results:
                        all_results.extend(results)
                    if callback:
                        callback(fpath, results)
                except OSError:
                    pass
            if not recursive:
                break

        return all_results


def compute_sha256(filepath: str) -> str:
    """计算文件 SHA256 哈希"""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""
