"""
猫卫士 YARA 规则扫描引擎
支持自定义规则文件，可扫描单个文件或整个目录。
"""
import os
import hashlib
import threading
from .utils import get_logger
from . import config
from .cloud_scanner import CloudMalwareScanner, compute_sha256 as compute_sha256_cloud
from .heuristic_detector import BehavioralHeuristicDetector
from .process_injection_detector import ProcessInjectionDetector
from .sandbox360 import get_sandbox

logger = get_logger()

_YARA_AVAILABLE = False
try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    pass

# ── 内置规则（当用户无自定义规则时使用） ──
# 目标：降低误报、提高针对性，尤其是针对勒索/后门/远控。
# 用户可在配置目录中添加自定义规则文件以覆盖或补充。

_BUILTIN_RULES_SOURCE = r"""
import "pe"

// 1) autorun.inf 规则：只检测真正包含执行指令的 autorun.inf
rule SuspiciousAutorun {
    meta:
        description = "Detects autorun.inf files with execution directives"
        severity = "medium"
    strings:
        $autorun = "[autorun]" nocase
        $open = /open\s*=\s*/ nocase
        $shellex = /shellexecute\s*=\s*/ nocase
    condition:
        $autorun and ($open or $shellex)
}

// 2) PowerShell 恶意脚本（需至少两个显著特征）
rule SuspiciousPowerShell {
    meta:
        description = "Detects potentially malicious PowerShell usage patterns"
        severity = "high"
    strings:
        $download = /DownloadString\s*\(/ nocase
        $invoke = /Invoke-Expression\s*\(/ nocase
        $iex = /\bIEX\b/ nocase
        $enc = /-EncodedCommand\b/ nocase
        $bypass = /-ExecutionPolicy\s+Bypass/ nocase
        $web = /New-Object\s+Net\.WebClient/ nocase
    condition:
        2 of them
}

// 3) Batch 脚本中的高风险命令组合（避免单词误报）
rule SuspiciousBatchCommands {
    meta:
        description = "Detects batch scripts that contain multiple high-risk commands"
        severity = "high"
    strings:
        $del = /\bdel\s+\/[fsq]\b/ nocase
        $reg = /\breg\s+(add|delete|query)\b/ nocase
        $net = /\bnet\s+(user|localgroup|stop|start)\b/ nocase
        $taskkill = /\btaskkill\b/ nocase
        $attrib = /\battrib\b/ nocase
        $powershell = /\bpowershell\b/ nocase
    condition:
        2 of them
}

// 4) 识别已知勒索/后门字符串（包含 WannaCry/其他典型样本标志）
rule KnownRansomwareSignatures {
    meta:
        description = "Detects known ransomware/backdoor string markers in PE binaries"
        severity = "critical"
    strings:
        $wannacry1 = "WannaCry" nocase
        $wannacry2 = "WannaCrypt" nocase
        $wannacry3 = "WannaDecryptor" nocase
        $ransom_note = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $ransom_note2 = "文件已被加密" wide
        $cobaltstrike = "Cobalt Strike" nocase
        $mimikatz = "mimikatz" nocase
        $petya = "PETYA" nocase
        $notpetya = "NotPetya" nocase
        $ransomware_marker = "README_FOR_DECRYPT" nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

// 5) 可能的键盘记录器行为：同时存在 hook 与键盘/鼠标钩子
rule PossibleKeylogger {
    meta:
        description = "Detects potential keylogging behavior patterns"
        severity = "high"
    strings:
        $a = "GetAsyncKeyState" ascii
        $b = "SetWindowsHookExA" ascii
        $c = "SetWindowsHookExW" ascii
        $d = "WH_KEYBOARD_LL" ascii
        $e = "WH_MOUSE_LL" ascii
        $f = "CallNextHookEx" ascii
    condition:
        $a and ($b or $c) and ($d or $e or $f)
}
"""


class YaraScanner:
    """YARA 规则扫描器

    该扫描器使用多种检测手段：
      - 内置/自定义 YARA 规则
      - SHA256 黑名单（配置文件中的 blacklist_hashes）
      - PE 结构启发式检测（若安装 pefile 模块）
    """

    def __init__(self):
        self._rules = None
        self._lock = threading.Lock()
        # 内置坏哈希列表，用户可在配置中补充
        self._builtin_bad_hashes = {
            # 示例(不真实):
            # "d41d8cd98f00b204e9800998ecf8427e",
        }
        # 初始化360学习的新检测引擎
        self.cloud_scanner = CloudMalwareScanner()
        self.heuristic_detector = BehavioralHeuristicDetector()
        self.injection_detector = ProcessInjectionDetector()
        self.sandbox = get_sandbox()

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
        """扫描单个文件，返回匹配结果列表。

        每个结果: {"rule": str, "description": str, "severity": str, "file": str, "method": str}
        method 用于标记命中来源（"yara"/"hash"/"pe"）。
        """
        if not self._rules:
            return []

        results = []

        # 1) 哈希黑名单检测
        file_hash = compute_sha256(filepath)
        if file_hash:
            cfg_hashes = set(h.lower() for h in config.get("blacklist_hashes", []) if isinstance(h, str))
            if file_hash.lower() in cfg_hashes or file_hash.lower() in self._builtin_bad_hashes:
                results.append({
                    "rule": "BlacklistedHash",
                    "description": "File hash matches blacklist",
                    "severity": "critical",
                    "file": filepath,
                    "method": "hash",
                })
                # 如果已经黑名单命中，可以直接返回避免浪费扫描
                return results

        # 2) 云查杀检测（向360学习）
        if config.get("cloud_scanner.enabled", False) and file_hash:
            cloud_result = self.cloud_scanner.scan_file_by_hash(file_hash)
            if cloud_result.get('detected') and cloud_result['detections'] >= 3:
                results.append({
                    "rule": "CloudMalwareDetected",
                    "description": f"Cloud scan detected malware ({cloud_result['detections']}/{cloud_result['total']} engines)",
                    "severity": "critical" if cloud_result['risk'] == 'critical' else "high",
                    "file": filepath,
                    "method": "cloud",
                })
                return results  # 云查杀命中，直接返回

        # 2) YARA 规则检测
        try:
            matches = self._rules.match(filepath, timeout=30)
            for m in matches:
                meta = m.meta if hasattr(m, 'meta') else {}
                results.append({
                    "rule": m.rule,
                    "description": meta.get("description", ""),
                    "severity": meta.get("severity", "medium"),
                    "file": filepath,
                    "method": "yara",
                })
        except yara.TimeoutError:
            logger.warning(f"YARA 扫描超时: {filepath}")
        except yara.Error as e:
            logger.debug(f"YARA 扫描错误 {filepath}: {e}")
        except Exception:
            pass

        # 3) PE 结构启发式检测（仅对 PE 有效）
        if file_hash and self._is_pe_file(filepath):
            pe_heuristic = self._scan_pe_heuristics(filepath)
            if pe_heuristic:
                results.append(pe_heuristic)

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
                    "method": "yara",
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
        scan_exts = {
            '.exe', '.dll', '.sys', '.ocx', '.cpl',
            '.bat', '.cmd', '.vbs', '.vbe',
            '.js', '.jse', '.wsf', '.wsh', '.ps1', '.scr',
            '.pif', '.com', '.inf', '.lnk',
        }

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


    def _is_pe_file(self, filepath: str) -> bool:
        """简单判断是否为 PE 文件（检查 MZ 头）。"""
        try:
            with open(filepath, "rb") as f:
                return f.read(2) == b"MZ"
        except OSError:
            return False

    def _scan_pe_heuristics(self, filepath: str) -> dict | None:
        """基于 PE 结构的启发式检测（不依赖第三方库）。"""
        try:
            with open(filepath, "rb") as f:
                data = f.read(1024 * 1024)  # 读取前 1MB 以提高速度
        except OSError:
            return None

        # 1) 仅在 PE 文件（MZ 头）时触发
        if not data.startswith(b"MZ"):
            return None

        basename = os.path.basename(filepath).lower()
        low = data.lower()

        # 2) 【最关键】检查明显的勒索软件/恶意软件特征字符串
        # 这些是真实恶意软件的确定性特征
        critical_malware_strings = [
            # WannaCry/WannaCrypt 系列
            b"wannacry", b"wannacrypt", b"wanadecryptor", b"wcry",
            # Petya 系列
            b"petya", b"notpetya", b"petyawrap",
            # 赎金提示相关
            b"your files have been encrypted",
            b"readme_for_decrypt", b"readme_decrypt",
            # 远程控制工具
            b"cobalt strike", b"cobaltstrike",
            b"mimikatz",
            # 比特币勒索
            b"send bitcoin", b"pay bitcoin", b"transfer bitcoin",
            # 其他已知恶意软件
            b"locky", b"cryptolocker", b"cryptowall",
            b"teslacrypt", b"cerber", b"ransomware",
        ]
        
        has_malware_string = any(s in low for s in critical_malware_strings)
        
        # 如果有已知恶意软件的特征字符串，直接标记为恶意
        if has_malware_string:
            return {
                "rule": "KnownMalwareString",
                "description": "PE 文件包含已知恶意软件特征字符串",
                "severity": "critical",
                "file": filepath,
                "method": "pe",
            }

        # 3) 【严格过滤】只对非安装程序和非常见程序执行API检测
        # 首先检查是否是安装程序或常见程序
        safe_keywords = [
            "setup", "installer", "uninstall", "install", "patch", 
            "update", "framework", "runtime", "sdk", "dotnet", "redistributable",
            # 开发工具
            "python", "java", "node", "git", "visual",
            # 常见软件
            "discord", "steam", "chrome", "firefox", "adobe",
        ]
        
        is_safe_type = any(kw in basename for kw in safe_keywords)
        
        # 如果是安装程序或常见程序类型，不进行API检测
        if is_safe_type:
            return None

        # 4) 仅对可疑的未识别程序执行【严格】的API检测
        # 只有同时满足以下条件才标记：
        # - 包含 CreateRemoteThread（最明确的进程注入）
        # - 同时包含加壳或混淆特征
        
        has_createremotethread = b"createremotethread" in low
        has_packing = any(p in low for p in [
            b".packed", b"upack", b"aspack", b"upx", 
            b"themida", b"vmprotect", b"confuser"
        ])
        
        # 只有当有最明确的恶意特征时才标记
        if has_createremotethread and has_packing:
            return {
                "rule": "PE_Suspicious_APIs",
                "description": "PE 文件包含 CreateRemoteThread API 和加壳特征",
                "severity": "critical",
                "file": filepath,
                "method": "pe",
            }

        return None


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
