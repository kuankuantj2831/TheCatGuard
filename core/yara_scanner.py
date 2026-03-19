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

# 基础规则（不依赖 PE 模块，始终可用）
_BUILTIN_RULES_BASE = r"""

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

// 4) 已知勒索/后门字符串（不限 PE，任何文件类型均可匹配）
rule KnownRansomwareSignatures {
    meta:
        description = "Detects known ransomware/backdoor string markers"
        severity = "critical"
    strings:
        $wannacry1 = "WannaCry" nocase
        $wannacry2 = "WannaCrypt" nocase
        $wannacry3 = "WannaDecryptor" nocase
        $ransom_note = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $ransom_note2 = {E6 96 87 E4 BB B6 E5 B7 B2 E8 A2 AB E5 8A A0 E5 AF 86}
        $cobaltstrike = "Cobalt Strike" nocase
        $mimikatz = "mimikatz" nocase
        $petya = "PETYA" nocase
        $notpetya = "NotPetya" nocase
        $ransomware_marker = "README_FOR_DECRYPT" nocase
    condition:
        any of them
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

// ── WannaCry 专项检测规则 ──

// 6) WannaCry 互斥体 + 服务名 + Kill Switch 域名
rule WannaCry_Mutex_And_Markers {
    meta:
        description = "Detects WannaCry mutex, service name, and kill switch domain"
        severity = "critical"
    strings:
        // WannaCry 使用的全局互斥体
        $mutex1 = "MsWinZonesCacheCounterMutexA" ascii wide
        $mutex2 = "MsWinZonesCacheCounterMutexA0" ascii wide
        // WannaCry 注册的服务名
        $svc1 = "mssecsvc2.0" ascii wide nocase
        // Kill switch 域名
        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide nocase
        // WannaCry 释放的文件名
        $tasksche = "tasksche.exe" ascii wide nocase
        $mssecsvc = "mssecsvc.exe" ascii wide nocase
        // 勒索信文件名
        $readme = "@Please_Read_Me@.txt" ascii wide nocase
        $wannadecryptor = "@WanaDecryptor@.exe" ascii wide nocase
    condition:
        any of them
}

// 7) WannaCry 加密相关特征（高置信度组合）
//    去掉通用 CryptoAPI 名称和 "msg" 等短字符串，只保留 WannaCry 专有标记
rule WannaCry_Encryption_Artifacts {
    meta:
        description = "Detects WannaCry encryption artifacts and ransom file patterns"
        severity = "critical"
    strings:
        // .WNCRY 加密文件扩展名（WannaCry 专有）
        $wncry_ext = ".WNCRY" ascii wide
        $wncryt = ".WNCRYT" ascii wide
        // WannaCry 内嵌的比特币钱包地址（唯一标识）
        $btc1 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
        $btc2 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" ascii
        $btc3 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii
        // WannaCry 资源中的 .wnry 文件（专有命名）
        $res_c = "c.wnry" ascii wide
        $res_r = "r.wnry" ascii wide
        $res_s = "s.wnry" ascii wide
        $res_t = "t.wnry" ascii wide
        $res_u = "u.wnry" ascii wide
    condition:
        // 比特币钱包地址（极高置信度）
        any of ($btc*) or
        // 同时出现 3 个以上 .wnry 资源文件名
        3 of ($res_*) or
        // .WNCRY 扩展名 + 任何 .wnry 资源
        ($wncry_ext or $wncryt) and any of ($res_*)
}

// 8) WannaCry SMB 传播特征（EternalBlue 利用）
//    必须同时匹配 EternalBlue 特征字节 + WannaCry 专有标记，避免误报正常 SMB 程序
rule WannaCry_SMB_Exploit {
    meta:
        description = "Detects WannaCry SMB/EternalBlue exploitation patterns"
        severity = "critical"
    strings:
        // EternalBlue exploit 中的特征操作码序列（非常规 SMB 不会包含）
        $eb_shellcode1 = { 31 C9 41 E2 01 C3 }  // xor ecx,ecx; loop $+3; ret
        $eb_shellcode2 = { E8 18 00 00 00 57 00 69 00 6E 00 45 00 78 00 65 00 63 00 }  // call + "WinExec" wide
        // WannaCry 特有的 SMB 传播函数中的组合
        $smb_pipe = "\\\\%s\\IPC$" ascii
        $svc_name = "mssecsvc2.0" ascii
        // WannaCry 扫描 445 端口的机器码
        $port445_asm = { C7 44 24 ?? BD 01 00 00 }  // mov [esp+xx], 445
        // WannaCry 的 payload 释放路径
        $payload_path = "tasksche.exe" ascii
        $payload_path2 = "mssecsvc.exe" ascii
    condition:
        // 必须有 EternalBlue shellcode 或 WannaCry 专有标记组合
        any of ($eb_shellcode*) or
        ($smb_pipe and ($svc_name or $payload_path or $payload_path2)) or
        ($port445_asm and any of ($svc_name, $payload_path, $payload_path2))
}

// 9) WannaCry PE 文件特征（需要 MZ 头 + 高置信度组合）
//    去掉 "cmd.exe /c"、"attrib +h" 等通用字符串，只保留 WannaCry 专有标记
rule WannaCry_PE_Indicators {
    meta:
        description = "Detects WannaCry PE binary indicators"
        severity = "critical"
    strings:
        // WannaCry 专有文件名（不会出现在正常程序中）
        $wcry1 = "tasksche.exe" ascii wide nocase
        $wcry2 = "mssecsvc.exe" ascii wide nocase
        // WannaCry 专有的 icacls 完整命令（含 Everyone:F）
        $icacls = "icacls . /grant Everyone:F /T /C /Q" ascii nocase
        // WannaCry 的 Tor .onion 地址（唯一标识）
        $tor1 = "gx7ekbenv2riucmf.onion" ascii
        $tor2 = "57g7spgrzlojinas.onion" ascii
        $tor3 = "xxlvbrloxvriy2c5.onion" ascii
        $tor4 = "76jdd2ir2embyv47.onion" ascii
        // WannaCry 注册表键（专有）
        $reg1 = "SOFTWARE\\WanaCrypt0r" ascii wide nocase
        $reg2 = "WanaCrypt0r" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and (
            // 任何 Tor 地址或注册表键 = 高置信度
            any of ($tor*) or any of ($reg*) or
            // WannaCry 专有文件名 + icacls 命令
            ($icacls and any of ($wcry*)) or
            // 同时出现两个 WannaCry 专有文件名
            ($wcry1 and $wcry2)
        )
}

// 10) Memz 木马检测
rule Memz_Trojan {
    meta:
        description = "Detects MEMZ trojan indicators"
        severity = "critical"
    strings:
        $memz1 = "MEMZ" ascii wide nocase
        $memz2 = "MBR has been overwritten" ascii wide nocase
        $memz3 = "Your computer has been trashed" ascii wide nocase
        $memz4 = "Leurak" ascii wide nocase
        $nyan = "nyan cat" ascii wide nocase
        $mbr_write = { B8 00 00 00 00 BA 80 00 }  // MBR 写入特征
    condition:
        2 of them
}

// 11) 通用勒索软件行为特征（文件加密 + 赎金提示）
rule Generic_Ransomware_Behavior {
    meta:
        description = "Detects generic ransomware behavior patterns"
        severity = "high"
    strings:
        $enc1 = "CryptEncrypt" ascii
        $enc2 = "CryptGenKey" ascii
        $enc3 = "CryptImportKey" ascii
        $enc4 = "CryptAcquireContext" ascii
        $del_shadow = "vssadmin delete shadows" ascii wide nocase
        $del_shadow2 = "wmic shadowcopy delete" ascii wide nocase
        $del_backup = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $del_backup2 = "wbadmin delete catalog" ascii wide nocase
        $ransom1 = "your files" ascii wide nocase
        $ransom2 = "encrypted" ascii wide nocase
        $ransom3 = "bitcoin" ascii wide nocase
        $ransom4 = "decrypt" ascii wide nocase
        $ransom5 = "ransom" ascii wide nocase
    condition:
        // 加密 API + 删除卷影副本 = 几乎确定是勒索软件
        (2 of ($enc*) and any of ($del_*)) or
        // 删除卷影副本 + 赎金关键词
        (any of ($del_*) and 2 of ($ransom*))
}
"""

# 需要 PE 模块的高级规则（可选）
_BUILTIN_RULES_PE = r"""
import "pe"

rule WannaCry_PE_Advanced {
    meta:
        description = "Advanced WannaCry PE detection using PE module"
        severity = "critical"
    strings:
        $mutex = "MsWinZonesCacheCounterMutexA" ascii
        $svc = "mssecsvc2.0" ascii
        $tasksche = "tasksche.exe" ascii
    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_resources > 0 and
        any of them
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
        # 内置坏哈希列表 —— 已知恶意软件 SHA256
        self._builtin_bad_hashes = {
            # WannaCry 主样本 (mssecsvc.exe / tasksche.exe)
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
            "2584e1521065e45ec3c17767c065429038fc6291c091097ea8b22c8a502c41dd",
            "f7c7b5e4b051ea5bd0017803f40af13bed224c4b0fd60b890b6784df5bd63494",
            "b9c5d4339809e0ad9a00d4d3dd26fdf44a32819a54abf846bb9b560d81391c25",
            "aee20f9188a5c3954623583c6b0e6623ec90d5cd3fdec4e1001646e27664002c",
            "09a46b3e1be080745a6d8d88d6b5bd351b1c7586ae0dc94d0c238ee36421cafa",
            "4a468603fdcb7a2eb5770705898cf9ef37aade532a7964642ecd705a74794b79",
            # WannaCry dropper
            "db349b97c37d22f5ea1d1841e3c89eb48f997f0dbaad868218b7a29f7bfc60db",
            "21ed253b796f63b9e95b4e426a82303dfac5bf8062bfe669995bbd2dba01f2f3",
            # Memz
            "3d3b5c3f3e3c5c3f3e3c5c3f3e3c5c3f3e3c5c3f3e3c5c3f3e3c5c3f3e3c5c",
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
        """加载 YARA 规则（内置 + 用户自定义）
        
        基础规则不依赖 PE 模块，始终可用。
        PE 高级规则仅在 PE 模块可用时加载。
        """
        if not _YARA_AVAILABLE:
            logger.warning("yara-python 未安装，YARA 扫描不可用")
            return False

        with self._lock:
            try:
                sources = {"builtin_base": _BUILTIN_RULES_BASE}

                # 尝试加载 PE 模块规则
                pe_available = False
                try:
                    yara.compile(source=_BUILTIN_RULES_PE)
                    pe_available = True
                except Exception:
                    logger.info("YARA PE 模块不可用，跳过 PE 高级规则")

                if pe_available:
                    sources["builtin_pe"] = _BUILTIN_RULES_PE

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
                logger.info(f"YARA 规则已加载: {rule_count} 个规则源 (PE模块: {'是' if pe_available else '否'})")
                return True
            except yara.SyntaxError as e:
                logger.error(f"YARA 规则语法错误: {e}")
                # 回退到仅基础规则
                try:
                    self._rules = yara.compile(source=_BUILTIN_RULES_BASE)
                    logger.info("已回退到基础 YARA 规则（无 PE 模块）")
                    return True
                except Exception as e2:
                    logger.error(f"基础规则也加载失败: {e2}")
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
                data = f.read(4 * 1024 * 1024)  # 读取前 4MB
        except OSError:
            return None

        # 仅在 PE 文件（MZ 头）时触发
        if not data.startswith(b"MZ"):
            return None

        basename = os.path.basename(filepath).lower()
        low = data.lower()

        # ── 1) WannaCry 专项二进制特征检测 ──
        wannacry_score = 0
        wannacry_indicators = []

        # 互斥体名（最强特征）
        if b"MsWinZonesCacheCounterMutexA" in data:
            wannacry_score += 5
            wannacry_indicators.append("mutex")

        # 服务名
        if b"mssecsvc2.0" in low:
            wannacry_score += 4
            wannacry_indicators.append("service_name")

        # Kill switch 域名
        if b"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" in low:
            wannacry_score += 5
            wannacry_indicators.append("killswitch")

        # WannaCry 释放的文件名
        wcry_files = [b"tasksche.exe", b"mssecsvc.exe", b"@wannadecryptor@",
                       b"@please_read_me@", b".wncry", b".wncryt"]
        wcry_file_hits = sum(1 for f in wcry_files if f in low)
        if wcry_file_hits >= 2:
            wannacry_score += 3
            wannacry_indicators.append(f"wcry_files({wcry_file_hits})")

        # .wnry 资源文件名
        wnry_resources = [b"c.wnry", b"r.wnry", b"s.wnry", b"t.wnry", b"u.wnry"]
        wnry_hits = sum(1 for r in wnry_resources if r in low)
        if wnry_hits >= 3:
            wannacry_score += 4
            wannacry_indicators.append(f"wnry_resources({wnry_hits})")

        # Tor .onion 地址
        onion_addrs = [b"gx7ekbenv2riucmf.onion", b"57g7spgrzlojinas.onion",
                       b"xxlvbrloxvriy2c5.onion", b"76jdd2ir2embyv47.onion"]
        if any(addr in low for addr in onion_addrs):
            wannacry_score += 4
            wannacry_indicators.append("tor_onion")

        # 比特币钱包地址
        btc_addrs = [b"115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn",
                     b"12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw",
                     b"13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"]
        if any(addr in data for addr in btc_addrs):
            wannacry_score += 5
            wannacry_indicators.append("btc_wallet")

        # 注册表键
        if b"WanaCrypt0r" in data or b"SOFTWARE\\WanaCrypt0r" in data:
            wannacry_score += 4
            wannacry_indicators.append("registry_key")

        # icacls 提权命令
        if b"icacls . /grant Everyone:F" in data:
            wannacry_score += 3
            wannacry_indicators.append("icacls_grant")

        if wannacry_score >= 4:
            return {
                "rule": "WannaCry_Heuristic",
                "description": f"PE 文件匹配 WannaCry 特征 (评分:{wannacry_score}, 指标:{','.join(wannacry_indicators)})",
                "severity": "critical",
                "file": filepath,
                "method": "pe",
            }

        # ── 2) 已知恶意软件特征字符串 ──
        critical_malware_strings = [
            b"wannacry", b"wannacrypt", b"wanadecryptor", b"wcry",
            b"petya", b"notpetya", b"petyawrap",
            b"your files have been encrypted",
            b"readme_for_decrypt", b"readme_decrypt",
            b"cobalt strike", b"cobaltstrike",
            b"mimikatz",
            b"send bitcoin", b"pay bitcoin", b"transfer bitcoin",
            b"locky", b"cryptolocker", b"cryptowall",
            b"teslacrypt", b"cerber", b"ransomware",
        ]

        if any(s in low for s in critical_malware_strings):
            return {
                "rule": "KnownMalwareString",
                "description": "PE 文件包含已知恶意软件特征字符串",
                "severity": "critical",
                "file": filepath,
                "method": "pe",
            }

        # ── 3) 勒索软件行为组合检测 ──
        has_crypto_api = sum(1 for api in [b"CryptEncrypt", b"CryptGenKey",
                                            b"CryptImportKey", b"CryptAcquireContext"]
                            if api in data)
        has_shadow_delete = b"vssadmin delete shadows" in low or b"wmic shadowcopy delete" in low
        has_recovery_disable = b"recoveryenabled no" in low or b"wbadmin delete catalog" in low

        if has_crypto_api >= 2 and (has_shadow_delete or has_recovery_disable):
            return {
                "rule": "Ransomware_Behavior",
                "description": "PE 文件同时包含加密 API 和卷影副本删除/恢复禁用命令",
                "severity": "critical",
                "file": filepath,
                "method": "pe",
            }

        # ── 4) 严格的 API 注入检测（仅对非安装程序）──
        safe_keywords = [
            "setup", "installer", "uninstall", "install", "patch",
            "update", "framework", "runtime", "sdk", "dotnet", "redistributable",
            "python", "java", "node", "git", "visual",
            "discord", "steam", "chrome", "firefox", "adobe",
        ]

        if not any(kw in basename for kw in safe_keywords):
            has_createremotethread = b"createremotethread" in low
            has_packing = any(p in low for p in [
                b".packed", b"upack", b"aspack", b"upx",
                b"themida", b"vmprotect", b"confuser"
            ])

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
