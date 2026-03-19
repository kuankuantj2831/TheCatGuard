"""
隐私保护与数据安全模块 - 文件加密、隐私清理、数据防护
- AES加密/解密支持
- 浏览器隐私清理（Cookie、历史、缓存）
- 敏感数据检测和防护
- 安全文件擦除（多遍覆盖）
- 剪贴板监控和清理
"""
import os
import sys
import shutil
import json
import time
import threading
import subprocess
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
try:
    # 新版本 (>= 42.0.0): PBKDF2 改名为 PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as PBKDF2
except ImportError:
    # 旧版本
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from .utils import get_logger

logger = get_logger()


class FileEncryptor:
    """文件加密/解密管理器"""
    
    def __init__(self, master_password=None):
        """
        初始化文件加密器
        
        Args:
            master_password: 主密码（为空时使用系统用户）
        """
        self.master_password = master_password or self._generate_system_key()
        self.cipher_suite = self._create_cipher()
        self.encryption_metadata = {}
    
    def _generate_system_key(self):
        """基于Windows用户SID生成系统密钥"""
        try:
            import subprocess
            result = subprocess.run(
                ["wmic", "useraccount", "get", "sid"],
                capture_output=True,
                text=True,
                timeout=5
            )
            # 简化处理：使用用户名 + 计算机名
            hostname = os.environ.get("COMPUTERNAME", "unknown")
            username = os.environ.get("USERNAME", "unknown")
            key = f"{username}@{hostname}".encode()
            
            # 使用PBKDF2生成密钥
            salt = b'\x00' * 16  # 简单实现，生产环境应随机生成
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            key = kdf.derive(key)
            return key
        except Exception as e:
            logger.warning(f"系统密钥生成失败: {e}，使用默认密钥")
            return Fernet.generate_key()
    
    def _create_cipher(self):
        """创建加密套件"""
        try:
            if isinstance(self.master_password, str):
                key = self.master_password.encode()
            else:
                key = self.master_password
            
            # 确保密钥长度为32字节
            if len(key) < 32:
                key = key + b'\x00' * (32 - len(key))
            else:
                key = key[:32]
            
            # 使用URL安全的Base64编码密钥
            import base64
            b64_key = base64.urlsafe_b64encode(key)
            return Fernet(b64_key)
        except Exception as e:
            logger.error(f"加密套件创建失败: {e}")
            return None
    
    def encrypt_file(self, file_path, delete_original=False):
        """
        加密单个文件
        
        Args:
            file_path: 文件路径
            delete_original: 是否删除原文件
        
        Returns:
            (success, encrypted_file_path)
        """
        try:
            if not os.path.isfile(file_path):
                logger.error(f"文件不存在: {file_path}")
                return False, None
            
            # 读取文件内容
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # 加密
            encrypted_data = self.cipher_suite.encrypt(file_data)
            
            # 保存加密文件
            encrypted_path = file_path + ".encrypted"
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # 记录元数据
            self.encryption_metadata[encrypted_path] = {
                "original_path": file_path,
                "original_size": len(file_data),
                "encrypted_size": len(encrypted_data),
                "encryption_time": datetime.now().isoformat(),
                "hash_algorithm": "PBKDF2"
            }
            
            # 删除原文件
            if delete_original:
                self._secure_delete(file_path)
            
            logger.info(f"文件已加密: {file_path} -> {encrypted_path}")
            return True, encrypted_path
        
        except Exception as e:
            logger.error(f"文件加密失败: {e}")
            return False, None
    
    def encrypt_directory(self, dir_path, pattern="*", delete_original=False):
        """
        加密目录中的所有文件
        
        Args:
            dir_path: 目录路径
            pattern: 文件模式（如 *.txt）
            delete_original: 是否删除原文件
        
        Returns:
            (success_count, fail_count)
        """
        success_count = 0
        fail_count = 0
        
        try:
            path = Path(dir_path)
            for file_path in path.glob(pattern):
                if file_path.is_file():
                    success, _ = self.encrypt_file(str(file_path), delete_original)
                    if success:
                        success_count += 1
                    else:
                        fail_count += 1
        
        except Exception as e:
            logger.error(f"目录加密失败: {e}")
        
        return success_count, fail_count
    
    def decrypt_file(self, encrypted_file_path, output_path=None):
        """
        解密文件
        
        Args:
            encrypted_file_path: 加密文件路径
            output_path: 输出路径（默认删除.encrypted后缀）
        
        Returns:
            (success, output_path)
        """
        try:
            if not os.path.isfile(encrypted_file_path):
                logger.error(f"加密文件不存在: {encrypted_file_path}")
                return False, None
            
            # 读取加密文件
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # 解密
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            
            # 确定输出路径
            if output_path is None:
                if encrypted_file_path.endswith('.encrypted'):
                    output_path = encrypted_file_path[:-10]  # 移除 .encrypted
                else:
                    output_path = encrypted_file_path + '.decrypted'
            
            # 保存解密文件
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            logger.info(f"文件已解密: {encrypted_file_path} -> {output_path}")
            return True, output_path
        
        except Exception as e:
            logger.error(f"文件解密失败: {e}")
            return False, None
    
    def _secure_delete(self, file_path, passes=3):
        """
        安全删除文件（多遍覆盖）
        
        Args:
            file_path: 文件路径
            passes: 覆盖遍数
        """
        try:
            file_size = os.path.getsize(file_path)
            
            # 多遍覆盖
            for _ in range(passes):
                with open(file_path, 'ba+') as f:
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # 删除文件
            os.remove(file_path)
            logger.debug(f"文件已安全删除: {file_path}")
        
        except Exception as e:
            logger.error(f"文件安全删除失败: {e}")


class PrivacyCleaner:
    """隐私清理工具"""
    
    def __init__(self):
        self.browsers = self._detect_browsers()
        self.cleanup_log = deque(maxlen=100)
    
    def _detect_browsers(self):
        """检测系统中安装的浏览器"""
        browsers = {}
        
        # Chrome
        chrome_path = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data")
        if os.path.exists(chrome_path):
            browsers['chrome'] = chrome_path
        
        # Firefox
        firefox_path = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
        if os.path.exists(firefox_path):
            browsers['firefox'] = firefox_path
        
        # Edge
        edge_path = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data")
        if os.path.exists(edge_path):
            browsers['edge'] = edge_path
        
        return browsers
    
    def clean_chrome_history(self):
        """清理Chrome浏览历史"""
        if 'chrome' not in self.browsers:
            return False, "Chrome未安装"
        
        try:
            chrome_path = self.browsers['chrome']
            
            # Chrome的主要数据库文件
            data_files = [
                "History",           # 浏览历史
                "History-journal",
                "Cookies",           # Cookie
                "Cookies-journal",
                "Cache/Cache_Data",  # 缓存
                "Code Cache/js",
            ]
            
            deleted_count = 0
            
            for data_file in data_files:
                file_path = os.path.join(chrome_path, data_file)
                
                # 处理目录
                if os.path.isdir(file_path):
                    try:
                        shutil.rmtree(file_path)
                        deleted_count += 1
                    except Exception as e:
                        logger.debug(f"删除Chrome目录失败 {file_path}: {e}")
                
                # 处理文件
                elif os.path.isfile(file_path):
                    try:
                        os.remove(file_path)
                        deleted_count += 1
                    except Exception as e:
                        logger.debug(f"删除Chrome文件失败 {file_path}: {e}")
            
            self.cleanup_log.append({
                "browser": "Chrome",
                "timestamp": datetime.now(),
                "deleted_items": deleted_count
            })
            
            logger.info(f"Chrome隐私已清理，删除了 {deleted_count} 项")
            return True, f"成功删除 {deleted_count} 项Chrome数据"
        
        except Exception as e:
            logger.error(f"Chrome隐私清理失败: {e}")
            return False, str(e)
    
    def clean_firefox_history(self):
        """清理Firefox浏览历史"""
        if 'firefox' not in self.browsers:
            return False, "Firefox未安装"
        
        try:
            firefox_path = self.browsers['firefox']
            
            # Firefox的主要数据库文件
            data_files = [
                "places.sqlite",       # 浏览历史和书签
                "places.sqlite-wal",
                "cookies.sqlite",      # Cookie
                "cache2/entries",      # 缓存
            ]
            
            deleted_count = 0
            
            # 遍历所有Firefox配置文件目录
            if os.path.exists(firefox_path):
                for profile_dir in os.listdir(firefox_path):
                    profile_path = os.path.join(firefox_path, profile_dir)
                    
                    if os.path.isdir(profile_path):
                        for data_file in data_files:
                            file_path = os.path.join(profile_path, data_file)
                            
                            if os.path.isdir(file_path):
                                try:
                                    shutil.rmtree(file_path)
                                    deleted_count += 1
                                except:
                                    pass
                            elif os.path.isfile(file_path):
                                try:
                                    os.remove(file_path)
                                    deleted_count += 1
                                except:
                                    pass
            
            self.cleanup_log.append({
                "browser": "Firefox",
                "timestamp": datetime.now(),
                "deleted_items": deleted_count
            })
            
            logger.info(f"Firefox隐私已清理，删除了 {deleted_count} 项")
            return True, f"成功删除 {deleted_count} 项Firefox数据"
        
        except Exception as e:
            logger.error(f"Firefox隐私清理失败: {e}")
            return False, str(e)
    
    def clean_system_temporary_files(self):
        """清理系统临时文件"""
        temp_dirs = [
            os.environ.get("TEMP", ""),
            os.environ.get("TMP", ""),
            os.path.expandvars(r"%WINDIR%\Temp"),
        ]
        
        deleted_count = 0
        
        for temp_dir in temp_dirs:
            if not temp_dir or not os.path.exists(temp_dir):
                continue
            
            try:
                for item in os.listdir(temp_dir):
                    item_path = os.path.join(temp_dir, item)
                    
                    try:
                        if os.path.isfile(item_path):
                            os.remove(item_path)
                            deleted_count += 1
                        elif os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                            deleted_count += 1
                    except:
                        pass
            
            except Exception as e:
                logger.debug(f"临时文件夹清理失败 {temp_dir}: {e}")
        
        logger.info(f"系统临时文件已清理，删除了 {deleted_count} 项")
        return True, f"成功删除 {deleted_count} 个临时文件"
    
    def clean_clipboard(self):
        """清理剪贴板"""
        try:
            # 使用PowerShell清空剪贴板
            subprocess.run(
                ["powershell", "-Command", "Set-Clipboard -Value $null"],
                capture_output=True,
                timeout=5
            )
            logger.info("剪贴板已清理")
            return True, "剪贴板已清理"
        except Exception as e:
            logger.error(f"剪贴板清理失败: {e}")
            return False, str(e)
    
    def clean_registry_artifacts(self):
        """清理注册表痕迹（MRU列表等）"""
        try:
            # 清理最近使用文件列表
            mru_keys = [
                r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
                r"HKEY_CURRENT_USER\Software\Microsoft\Office\Common\Open Find",
            ]
            
            for key in mru_keys:
                try:
                    cmd = f'reg delete "{key}" /f'
                    subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
                except Exception as e:
                    logger.debug(f"注册表清理失败 {key}: {e}")
            
            logger.info("注册表痕迹已清理")
            return True, "注册表痕迹已清理"
        
        except Exception as e:
            logger.error(f"注册表清理失败: {e}")
            return False, str(e)


class SensitiveDataDetector:
    """敏感数据检测器"""
    
    def __init__(self):
        # 敏感文件类型
        self.sensitive_extensions = [
            ".key", ".pem", ".pfx", ".p12",  # 密钥
            ".sql", ".db", ".sqlite",         # 数据库
            ".doc", ".docx", ".xls", ".xlsx", # 文档
            ".zip", ".rar", ".7z",            # 压缩包
        ]
        
        # 敏感数据特征
        self.sensitive_patterns = {
            "credit_card": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
            "social_security": r"\b\d{3}-\d{2}-\d{4}\b",
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "api_key": r"(api_key|apikey|secret)[\s]*[:=][\s]*['\"]?[A-Za-z0-9_-]+['\"]?",
        }
    
    def scan_directory(self, dir_path):
        """
        扫描目录查找敏感文件
        
        Returns:
            {
                "sensitive_files": [...],
                "scan_time": timestamp
            }
        """
        sensitive_files = []
        
        try:
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # 检查文件扩展名
                    file_ext = os.path.splitext(file)[1].lower()
                    if file_ext in self.sensitive_extensions:
                        sensitive_files.append({
                            "path": file_path,
                            "type": "sensitive_extension",
                            "extension": file_ext
                        })
        
        except Exception as e:
            logger.error(f"敏感文件扫描失败: {e}")
        
        return {
            "sensitive_files": sensitive_files,
            "scan_time": datetime.now().isoformat(),
            "total_found": len(sensitive_files)
        }
    
    def scan_file_content(self, file_path):
        """
        扫描文件内容查找敏感数据
        
        Returns:
            {
                "findings": [...],
                "risk_level": "low" / "medium" / "high"
            }
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 检查每种敏感数据模式
            import re
            for pattern_name, pattern in self.sensitive_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        "type": pattern_name,
                        "value": match.group(0),
                        "line": content[:match.start()].count('\n') + 1
                    })
        
        except Exception as e:
            logger.debug(f"文件内容扫描失败: {e}")
        
        # 评估风险等级
        risk_level = "low"
        if len(findings) > 5:
            risk_level = "high"
        elif len(findings) > 2:
            risk_level = "medium"
        
        return {
            "findings": findings,
            "risk_level": risk_level,
            "total_findings": len(findings)
        }


# 全局实例
_file_encryptor = None
_privacy_cleaner = None
_sensitive_data_detector = None


def get_file_encryptor():
    """获取文件加密器实例"""
    global _file_encryptor
    if _file_encryptor is None:
        _file_encryptor = FileEncryptor()
    return _file_encryptor


def get_privacy_cleaner():
    """获取隐私清理器实例"""
    global _privacy_cleaner
    if _privacy_cleaner is None:
        _privacy_cleaner = PrivacyCleaner()
    return _privacy_cleaner


def get_sensitive_data_detector():
    """获取敏感数据检测器实例"""
    global _sensitive_data_detector
    if _sensitive_data_detector is None:
        _sensitive_data_detector = SensitiveDataDetector()
    return _sensitive_data_detector
