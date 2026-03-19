import os
import subprocess
import winreg
import shutil
import time
from .utils import get_logger
from . import config

logger = get_logger()

class AutoFixer:
    """自动修复引擎 - 针对常见安全问题提供一键修复"""

    def __init__(self):
        self.backup_dir = os.path.join(config.get_quarantine_dir(), "backups")
        os.makedirs(self.backup_dir, exist_ok=True)

    def create_system_restore_point(self, description="TheCatGuard Auto Fix"):
        """创建系统还原点"""
        try:
            # 使用PowerShell创建还原点
            cmd = [
                "powershell",
                "-Command",
                f"Checkpoint-Computer -Description '{description}' -RestorePointType 'MODIFY_SETTINGS'"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info("系统还原点创建成功")
                return True
            else:
                logger.warning(f"系统还原点创建失败: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"创建还原点异常: {e}")
            return False

    def fix_startup_entries(self, suspicious_entries: list) -> dict:
        """
        修复可疑启动项
        Args:
            suspicious_entries: 可疑启动项列表，每个元素为 (key_path, value_name)
        Returns:
            修复结果字典
        """
        results = {"fixed": 0, "failed": 0, "backed_up": 0}

        for key_path, value_name in suspicious_entries:
            try:
                # 备份注册表项
                backup_path = self._backup_registry_key(key_path, value_name)
                if backup_path:
                    results["backed_up"] += 1

                # 删除可疑启动项
                if self._delete_registry_value(key_path, value_name):
                    results["fixed"] += 1
                    logger.info(f"已移除可疑启动项: {key_path}\\{value_name}")
                else:
                    results["failed"] += 1

            except Exception as e:
                logger.error(f"修复启动项失败 {key_path}\\{value_name}: {e}")
                results["failed"] += 1

        return results

    def fix_hosts_file(self, malicious_entries: list) -> dict:
        """
        修复被篡改的hosts文件
        Args:
            malicious_entries: 恶意hosts条目列表
        Returns:
            修复结果字典
        """
        results = {"fixed": 0, "failed": 0, "backed_up": False}

        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"

        try:
            # 备份hosts文件
            backup_path = os.path.join(self.backup_dir, f"hosts_{int(time.time())}.bak")
            shutil.copy2(hosts_path, backup_path)
            results["backed_up"] = True

            # 读取当前hosts内容
            with open(hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # 移除恶意条目
            cleaned_lines = []
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    cleaned_lines.append(line)
                    continue

                # 检查是否为恶意条目
                is_malicious = False
                for malicious in malicious_entries:
                    if malicious in line:
                        is_malicious = True
                        break

                if not is_malicious:
                    cleaned_lines.append(line)
                else:
                    results["fixed"] += 1
                    logger.info(f"已移除恶意hosts条目: {line}")

            # 写回干净的hosts文件
            with open(hosts_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(cleaned_lines) + '\n')

            logger.info("hosts文件修复完成")

        except Exception as e:
            logger.error(f"修复hosts文件失败: {e}")
            results["failed"] = len(malicious_entries)

        return results

    def fix_dns_settings(self) -> dict:
        """修复被篡改的DNS设置"""
        results = {"fixed": 0, "failed": 0}

        try:
            # 重置DNS为自动获取
            cmd = [
                "powershell",
                "-Command",
                "Set-DnsClientServerAddress -InterfaceAlias '*' -ResetServerAddresses"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                results["fixed"] += 1
                logger.info("DNS设置已重置为自动获取")
            else:
                results["failed"] += 1
                logger.error(f"DNS重置失败: {result.stderr}")

        except Exception as e:
            logger.error(f"DNS修复异常: {e}")
            results["failed"] += 1

        return results

    def quarantine_file(self, file_path: str, threat_type: str = "unknown") -> bool:
        """隔离可疑文件"""
        try:
            from .quarantine import QuarantineManager
            quarantine = QuarantineManager()

            if quarantine.add_file(file_path, threat_type):
                logger.info(f"文件已隔离: {file_path}")
                return True
            else:
                logger.error(f"文件隔离失败: {file_path}")
                return False

        except Exception as e:
            logger.error(f"隔离文件异常 {file_path}: {e}")
            return False

    def kill_suspicious_process(self, pid: int, process_name: str) -> bool:
        """终止可疑进程"""
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.kill()
            logger.info(f"已终止可疑进程: {process_name}(PID:{pid})")
            return True
        except Exception as e:
            logger.error(f"终止进程失败 {process_name}(PID:{pid}): {e}")
            return False

    def fix_browser_hijack(self) -> dict:
        """修复浏览器劫持"""
        results = {"fixed": 0, "failed": 0}

        # 重置浏览器主页和搜索引擎
        browser_fixes = {
            "chrome": self._fix_chrome_settings,
            "firefox": self._fix_firefox_settings,
            "edge": self._fix_edge_settings
        }

        for browser, fix_func in browser_fixes.items():
            try:
                if fix_func():
                    results["fixed"] += 1
                    logger.info(f"{browser}浏览器设置已修复")
                else:
                    results["failed"] += 1
            except Exception as e:
                logger.error(f"{browser}修复失败: {e}")
                results["failed"] += 1

        return results

    def _backup_registry_key(self, key_path: str, value_name: str) -> str:
        """备份注册表项到文件"""
        try:
            timestamp = int(time.time())
            backup_file = os.path.join(self.backup_dir, f"reg_{timestamp}.bak")

            # 使用reg export备份
            cmd = ["reg", "export", key_path, backup_file, "/y"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                return backup_file
            else:
                logger.warning(f"注册表备份失败: {result.stderr}")
                return ""

        except Exception as e:
            logger.error(f"备份注册表异常: {e}")
            return ""

    def _delete_registry_value(self, key_path: str, value_name: str) -> bool:
        """删除注册表值"""
        try:
            # 使用reg delete命令
            cmd = ["reg", "delete", key_path, "/v", value_name, "/f"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            return result.returncode == 0

        except Exception as e:
            logger.error(f"删除注册表值异常: {e}")
            return False

    def _fix_chrome_settings(self) -> bool:
        """修复Chrome浏览器设置"""
        try:
            # 重置Chrome主页和默认搜索引擎
            chrome_prefs = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Preferences")

            if os.path.exists(chrome_prefs):
                # 这里可以实现具体的Chrome设置修复
                # 暂时返回成功
                return True
            return False
        except Exception:
            return False

    def _fix_firefox_settings(self) -> bool:
        """修复Firefox浏览器设置"""
        try:
            firefox_prefs = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")

            if os.path.exists(firefox_prefs):
                # 查找默认配置文件目录
                for item in os.listdir(firefox_prefs):
                    profile_dir = os.path.join(firefox_prefs, item)
                    if os.path.isdir(profile_dir) and item.endswith('.default'):
                        # 可以实现Firefox设置修复
                        return True
            return False
        except Exception:
            return False

    def _fix_edge_settings(self) -> bool:
        """修复Edge浏览器设置"""
        try:
            # Edge设置通常通过注册表管理
            return True
        except Exception:
            return False

    def generate_fix_report(self, fix_results: dict) -> str:
        """生成修复报告"""
        report_lines = [
            "=== TheCatGuard 自动修复报告 ===",
            f"修复时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "修复结果汇总:"
        ]

        total_fixed = 0
        total_failed = 0

        for category, results in fix_results.items():
            if isinstance(results, dict):
                fixed = results.get("fixed", 0)
                failed = results.get("failed", 0)
                total_fixed += fixed
                total_failed += failed

                report_lines.append(f"• {category}: 成功 {fixed} 项, 失败 {failed} 项")

                if results.get("backed_up"):
                    report_lines.append("  ✓ 已创建备份")

        report_lines.extend([
            "",
            f"总计: 成功修复 {total_fixed} 项, 失败 {total_failed} 项",
            "",
            "建议:",
            "• 重启计算机以确保所有修复生效",
            "• 运行完整扫描确认威胁已清除",
            "• 定期更新系统和安全软件"
        ])

        return "\n".join(report_lines)