import winreg
import os
import glob
import shutil
import subprocess
import tempfile
from .utils import get_logger

logger = get_logger()

class SystemRepair:
    @staticmethod
    def fix_task_manager():
        """修复任务管理器 (Re-enable Task Manager)"""
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
        SystemRepair._delete_value(winreg.HKEY_CURRENT_USER, key_path, "DisableTaskMgr")
        SystemRepair._delete_value(winreg.HKEY_LOCAL_MACHINE, key_path, "DisableTaskMgr")

    @staticmethod
    def fix_registry_tools():
        """修复注册表编辑器 (Re-enable Registry Tools)"""
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
        SystemRepair._delete_value(winreg.HKEY_CURRENT_USER, key_path, "DisableRegistryTools")
        SystemRepair._delete_value(winreg.HKEY_LOCAL_MACHINE, key_path, "DisableRegistryTools")

    @staticmethod
    def fix_cmd():
        """修复 CMD (Re-enable Command Prompt)"""
        key_path = r"Software\Policies\Microsoft\Windows\System"
        SystemRepair._delete_value(winreg.HKEY_CURRENT_USER, key_path, "DisableCMD")
        SystemRepair._delete_value(winreg.HKEY_LOCAL_MACHINE, key_path, "DisableCMD")

    @staticmethod
    def _delete_value(hkey_root, key_path, value_name):
        try:
            key = winreg.OpenKey(hkey_root, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)
            logger.info(f"Successfully fixed {value_name} in {key_path}")
        except FileNotFoundError:
            # Value doesn't exist, which is good
            pass 
        except PermissionError:
            logger.error(f"Permission denied fixing {value_name}. Run as Admin.")
        except Exception as e:
            logger.error(f"Error fixing {value_name}: {e}")

    @staticmethod
    def fix_file_associations():
        """修复文件关联 (Reset .exe and .lnk associations)"""
        repairs_done = 0

        # 1. Fix exefile\shell\open\command → "%1" %*
        try:
            key_path = r"exefile\shell\open\command"
            key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key_path, 0,
                                winreg.KEY_READ | winreg.KEY_SET_VALUE)
            current, _ = winreg.QueryValueEx(key, "")
            expected = '"%1" %*'
            if current != expected:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, expected)
                logger.info(f"Fixed exefile open command: {current!r} -> {expected!r}")
                repairs_done += 1
            else:
                logger.info("exefile open command is correct.")
            winreg.CloseKey(key)
        except PermissionError:
            logger.error("Permission denied fixing exefile association. Run as Admin.")
        except FileNotFoundError:
            logger.info("exefile open command key not found (OK).")
        except Exception as e:
            logger.error(f"Error fixing exefile association: {e}")

        # 2. Fix .lnk association → lnkfile
        try:
            key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r".lnk", 0,
                                winreg.KEY_READ | winreg.KEY_SET_VALUE)
            current, _ = winreg.QueryValueEx(key, "")
            if current != "lnkfile":
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "lnkfile")
                logger.info(f"Fixed .lnk association: {current!r} -> 'lnkfile'")
                repairs_done += 1
            else:
                logger.info(".lnk association is correct.")
            winreg.CloseKey(key)
        except PermissionError:
            logger.error("Permission denied fixing .lnk association. Run as Admin.")
        except FileNotFoundError:
            logger.info(".lnk key not found (OK).")
        except Exception as e:
            logger.error(f"Error fixing .lnk association: {e}")

        if repairs_done:
            logger.info(f"File association repair complete. {repairs_done} item(s) fixed.")
        else:
            logger.info("File associations look healthy. No changes needed.")

    @staticmethod
    def fix_network():
        """网络修复 (Flush DNS, Reset Winsock)"""
        try:
            logger.info("Flushing DNS...")
            result = subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                logger.info(f"DNS flushed: {result.stdout.strip()}")
            else:
                logger.warning(f"DNS flush returned code {result.returncode}: {result.stderr.strip()}")
        except Exception as e:
            logger.error(f"Error flushing DNS: {e}")

        try:
            logger.info("Resetting Winsock...")
            result = subprocess.run(
                ["netsh", "winsock", "reset"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                logger.info(f"Winsock reset: {result.stdout.strip()}")
            else:
                logger.warning(f"Winsock reset returned code {result.returncode}: {result.stderr.strip()}")
        except Exception as e:
            logger.error(f"Error resetting Winsock: {e}")

        logger.info("Network repair commands completed.")

    @staticmethod
    def clean_junk():
        """清理系统垃圾文件"""
        total_size = 0
        total_files = 0

        junk_dirs = [
            # Windows 临时文件
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%WINDIR%\Temp"),
            # Windows 预读取缓存
            os.path.expandvars(r"%WINDIR%\Prefetch"),
            # Windows 更新缓存
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\INetCache"),
            # 最近文件记录
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent"),
            # Windows 缩略图缓存
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer"),
        ]

        # 缩略图缓存只删匹配的文件
        explorer_dir = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Explorer")
        thumb_patterns = ["thumbcache_*.db", "iconcache_*.db"]

        for junk_dir in junk_dirs:
            if not os.path.isdir(junk_dir):
                continue

            if junk_dir == explorer_dir:
                # 只删缩略图/图标缓存文件
                for pattern in thumb_patterns:
                    for fpath in glob.glob(os.path.join(explorer_dir, pattern)):
                        size, ok = SystemRepair._safe_delete_file(fpath)
                        if ok:
                            total_size += size
                            total_files += 1
                continue

            count, size = SystemRepair._clean_directory(junk_dir)
            total_files += count
            total_size += size

        # 清空回收站
        try:
            import ctypes
            SHERB_NOCONFIRMATION = 0x00000001
            SHERB_NOPROGRESSUI = 0x00000002
            SHERB_NOSOUND = 0x00000004
            flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
            ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, flags)
            logger.info("回收站已清空。")
        except Exception as e:
            logger.warning(f"清空回收站失败：{e}")

        size_mb = total_size / (1024 * 1024)
        logger.info(f"垃圾清理完成：共删除 {total_files} 个文件，释放 {size_mb:.1f} MB 空间。")
        return total_files, total_size

    @staticmethod
    def _clean_directory(dir_path):
        """清理目录中的文件，返回 (删除文件数, 释放字节数)"""
        count = 0
        size = 0
        for root, dirs, files in os.walk(dir_path, topdown=False):
            for name in files:
                fpath = os.path.join(root, name)
                s, ok = SystemRepair._safe_delete_file(fpath)
                if ok:
                    count += 1
                    size += s
            for name in dirs:
                dpath = os.path.join(root, name)
                try:
                    os.rmdir(dpath)  # 只删空目录
                except Exception:
                    pass
        return count, size

    @staticmethod
    def _safe_delete_file(fpath):
        """安全删除单个文件，返回 (文件大小, 是否成功)"""
        try:
            fsize = os.path.getsize(fpath)
            os.remove(fpath)
            return fsize, True
        except (PermissionError, OSError):
            return 0, False
