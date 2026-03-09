import logging
import ctypes
import os
import sys
import winreg

_AUTOSTART_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
_AUTOSTART_VALUE_NAME = "TheCatGuard"

def is_admin():
    """检查当前是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def _get_log_dir():
    """返回日志目录路径，确保目录存在"""
    log_dir = os.path.join(os.path.expandvars("%LOCALAPPDATA%"), "TheCatGuard", "logs")
    os.makedirs(log_dir, exist_ok=True)
    return log_dir


def get_logger(name="TheCatGuard"):
    """配置并返回日志记录器"""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # 控制台输出
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        # 文件日志输出
        try:
            from logging.handlers import RotatingFileHandler
            log_file = os.path.join(_get_log_dir(), f"{name}.log")
            fh = RotatingFileHandler(
                log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
            fh.setLevel(logging.INFO)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception:
            # 如果文件日志创建失败，仅使用控制台
            pass

    return logger

def restart_as_admin():
    """尝试以管理员权限重启自身"""
    if is_admin():
        return
    
    # 获取当前 Python解释器路径和脚本路径
    python_exe = sys.executable
    script_path = sys.argv[0]
    params = " ".join(sys.argv[1:])
    
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", python_exe, f'"{script_path}" {params}', None, 1
        )
        sys.exit(0)
    except Exception as e:
        print(f"Failed to restart as admin: {e}")


def get_exe_path():
    """获取当前可执行文件路径（支持 PyInstaller 打包和开发模式）"""
    if getattr(sys, 'frozen', False):
        # PyInstaller 打包后
        return sys.executable
    else:
        # 开发模式：用 pythonw.exe 运行 main.py
        python_exe = sys.executable
        script = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'main.py'))
        return f'"{python_exe}" "{script}"'


def is_autostart_enabled():
    """检查是否已设置开机自启"""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _AUTOSTART_KEY_PATH, 0, winreg.KEY_READ)
        winreg.QueryValueEx(key, _AUTOSTART_VALUE_NAME)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def enable_autostart():
    """设置开机自启"""
    try:
        exe_path = get_exe_path()
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _AUTOSTART_KEY_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, _AUTOSTART_VALUE_NAME, 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def disable_autostart():
    """取消开机自启"""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _AUTOSTART_KEY_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, _AUTOSTART_VALUE_NAME)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return True  # 本来就没有，等于已取消
    except Exception:
        return False
