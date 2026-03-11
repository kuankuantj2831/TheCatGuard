import logging
import ctypes
import ctypes.wintypes
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
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", python_exe, f'"{script_path}" {params}'.strip(), None, 1
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


# ─── SYSTEM 提权 ───

def is_system():
    """检查当前是否以 SYSTEM 身份运行（通过 Windows API 获取令牌 SID）"""
    try:
        import ctypes
        from ctypes import wintypes
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        TOKEN_QUERY = 0x0008
        TokenUser = 1
        h_token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(h_token)
        ):
            return False
        try:
            # 获取 TOKEN_USER 所需缓冲区大小
            buf_size = wintypes.DWORD(0)
            advapi32.GetTokenInformation(h_token, TokenUser, None, 0, ctypes.byref(buf_size))
            buf = ctypes.create_string_buffer(buf_size.value)
            if not advapi32.GetTokenInformation(
                h_token, TokenUser, buf, buf_size, ctypes.byref(buf_size)
            ):
                return False
            # TOKEN_USER 结构体的前 sizeof(c_void_p) 字节是 SID 指针
            sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            # 转换 SID 为字符串
            sid_str = ctypes.c_wchar_p()
            if not advapi32.ConvertSidToStringSidW(
                ctypes.c_void_p(sid_ptr), ctypes.byref(sid_str)
            ):
                return False
            result = str(sid_str.value)
            kernel32.LocalFree(sid_str)
            # S-1-5-18 是 SYSTEM 的 Well-Known SID
            return result == "S-1-5-18"
        finally:
            kernel32.CloseHandle(h_token)
    except Exception:
        return False


def elevate_to_system():
    """
    管理员 → SYSTEM 提权。
    通过复制 winlogon.exe 的 SYSTEM 令牌，以该令牌重新启动自身。
    仅在管理员权限下有效。成功后当前进程退出，新 SYSTEM 进程启动。
    返回 True 表示已发起提权（当前进程即将退出），False 表示失败。
    """
    if not is_admin():
        return False
    if is_system():
        return False  # 已经是 SYSTEM

    try:
        import subprocess
        # 找到 winlogon.exe 的 PID
        import psutil
        winlogon_pid = None
        for proc in psutil.process_iter(['name', 'pid', 'exe']):
            if proc.info['name'] and proc.info['name'].lower() == 'winlogon.exe':
                # 验证路径必须在 System32，防止伪造进程
                try:
                    exe_path = proc.info.get('exe', '') or ''
                    if os.path.normcase(os.path.normpath(exe_path)).startswith(
                        os.path.normcase(r'C:\Windows\System32')
                    ):
                        winlogon_pid = proc.info['pid']
                        break
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

        if not winlogon_pid:
            return False

        # 使用 Windows API 复制令牌并创建新进程
        return _create_system_process(winlogon_pid)
    except Exception:
        return False


def _create_system_process(system_pid):
    """通过复制 SYSTEM 进程令牌创建新进程"""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32

    PROCESS_QUERY_INFORMATION = 0x0400
    TOKEN_DUPLICATE = 0x0002
    TOKEN_QUERY = 0x0008
    TOKEN_ASSIGN_PRIMARY = 0x0001
    TOKEN_ALL_ACCESS = 0x000F01FF
    SecurityImpersonation = 2
    TokenPrimary = 1
    CREATE_NEW_CONSOLE = 0x00000010
    CREATE_UNICODE_ENVIRONMENT = 0x00000400

    # 启用 SeDebugPrivilege
    _enable_privilege("SeDebugPrivilege")

    # 打开 SYSTEM 进程
    h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, system_pid)
    if not h_process:
        return False

    try:
        # 获取进程令牌
        h_token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(h_process, TOKEN_DUPLICATE, ctypes.byref(h_token)):
            return False

        try:
            # 复制令牌
            h_new_token = wintypes.HANDLE()
            if not advapi32.DuplicateTokenEx(
                h_token, TOKEN_ALL_ACCESS, None,
                SecurityImpersonation, TokenPrimary,
                ctypes.byref(h_new_token)
            ):
                return False

            try:
                # 构建命令行
                python_exe = sys.executable
                script = os.path.abspath(sys.argv[0])
                cmd_line = f'"{python_exe}" "{script}" --system-elevated'

                # STARTUPINFOW
                class STARTUPINFOW(ctypes.Structure):
                    _fields_ = [
                        ("cb", wintypes.DWORD),
                        ("lpReserved", wintypes.LPWSTR),
                        ("lpDesktop", wintypes.LPWSTR),
                        ("lpTitle", wintypes.LPWSTR),
                        ("dwX", wintypes.DWORD),
                        ("dwY", wintypes.DWORD),
                        ("dwXSize", wintypes.DWORD),
                        ("dwYSize", wintypes.DWORD),
                        ("dwXCountChars", wintypes.DWORD),
                        ("dwYCountChars", wintypes.DWORD),
                        ("dwFillAttribute", wintypes.DWORD),
                        ("dwFlags", wintypes.DWORD),
                        ("wShowWindow", wintypes.WORD),
                        ("cbReserved2", wintypes.WORD),
                        ("lpReserved2", ctypes.c_void_p),
                        ("hStdInput", wintypes.HANDLE),
                        ("hStdOutput", wintypes.HANDLE),
                        ("hStdError", wintypes.HANDLE),
                    ]

                class PROCESS_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("hProcess", wintypes.HANDLE),
                        ("hThread", wintypes.HANDLE),
                        ("dwProcessId", wintypes.DWORD),
                        ("dwThreadId", wintypes.DWORD),
                    ]

                si = STARTUPINFOW()
                si.cb = ctypes.sizeof(STARTUPINFOW)
                si.lpDesktop = "winsta0\\default"
                pi = PROCESS_INFORMATION()

                # 用 SYSTEM 令牌创建进程
                cmd_buf = ctypes.create_unicode_buffer(cmd_line)
                success = advapi32.CreateProcessAsUserW(
                    h_new_token,
                    None,
                    cmd_buf,
                    None, None,
                    False,
                    CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                    None,
                    None,
                    ctypes.byref(si),
                    ctypes.byref(pi),
                )

                if success:
                    kernel32.CloseHandle(pi.hProcess)
                    kernel32.CloseHandle(pi.hThread)
                    return True
                return False
            finally:
                kernel32.CloseHandle(h_new_token)
        finally:
            kernel32.CloseHandle(h_token)
    finally:
        kernel32.CloseHandle(h_process)


def _enable_privilege(privilege_name):
    """启用当前进程的指定特权"""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", wintypes.DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES * 1),
        ]

    h_token = wintypes.HANDLE()
    advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(h_token),
    )

    luid = LUID()
    advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid))

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), 0, None, None)
    kernel32.CloseHandle(h_token)
