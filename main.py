import sys
import os
import ctypes

# ── 启动前自动请求管理员权限 ──
def _ensure_admin():
    """如果不是管理员，通过 UAC 重新以管理员身份启动自身，然后退出当前进程"""
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return  # 已经是管理员
    except Exception:
        return

    # 以管理员身份重新启动
    python_exe = sys.executable
    script = os.path.abspath(sys.argv[0])
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", python_exe, f'"{script}" {params}'.strip(), None, 1
        )
        if ret > 32:  # ShellExecute 成功
            sys.exit(0)
    except Exception:
        pass
    # 如果 UAC 被拒绝或失败，继续以普通权限运行

_ensure_admin()

# ── 管理员 → SYSTEM 提权 ──
def _try_elevate_to_system():
    """如果已是管理员但不是 SYSTEM，尝试提权到 SYSTEM"""
    if "--system-elevated" in sys.argv:
        return  # 已经是 SYSTEM 提权后的进程，不再重复
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return  # 不是管理员，跳过
        # 检查是否已经是 SYSTEM
        if os.environ.get("USERNAME", "").upper() in ("SYSTEM", "СИСТЕМА"):
            return
        # 动态导入，避免循环依赖
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from core.utils import elevate_to_system
        if elevate_to_system():
            sys.exit(0)  # 新 SYSTEM 进程已启动，退出当前进程
    except Exception:
        pass  # 提权失败，继续以管理员权限运行

_try_elevate_to_system()

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import QFile, QTextStream, QSharedMemory
from PyQt6.QtNetwork import QLocalServer, QLocalSocket

# Ensure we can find the modules
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from gui.mainwindow import MainWindow

_APP_ID = "TheCatGuard_SingleInstance_Lock"


def is_already_running():
    """检测是否已有实例在运行"""
    socket = QLocalSocket()
    socket.connectToServer(_APP_ID)
    connected = socket.waitForConnected(200)
    if connected:
        socket.disconnectFromServer()
        return True
    socket.abort()
    # 清理可能残留的无主服务器
    QLocalServer.removeServer(_APP_ID)
    return False


def load_stylesheet(app):
    file = QFile(os.path.join(current_dir, "assets", "style.qss"))
    if file.open(QFile.OpenModeFlag.ReadOnly | QFile.OpenModeFlag.Text):
        stream = QTextStream(file)
        app.setStyleSheet(stream.readAll())

def main():
    app = QApplication(sys.argv)

    # 单实例检测
    if is_already_running():
        QMessageBox.warning(None, "猫卫士", "猫卫士已在运行中。")
        sys.exit(0)

    # 创建本地服务器，占住名称供后续实例检测
    server = QLocalServer()
    QLocalServer.removeServer(_APP_ID)  # 清理残留
    if not server.listen(_APP_ID):
        # 监听失败也不阻止启动
        print(f"Warning: QLocalServer listen failed: {server.errorString()}")

    # Load Styles
    load_stylesheet(app)
    
    try:
        window = MainWindow()
        window.show()
    except Exception as e:
        import traceback
        traceback.print_exc()
        QMessageBox.critical(None, "猫卫士 - 启动错误", f"启动失败:\n{e}")
        sys.exit(1)
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
