import sys
import os
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
