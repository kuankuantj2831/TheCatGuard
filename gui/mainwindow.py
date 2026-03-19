import logging
import os

from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout,
    QSystemTrayIcon, QMenu, QMessageBox, QApplication
)
from PyQt6.QtGui import QIcon, QAction

from core.monitor import MonitorManager
from core.utils import get_logger, is_admin
from gui.enhanced_dashboard import EnhancedDashboard
from gui.tools import ToolsWidget
from gui.settings import SettingsWidget
from gui.security import SecurityWidget
from gui.advanced_features import AdvancedFeaturesPanel
from gui.utils import QtLogHandler

# Resolve asset paths relative to the application root
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("猫卫士 (The Cat Guard)")
        self.resize(960, 640)
        self.setMinimumSize(800, 500)
        self._tray_tip_shown = False
        
        # Initialize Core
        self.monitor_manager = MonitorManager()
        self.logger = get_logger()
        
        # Setup Logging to GUI
        self.log_handler = QtLogHandler()
        self.log_handler.setLevel(logging.INFO)
        logging.getLogger("TheCatGuard").addHandler(self.log_handler)
        
        self.setup_ui()
        self.setup_tray()
        
        # Connect signal
        self.log_handler.log_signal.connect(self.dashboard.add_log)
        
        if not is_admin():
            self.dashboard.add_log("⚠ 警告：未以管理员权限运行，修复功能可能无法正常使用。")
        else:
            self.dashboard.add_log("✔ 系统已以管理员权限运行。")

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        self.tabs = QTabWidget()
        
        self.dashboard = EnhancedDashboard(self.monitor_manager)
        self.tools = ToolsWidget()
        self.security = SecurityWidget()
        self.settings = SettingsWidget()
        self.advanced = AdvancedFeaturesPanel()
        
        self.about = self._build_about_widget()
        
        self.tabs.addTab(self.dashboard, "🛡️ 仪表盘")
        self.tabs.addTab(self.security, "🔍 安全扫描")
        self.tabs.addTab(self.tools, "🛠️ 系统修复")
        self.tabs.addTab(self.advanced, "🚀 高级功能")
        self.tabs.addTab(self.settings, "⚙️ 设置")
        self.tabs.addTab(self.about, "ℹ️ 关于")
        
        main_layout.addWidget(self.tabs)

    def _build_about_widget(self):
        from PyQt6.QtWidgets import QLabel
        from PyQt6.QtCore import Qt
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(12)

        icon_label = QLabel("🐱")
        icon_label.setStyleSheet("font-size: 64px; background: transparent;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("猫卫士 The Cat Guard")
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #4ecca3; background: transparent;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        ver = QLabel("版本 1.5.0")
        ver.setStyleSheet("font-size: 14px; color: #8892a8; background: transparent;")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)

        desc = QLabel("一款轻量级 Windows 主动防御与系统修复工具。\n实时监控启动项、进程、注册表、USB 和网络连接，\n支持 YARA 规则扫描、可疑文件隔离和白/黑名单配置。")
        desc.setStyleSheet("font-size: 13px; color: #b0b8c8; background: transparent;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)

        copy_label = QLabel("© 2026 The Cat Guard Project")
        copy_label.setStyleSheet("font-size: 11px; color: #555e70; margin-top: 20px; background: transparent;")
        copy_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addStretch()
        layout.addWidget(icon_label)
        layout.addWidget(title)
        layout.addWidget(ver)
        layout.addSpacing(10)
        layout.addWidget(desc)
        layout.addWidget(copy_label)
        layout.addStretch()
        return w

    def setup_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        # 优先使用 .ico（Windows 托盘兼容性更好）
        ico_path = os.path.join(_BASE_DIR, "assets", "icon.ico")
        png_path = os.path.join(_BASE_DIR, "assets", "icon.png")
        icon_path = ico_path if os.path.isfile(ico_path) else png_path
        app_icon = QIcon(icon_path)
        self.tray_icon.setIcon(app_icon)
        self.setWindowIcon(app_icon)
        
        tray_menu = QMenu()
        
        show_action = QAction("显示主窗口", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        quit_action = QAction("退出", self)
        quit_action.triggered.connect(self.quit_app)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        
        # Optional: Click to show
        self.tray_icon.activated.connect(self.on_tray_icon_activated)

    def on_tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.isVisible():
                self.hide()
            else:
                self.show()

    def closeEvent(self, event):
        if self.tray_icon.isVisible():
            if not self._tray_tip_shown:
                self.tray_icon.showMessage(
                    "猫卫士", "程序已最小化到系统托盘，继续在后台运行。",
                    QSystemTrayIcon.MessageIcon.Information, 3000
                )
                self._tray_tip_shown = True
            self.hide()
            event.ignore()
        else:
            self.monitor_manager.stop_all()
            event.accept()

    def quit_app(self):
        self.monitor_manager.stop_all()
        QApplication.instance().quit()
