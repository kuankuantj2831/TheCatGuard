from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QMessageBox, QGridLayout, QFrame
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from core.repair import SystemRepair
from core.utils import is_autostart_enabled, enable_autostart, disable_autostart


class _RepairWorker(QThread):
    """通用后台修复线程，避免阻塞 GUI"""
    finished = pyqtSignal(object)  # result

    def __init__(self, func, *args):
        super().__init__()
        self._func = func
        self._args = args

    def run(self):
        result = self._func(*self._args)
        self.finished.emit(result)


class ToolCard(QFrame):
    """工具卡片按钮"""
    def __init__(self, icon, title, desc, callback):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background-color: #16213e;
                border: 1px solid #1e2d4a;
                border-radius: 10px;
            }
            QFrame:hover {
                border-color: #4ecca3;
                background-color: #1a2744;
            }
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.callback = callback

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 15, 18, 15)
        layout.setSpacing(6)

        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI", 22))
        icon_label.setStyleSheet("background: transparent; border: none;")

        title_label = QLabel(title)
        title_label.setFont(QFont("Microsoft YaHei UI", 12, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #e0e0e0; background: transparent; border: none;")

        desc_label = QLabel(desc)
        desc_label.setFont(QFont("Microsoft YaHei UI", 9))
        desc_label.setStyleSheet("color: #6b7b9e; background: transparent; border: none;")
        desc_label.setWordWrap(True)

        layout.addWidget(icon_label)
        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        layout.addStretch()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.callback()


class ToolsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # 标题
        header = QLabel("🛠️ 系统修复工具")
        header.setFont(QFont("Microsoft YaHei UI", 16, QFont.Weight.Bold))
        header.setStyleSheet("background: transparent;")
        layout.addWidget(header)

        desc = QLabel("点击卡片修复被恶意软件篡改的系统功能，或执行系统维护操作。")
        desc.setStyleSheet("color: #6b7b9e; margin-bottom: 5px; background: transparent;")
        layout.addWidget(desc)

        # 工具卡片网格
        self._grid = grid = QGridLayout()
        grid.setSpacing(12)

        cards = [
            ("📊", "修复任务管理器", "解除任务管理器禁用限制", self.fix_taskmgr),
            ("📝", "修复注册表编辑器", "解除注册表编辑器禁用限制", self.fix_reg),
            ("⌨️", "修复命令提示符", "解除 CMD 禁用限制", self.fix_cmd),
            ("📂", "修复文件关联", "修复 .exe/.lnk 文件关联", self.fix_file_assoc),
            ("🌐", "网络修复", "刷新 DNS 并重置 Winsock", self.fix_network),
            ("🧹", "清理系统垃圾", "清理临时文件、缓存和回收站", self.clean_junk),
        ]

        for i, (icon, title, description, func) in enumerate(cards):
            card = ToolCard(icon, title, description, func)
            grid.addWidget(card, i // 3, i % 3)

        layout.addLayout(grid)

        # 开机自启卡片
        self.autostart_frame = QFrame()
        self.autostart_frame.setCursor(Qt.CursorShape.PointingHandCursor)
        autostart_layout = QHBoxLayout(self.autostart_frame)
        autostart_layout.setContentsMargins(18, 12, 18, 12)

        self.autostart_icon = QLabel()
        self.autostart_icon.setFont(QFont("Segoe UI", 16))
        self.autostart_icon.setStyleSheet("background: transparent; border: none;")
        self.autostart_text = QLabel()
        self.autostart_text.setFont(QFont("Microsoft YaHei UI", 12, QFont.Weight.Bold))
        self.autostart_text.setStyleSheet("background: transparent; border: none;")
        self.autostart_desc = QLabel()
        self.autostart_desc.setFont(QFont("Microsoft YaHei UI", 9))
        self.autostart_desc.setStyleSheet("color: #6b7b9e; background: transparent; border: none;")

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        text_col.addWidget(self.autostart_text)
        text_col.addWidget(self.autostart_desc)

        autostart_layout.addWidget(self.autostart_icon)
        autostart_layout.addSpacing(10)
        autostart_layout.addLayout(text_col)
        autostart_layout.addStretch()

        self.autostart_frame.mousePressEvent = lambda e: self.toggle_autostart()
        self._update_autostart_btn()

        layout.addWidget(self.autostart_frame)
        layout.addStretch()

    def fix_taskmgr(self):
        SystemRepair.fix_task_manager()
        QMessageBox.information(self, "修复结果", "已尝试修复任务管理器。\n请查看日志了解详情。")

    def fix_reg(self):
        SystemRepair.fix_registry_tools()
        QMessageBox.information(self, "修复结果", "已尝试修复注册表编辑器。\n请查看日志了解详情。")

    def fix_cmd(self):
        SystemRepair.fix_cmd()
        QMessageBox.information(self, "修复结果", "已尝试修复命令提示符。\n请查看日志了解详情。")

    def fix_file_assoc(self):
        SystemRepair.fix_file_associations()
        QMessageBox.information(self, "修复结果", "已尝试修复文件关联。\n请查看日志了解详情。")

    def fix_network(self):
        self._set_cards_enabled(False)
        self._net_worker = _RepairWorker(SystemRepair.fix_network)
        self._net_worker.finished.connect(self._on_network_finished)
        self._net_worker.start()

    def _on_network_finished(self, _result):
        self._set_cards_enabled(True)
        QMessageBox.information(self, "修复结果", "网络修复已执行（DNS/Winsock）。\n请查看日志了解详情。")

    def clean_junk(self):
        reply = QMessageBox.question(
            self, "确认清理",
            "将清理以下内容：\n\n"
            "• Windows 临时文件\n"
            "• 系统预读取缓存\n"
            "• 浏览器缓存\n"
            "• 最近文件记录\n"
            "• 缩略图缓存\n"
            "• 回收站\n\n"
            "确定要继续吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._set_cards_enabled(False)
            self._clean_worker = _RepairWorker(SystemRepair.clean_junk)
            self._clean_worker.finished.connect(self._on_clean_finished)
            self._clean_worker.start()

    def _set_cards_enabled(self, enabled):
        for i in range(self._grid.count()):
            w = self._grid.itemAt(i).widget()
            if w and isinstance(w, ToolCard):
                w.setEnabled(enabled)

    def _on_clean_finished(self, result):
        self._set_cards_enabled(True)
        total_files, total_size = result if result else (0, 0)
        size_mb = total_size / (1024 * 1024)
        QMessageBox.information(
            self, "清理完成",
            f"共删除 {total_files} 个文件\n释放 {size_mb:.1f} MB 空间。\n\n请查看日志了解详情。"
        )

    def toggle_autostart(self):
        if is_autostart_enabled():
            if disable_autostart():
                QMessageBox.information(self, "开机自启", "已取消开机自动启动。")
            else:
                QMessageBox.warning(self, "失败", "取消开机自启失败，请检查权限。")
        else:
            if enable_autostart():
                QMessageBox.information(self, "开机自启", "已设置开机自动启动。")
            else:
                QMessageBox.warning(self, "失败", "设置开机自启失败，请检查权限。")
        self._update_autostart_btn()

    def _update_autostart_btn(self):
        enabled = is_autostart_enabled()
        if enabled:
            self.autostart_icon.setText("✅")
            self.autostart_text.setText("开机自启：已开启")
            self.autostart_text.setStyleSheet("color: #4ecca3; background: transparent; border: none;")
            self.autostart_desc.setText("点击关闭开机自动启动")
            self.autostart_frame.setStyleSheet("""
                QFrame {
                    background-color: #162e2e; border: 1px solid #4ecca3;
                    border-radius: 10px;
                }
                QFrame:hover { background-color: #1a3838; }
            """)
        else:
            self.autostart_icon.setText("⚪")
            self.autostart_text.setText("开机自启：已关闭")
            self.autostart_text.setStyleSheet("color: #8892a8; background: transparent; border: none;")
            self.autostart_desc.setText("点击开启开机自动启动")
            self.autostart_frame.setStyleSheet("""
                QFrame {
                    background-color: #16213e; border: 1px solid #1e2d4a;
                    border-radius: 10px;
                }
                QFrame:hover { border-color: #4ecca3; background-color: #1a2744; }
            """)
