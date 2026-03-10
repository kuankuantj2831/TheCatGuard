from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QTextEdit, QPushButton, QFrame, QGridLayout
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QFont, QColor

class StatusCard(QFrame):
    """小型状态指示卡片"""
    def __init__(self, title, icon_char):
        super().__init__()
        self.setFixedHeight(70)
        self.setStyleSheet("background-color: #16213e; border-radius: 10px; border: 1px solid #1e2d4a;")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(15, 8, 15, 8)

        icon = QLabel(icon_char)
        icon.setFont(QFont("Segoe UI", 18))
        icon.setFixedWidth(35)
        icon.setStyleSheet("background: transparent; border: none;")

        info = QVBoxLayout()
        info.setSpacing(2)
        self.title_label = QLabel(title)
        self.title_label.setFont(QFont("Microsoft YaHei UI", 9))
        self.title_label.setStyleSheet("color: #8892a8; background: transparent; border: none;")
        self.value_label = QLabel("--")
        self.value_label.setFont(QFont("Microsoft YaHei UI", 11, QFont.Weight.Bold))
        self.value_label.setStyleSheet("color: #e0e0e0; background: transparent; border: none;")
        info.addWidget(self.title_label)
        info.addWidget(self.value_label)

        layout.addWidget(icon)
        layout.addLayout(info)
        layout.addStretch()

    def set_value(self, text, color="#e0e0e0"):
        self.value_label.setText(text)
        self.value_label.setStyleSheet(f"color: {color}; background: transparent; border: none;")


class Dashboard(QWidget):
    def __init__(self, monitor_manager):
        super().__init__()
        self.monitor_manager = monitor_manager
        self.is_monitoring = False
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # ── 顶部状态栏 ──
        self.status_frame = QFrame()
        self.status_frame.setStyleSheet(
            "background-color: #16213e; border-radius: 12px; border: 1px solid #1e2d4a;"
        )
        status_layout = QHBoxLayout(self.status_frame)
        status_layout.setContentsMargins(25, 18, 25, 18)

        # 盾牌图标 + 状态文字
        shield_icon = QLabel("🛡️")
        shield_icon.setFont(QFont("Segoe UI", 28))
        shield_icon.setStyleSheet("background: transparent; border: none;")

        status_text = QVBoxLayout()
        status_text.setSpacing(4)
        self.status_label = QLabel("防护状态：已关闭")
        self.status_label.setFont(QFont("Microsoft YaHei UI", 18, QFont.Weight.Bold))
        self.status_label.setStyleSheet("color: #e74c3c; background: transparent; border: none;")
        self.status_sub = QLabel("点击右侧按钮开启实时防护")
        self.status_sub.setFont(QFont("Microsoft YaHei UI", 10))
        self.status_sub.setStyleSheet("color: #8892a8; background: transparent; border: none;")
        status_text.addWidget(self.status_label)
        status_text.addWidget(self.status_sub)

        self.toggle_btn = QPushButton("开启防护")
        self.toggle_btn.setFixedSize(130, 45)
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: #4ecca3;
                color: #1a1a2e;
                border-radius: 10px;
                font-size: 15px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover { background-color: #3dbb94; }
            QPushButton:pressed { background-color: #2eaa83; }
        """)
        self.toggle_btn.clicked.connect(self.toggle_protection)

        status_layout.addWidget(shield_icon)
        status_layout.addSpacing(12)
        status_layout.addLayout(status_text)
        status_layout.addStretch()
        status_layout.addWidget(self.toggle_btn)

        # ── 监控模块状态卡片 ──
        cards_layout = QGridLayout()
        cards_layout.setSpacing(12)

        self.card_file = StatusCard("文件监控", "📁")
        self.card_process = StatusCard("进程监控", "⚙️")
        self.card_registry = StatusCard("注册表监控", "🔑")
        self.card_usb = StatusCard("USB 监控", "🔌")
        self.card_network = StatusCard("网络监控", "🌐")

        cards_layout.addWidget(self.card_file, 0, 0)
        cards_layout.addWidget(self.card_process, 0, 1)
        cards_layout.addWidget(self.card_registry, 0, 2)
        cards_layout.addWidget(self.card_usb, 0, 3)
        cards_layout.addWidget(self.card_network, 0, 4)

        self._set_cards_status(False)

        # ── 日志区域 ──
        log_header = QHBoxLayout()
        log_label = QLabel("📋 实时活动日志")
        log_label.setFont(QFont("Microsoft YaHei UI", 12, QFont.Weight.Bold))
        log_label.setStyleSheet("background: transparent;")

        self.clear_log_btn = QPushButton("清空")
        self.clear_log_btn.setFixedSize(60, 28)
        self.clear_log_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_log_btn.setStyleSheet("""
            QPushButton {
                background-color: #16213e; color: #8892a8; border: 1px solid #2a3a5c;
                border-radius: 6px; font-size: 11px;
            }
            QPushButton:hover { color: #e74c3c; border-color: #e74c3c; }
        """)
        self.clear_log_btn.clicked.connect(lambda: self.log_viewer.clear())

        log_header.addWidget(log_label)
        log_header.addStretch()
        log_header.addWidget(self.clear_log_btn)

        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)

        # ── 组装 ──
        layout.addWidget(self.status_frame)
        layout.addLayout(cards_layout)
        layout.addLayout(log_header)
        layout.addWidget(self.log_viewer, 1)  # stretch=1 让日志区域占满剩余空间

    def _set_cards_status(self, running):
        if running:
            for card in [self.card_file, self.card_process, self.card_registry, self.card_usb, self.card_network]:
                card.set_value("运行中", "#4ecca3")
        else:
            for card in [self.card_file, self.card_process, self.card_registry, self.card_usb, self.card_network]:
                card.set_value("未启动", "#8892a8")

    def toggle_protection(self):
        if self.is_monitoring:
            self.monitor_manager.stop_all()
            self.is_monitoring = False
            self.status_label.setText("防护状态：已关闭")
            self.status_label.setStyleSheet("color: #e74c3c; background: transparent; border: none;")
            self.status_sub.setText("点击右侧按钮开启实时防护")
            self.toggle_btn.setText("开启防护")
            self.toggle_btn.setStyleSheet("""
                QPushButton {
                    background-color: #4ecca3; color: #1a1a2e; border-radius: 10px;
                    font-size: 15px; font-weight: bold; border: none;
                }
                QPushButton:hover { background-color: #3dbb94; }
                QPushButton:pressed { background-color: #2eaa83; }
            """)
            self._set_cards_status(False)
            self.add_log("防护已停止。")
        else:
            try:
                self.monitor_manager.start_all()
                self.is_monitoring = True
                self.status_label.setText("防护状态：安全")
                self.status_label.setStyleSheet("color: #4ecca3; background: transparent; border: none;")
                self.status_sub.setText("所有监控模块运行中")
                self.toggle_btn.setText("关闭防护")
                self.toggle_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #e74c3c; color: white; border-radius: 10px;
                        font-size: 15px; font-weight: bold; border: none;
                    }
                    QPushButton:hover { background-color: #c0392b; }
                    QPushButton:pressed { background-color: #a93226; }
                """)
                self._set_cards_status(True)
                self.add_log("防护已开启，正在监控进程、启动项、注册表、USB设备和网络连接...")
            except Exception as e:
                self.add_log(f"启动防护失败：{e}")

    @pyqtSlot(str)
    def add_log(self, message):
        # 根据日志级别着色
        msg_lower = message.lower()
        if "security alert" in msg_lower or "error" in msg_lower:
            color = "#e74c3c"  # 红色
        elif "warning" in msg_lower or "警告" in message:
            color = "#f39c12"  # 橙色
        elif "started" in msg_lower or "已开启" in message or "✔" in message:
            color = "#4ecca3"  # 绿色
        else:
            color = "#58d68d"  # 默认日志绿
        self.log_viewer.append(f'<span style="color:{color}">{message}</span>')
        sb = self.log_viewer.verticalScrollBar()
        sb.setValue(sb.maximum())
