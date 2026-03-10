"""
猫卫士设置页面 — 配置白名单/黑名单、监控参数、YARA、隔离区
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QListWidget, QGroupBox, QFormLayout,
    QSpinBox, QCheckBox, QMessageBox, QFrame, QScrollArea,
    QFileDialog
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
from core import config


class _ListEditor(QFrame):
    """可增删的列表编辑器"""
    def __init__(self, title, placeholder="输入后点击添加"):
        super().__init__()
        self.setStyleSheet("QFrame { background-color: #16213e; border-radius: 8px; border: 1px solid #1e2d4a; }")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        lbl = QLabel(title)
        lbl.setFont(QFont("Microsoft YaHei UI", 10, QFont.Weight.Bold))
        lbl.setStyleSheet("color: #e0e0e0; background: transparent; border: none;")
        layout.addWidget(lbl)

        row = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText(placeholder)
        self.input.setStyleSheet(
            "background-color: #0f1a30; color: #e0e0e0; border: 1px solid #2a3a5c; "
            "border-radius: 5px; padding: 4px 8px;"
        )
        add_btn = QPushButton("添加")
        add_btn.setFixedWidth(60)
        add_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        add_btn.setStyleSheet(
            "QPushButton { background-color: #4ecca3; color: #1a1a2e; border-radius: 5px; "
            "font-weight: bold; border: none; padding: 4px; }"
            "QPushButton:hover { background-color: #3dbb94; }"
        )
        add_btn.clicked.connect(self._add_item)
        self.input.returnPressed.connect(self._add_item)
        row.addWidget(self.input)
        row.addWidget(add_btn)
        layout.addLayout(row)

        self.list_widget = QListWidget()
        self.list_widget.setMaximumHeight(120)
        self.list_widget.setStyleSheet(
            "QListWidget { background-color: #0f1a30; color: #b0b8c8; border: 1px solid #2a3a5c; "
            "border-radius: 5px; }"
            "QListWidget::item:selected { background-color: #2a3a5c; }"
        )
        layout.addWidget(self.list_widget)

        del_btn = QPushButton("删除选中")
        del_btn.setFixedWidth(80)
        del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        del_btn.setStyleSheet(
            "QPushButton { background-color: #e74c3c; color: white; border-radius: 5px; "
            "font-size: 11px; border: none; padding: 3px; }"
            "QPushButton:hover { background-color: #c0392b; }"
        )
        del_btn.clicked.connect(self._del_item)
        layout.addWidget(del_btn, alignment=Qt.AlignmentFlag.AlignRight)

    def _add_item(self):
        text = self.input.text().strip()
        if text:
            self.list_widget.addItem(text)
            self.input.clear()

    def _del_item(self):
        for item in self.list_widget.selectedItems():
            self.list_widget.takeItem(self.list_widget.row(item))

    def get_items(self) -> list:
        return [self.list_widget.item(i).text() for i in range(self.list_widget.count())]

    def set_items(self, items: list):
        self.list_widget.clear()
        for item in items:
            self.list_widget.addItem(str(item))


class SettingsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()
        self._load_from_config()

    def _build_ui(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # 标题
        header = QLabel("⚙️ 设置")
        header.setFont(QFont("Microsoft YaHei UI", 16, QFont.Weight.Bold))
        header.setStyleSheet("background: transparent;")
        layout.addWidget(header)

        # ── 监控参数 ──
        monitor_group = QGroupBox("监控参数")
        monitor_group.setStyleSheet(self._group_style())
        mg = QFormLayout(monitor_group)
        mg.setSpacing(8)

        self.spin_process = QSpinBox()
        self.spin_process.setRange(1, 30)
        self.spin_process.setSuffix(" 秒")
        self.spin_process.setStyleSheet(self._spin_style())

        self.spin_registry = QSpinBox()
        self.spin_registry.setRange(1, 30)
        self.spin_registry.setSuffix(" 秒")
        self.spin_registry.setStyleSheet(self._spin_style())

        self.spin_network = QSpinBox()
        self.spin_network.setRange(1, 30)
        self.spin_network.setSuffix(" 秒")
        self.spin_network.setStyleSheet(self._spin_style())

        mg.addRow(self._form_label("进程轮询间隔:"), self.spin_process)
        mg.addRow(self._form_label("注册表轮询间隔:"), self.spin_registry)
        mg.addRow(self._form_label("网络轮询间隔:"), self.spin_network)
        layout.addWidget(monitor_group)

        # ── 安全端口 ──
        self.safe_ports_editor = _ListEditor("安全端口列表", "输入端口号，如 8080")
        layout.addWidget(self.safe_ports_editor)

        # ── 白名单 ──
        self.wl_process = _ListEditor("进程白名单", "进程名，如 chrome.exe")
        self.wl_path = _ListEditor("路径白名单", "路径前缀，如 C:\\Program Files")
        self.wl_ip = _ListEditor("IP 白名单", "IP 地址，如 192.168.1.1")
        layout.addWidget(self.wl_process)
        layout.addWidget(self.wl_path)
        layout.addWidget(self.wl_ip)

        # ── 黑名单 ──
        self.bl_process = _ListEditor("进程黑名单", "进程名")
        self.bl_hash = _ListEditor("SHA256 黑名单", "文件 SHA256 哈希")
        layout.addWidget(self.bl_process)
        layout.addWidget(self.bl_hash)

        # ── YARA ──
        yara_group = QGroupBox("YARA 扫描")
        yara_group.setStyleSheet(self._group_style())
        yg = QVBoxLayout(yara_group)

        self.chk_yara = QCheckBox("启用 YARA 规则扫描")
        self.chk_yara.setStyleSheet("color: #e0e0e0; background: transparent;")
        yg.addWidget(self.chk_yara)

        rules_row = QHBoxLayout()
        self.yara_dir_input = QLineEdit()
        self.yara_dir_input.setPlaceholderText("自定义规则目录（留空使用默认）")
        self.yara_dir_input.setStyleSheet(
            "background-color: #0f1a30; color: #e0e0e0; border: 1px solid #2a3a5c; "
            "border-radius: 5px; padding: 4px 8px;"
        )
        browse_btn = QPushButton("浏览")
        browse_btn.setFixedWidth(60)
        browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        browse_btn.setStyleSheet(
            "QPushButton { background-color: #2a3a5c; color: #b0b8c8; border-radius: 5px; "
            "border: none; padding: 4px; }"
            "QPushButton:hover { background-color: #3a4a6c; }"
        )
        browse_btn.clicked.connect(self._browse_yara_dir)
        rules_row.addWidget(self.yara_dir_input)
        rules_row.addWidget(browse_btn)
        yg.addLayout(rules_row)
        layout.addWidget(yara_group)

        # ── 隔离区 ──
        q_group = QGroupBox("隔离区")
        q_group.setStyleSheet(self._group_style())
        qg = QVBoxLayout(q_group)

        self.chk_auto_quarantine = QCheckBox("自动隔离 YARA 检出的可疑文件")
        self.chk_auto_quarantine.setStyleSheet("color: #e0e0e0; background: transparent;")
        qg.addWidget(self.chk_auto_quarantine)
        layout.addWidget(q_group)

        # ── 保存按钮 ──
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        save_btn = QPushButton("💾 保存设置")
        save_btn.setFixedSize(140, 40)
        save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save_btn.setStyleSheet(
            "QPushButton { background-color: #4ecca3; color: #1a1a2e; border-radius: 10px; "
            "font-size: 14px; font-weight: bold; border: none; }"
            "QPushButton:hover { background-color: #3dbb94; }"
            "QPushButton:pressed { background-color: #2eaa83; }"
        )
        save_btn.clicked.connect(self._save)
        btn_row.addWidget(save_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        layout.addStretch()
        scroll.setWidget(container)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    def _load_from_config(self):
        cfg = config.load_config()
        self.spin_process.setValue(cfg.get("process_poll_interval", 1))
        self.spin_registry.setValue(cfg.get("registry_poll_interval", 2))
        self.spin_network.setValue(cfg.get("network_poll_interval", 3))
        self.safe_ports_editor.set_items([str(p) for p in cfg.get("safe_ports", [])])
        self.wl_process.set_items(cfg.get("whitelist_processes", []))
        self.wl_path.set_items(cfg.get("whitelist_paths", []))
        self.wl_ip.set_items(cfg.get("whitelist_network_ips", []))
        self.bl_process.set_items(cfg.get("blacklist_processes", []))
        self.bl_hash.set_items(cfg.get("blacklist_hashes", []))
        self.chk_yara.setChecked(cfg.get("yara_enabled", True))
        self.yara_dir_input.setText(cfg.get("yara_rules_dir", ""))
        self.chk_auto_quarantine.setChecked(cfg.get("quarantine_auto", False))

    def _save(self):
        cfg = config.load_config()
        cfg["process_poll_interval"] = self.spin_process.value()
        cfg["registry_poll_interval"] = self.spin_registry.value()
        cfg["network_poll_interval"] = self.spin_network.value()

        # 安全端口：过滤非数字
        ports = []
        for p in self.safe_ports_editor.get_items():
            try:
                ports.append(int(p))
            except ValueError:
                pass
        cfg["safe_ports"] = ports

        cfg["whitelist_processes"] = self.wl_process.get_items()
        cfg["whitelist_paths"] = self.wl_path.get_items()
        cfg["whitelist_network_ips"] = self.wl_ip.get_items()
        cfg["blacklist_processes"] = self.bl_process.get_items()
        cfg["blacklist_hashes"] = self.bl_hash.get_items()
        cfg["yara_enabled"] = self.chk_yara.isChecked()
        cfg["yara_rules_dir"] = self.yara_dir_input.text().strip()
        cfg["quarantine_auto"] = self.chk_auto_quarantine.isChecked()

        config.save_config(cfg)
        QMessageBox.information(self, "设置", "设置已保存。\n部分设置将在下次启动防护时生效。")

    def _browse_yara_dir(self):
        d = QFileDialog.getExistingDirectory(self, "选择 YARA 规则目录")
        if d:
            self.yara_dir_input.setText(d)

    @staticmethod
    def _group_style():
        return (
            "QGroupBox { background-color: #16213e; border: 1px solid #1e2d4a; "
            "border-radius: 8px; margin-top: 10px; padding-top: 18px; color: #4ecca3; "
            "font-weight: bold; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }"
        )

    @staticmethod
    def _spin_style():
        return (
            "QSpinBox { background-color: #0f1a30; color: #e0e0e0; border: 1px solid #2a3a5c; "
            "border-radius: 5px; padding: 3px 6px; }"
        )

    @staticmethod
    def _form_label(text):
        lbl = QLabel(text)
        lbl.setStyleSheet("color: #b0b8c8; background: transparent;")
        return lbl
