"""
猫卫士安全扫描 & 隔离区页面
"""
import os
import threading
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFileDialog, QProgressBar, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QFrame, QTabWidget
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from core.yara_scanner import YaraScanner
from core.quarantine import QuarantineManager
from core import config


class _ScanWorker(QThread):
    """后台 YARA 扫描线程"""
    progress = pyqtSignal(str)          # 当前扫描的文件路径
    found = pyqtSignal(dict)            # 发现匹配
    finished_signal = pyqtSignal(int)   # 总匹配数

    def __init__(self, scanner: YaraScanner, target_dir: str):
        super().__init__()
        self._scanner = scanner
        self._target_dir = target_dir
        self._stop_event = threading.Event()

    def run(self):
        count = 0

        def cb(filepath, results):
            nonlocal count
            self.progress.emit(filepath)
            for r in results:
                count += 1
                self.found.emit(r)

        self._scanner.scan_directory(
            self._target_dir, recursive=True,
            callback=cb, stop_event=self._stop_event
        )
        self.finished_signal.emit(count)

    def stop(self):
        self._stop_event.set()


class ScanWidget(QWidget):
    """YARA 扫描页面"""
    def __init__(self):
        super().__init__()
        self._scanner = YaraScanner()
        self._quarantine = QuarantineManager()
        self._worker = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # 标题
        header = QLabel("🔍 安全扫描")
        header.setFont(QFont("Microsoft YaHei UI", 16, QFont.Weight.Bold))
        header.setStyleSheet("background: transparent;")
        layout.addWidget(header)

        if not self._scanner.available:
            warn = QLabel("⚠ yara-python 未安装，YARA 扫描功能不可用。\n请运行: pip install yara-python")
            warn.setStyleSheet("color: #f39c12; font-size: 13px; background: transparent;")
            warn.setWordWrap(True)
            layout.addWidget(warn)

        # 扫描控制栏
        ctrl = QHBoxLayout()
        self.dir_label = QLabel("未选择目录")
        self.dir_label.setStyleSheet("color: #8892a8; background: transparent;")
        self.dir_label.setMinimumWidth(200)

        choose_btn = QPushButton("📂 选择目录")
        choose_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        choose_btn.setFixedHeight(34)
        choose_btn.setStyleSheet(self._btn_style("#2a3a5c", "#3a4a6c"))
        choose_btn.clicked.connect(self._choose_dir)

        self.scan_btn = QPushButton("▶ 开始扫描")
        self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_btn.setFixedHeight(34)
        self.scan_btn.setStyleSheet(self._btn_style("#4ecca3", "#3dbb94", text_color="#1a1a2e"))
        self.scan_btn.clicked.connect(self._start_scan)

        self.stop_btn = QPushButton("⏹ 停止")
        self.stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn.setFixedHeight(34)
        self.stop_btn.setStyleSheet(self._btn_style("#e74c3c", "#c0392b"))
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)

        ctrl.addWidget(self.dir_label, 1)
        ctrl.addWidget(choose_btn)
        ctrl.addWidget(self.scan_btn)
        ctrl.addWidget(self.stop_btn)
        layout.addLayout(ctrl)

        # 进度
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # indeterminate
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setStyleSheet(
            "QProgressBar { background-color: #0f1a30; border: none; border-radius: 3px; }"
            "QProgressBar::chunk { background-color: #4ecca3; border-radius: 3px; }"
        )
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #6b7b9e; font-size: 11px; background: transparent;")
        layout.addWidget(self.status_label)

        # 结果表格
        self.result_table = QTableWidget(0, 4)
        self.result_table.setHorizontalHeaderLabels(["文件", "规则", "严重度", "操作"])
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.result_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.result_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.result_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.result_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.result_table.setStyleSheet(
            "QTableWidget { background-color: #0f1a30; color: #e0e0e0; border: 1px solid #1e2d4a; "
            "gridline-color: #1e2d4a; }"
            "QHeaderView::section { background-color: #16213e; color: #4ecca3; border: 1px solid #1e2d4a; "
            "padding: 4px; font-weight: bold; }"
            "QTableWidget::item:selected { background-color: #2a3a5c; }"
        )
        layout.addWidget(self.result_table, 1)

        self._target_dir = ""

    def _choose_dir(self):
        d = QFileDialog.getExistingDirectory(self, "选择扫描目录")
        if d:
            self._target_dir = d
            self.dir_label.setText(d)
            self.dir_label.setStyleSheet("color: #e0e0e0; background: transparent;")

    def _start_scan(self):
        if not self._scanner.available:
            QMessageBox.warning(self, "不可用", "yara-python 未安装，无法扫描。")
            return
        if not self._target_dir or not os.path.isdir(self._target_dir):
            QMessageBox.warning(self, "提示", "请先选择一个有效的扫描目录。")
            return

        if not self._scanner.load_rules():
            QMessageBox.warning(self, "错误", "YARA 规则加载失败，请检查规则文件。")
            return

        self.result_table.setRowCount(0)
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.status_label.setText("正在扫描...")

        self._worker = _ScanWorker(self._scanner, self._target_dir)
        self._worker.progress.connect(self._on_progress)
        self._worker.found.connect(self._on_found)
        self._worker.finished_signal.connect(self._on_finished)
        self._worker.start()

    def _stop_scan(self):
        if self._worker:
            self._worker.stop()

    def _on_progress(self, filepath):
        name = os.path.basename(filepath)
        self.status_label.setText(f"正在扫描: {name}")

    def _on_found(self, result):
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        self.result_table.setItem(row, 0, QTableWidgetItem(result["file"]))
        self.result_table.setItem(row, 1, QTableWidgetItem(f'{result["rule"]}'))

        severity = result.get("severity", "medium")
        sev_item = QTableWidgetItem(severity)
        color_map = {"critical": "#e74c3c", "high": "#e67e22", "medium": "#f1c40f", "low": "#4ecca3"}
        sev_item.setForeground(Qt.GlobalColor.white)
        self.result_table.setItem(row, 2, sev_item)

        # 隔离按钮
        q_btn = QPushButton("隔离")
        q_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        q_btn.setStyleSheet(
            "QPushButton { background-color: #e74c3c; color: white; border: none; "
            "border-radius: 4px; padding: 2px 8px; font-size: 11px; }"
            "QPushButton:hover { background-color: #c0392b; }"
        )
        filepath = result["file"]
        rule = result["rule"]
        q_btn.clicked.connect(lambda checked, f=filepath, r=rule: self._quarantine_file(f, r))
        self.result_table.setCellWidget(row, 3, q_btn)

    def _on_finished(self, count):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"扫描完成，发现 {count} 个匹配项。")

        # 自动隔离
        if config.get("quarantine_auto", False) and count > 0:
            self.status_label.setText(f"扫描完成，发现 {count} 个匹配项（已自动隔离）。")
            for row in range(self.result_table.rowCount()):
                fpath = self.result_table.item(row, 0).text()
                rule = self.result_table.item(row, 1).text()
                self._quarantine.quarantine_file(fpath, f"YARA: {rule}")

    def _quarantine_file(self, filepath, rule):
        if self._quarantine.quarantine_file(filepath, f"YARA: {rule}"):
            QMessageBox.information(self, "隔离", f"文件已隔离:\n{os.path.basename(filepath)}")
        else:
            QMessageBox.warning(self, "失败", f"隔离失败:\n{filepath}")

    @staticmethod
    def _btn_style(bg, hover, text_color="#e0e0e0"):
        return (
            f"QPushButton {{ background-color: {bg}; color: {text_color}; border: none; "
            f"border-radius: 6px; padding: 4px 14px; font-weight: bold; }}"
            f"QPushButton:hover {{ background-color: {hover}; }}"
        )


class QuarantineWidget(QWidget):
    """隔离区管理页面"""
    def __init__(self):
        super().__init__()
        self._qm = QuarantineManager()
        self._build_ui()
        self._refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        header = QLabel("🔒 隔离区")
        header.setFont(QFont("Microsoft YaHei UI", 16, QFont.Weight.Bold))
        header.setStyleSheet("background: transparent;")
        layout.addWidget(header)

        desc = QLabel("被隔离的可疑文件列表。可恢复到原始位置或永久删除。")
        desc.setStyleSheet("color: #6b7b9e; background: transparent;")
        layout.addWidget(desc)

        # 表格
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["文件名", "原始路径", "原因", "时间", "恢复", "删除"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setStyleSheet(
            "QTableWidget { background-color: #0f1a30; color: #e0e0e0; border: 1px solid #1e2d4a; "
            "gridline-color: #1e2d4a; }"
            "QHeaderView::section { background-color: #16213e; color: #4ecca3; border: 1px solid #1e2d4a; "
            "padding: 4px; font-weight: bold; }"
            "QTableWidget::item:selected { background-color: #2a3a5c; }"
        )
        layout.addWidget(self.table, 1)

        # 底部按钮
        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("🔄 刷新")
        refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh_btn.setStyleSheet(
            "QPushButton { background-color: #2a3a5c; color: #b0b8c8; border: none; "
            "border-radius: 6px; padding: 6px 16px; font-weight: bold; }"
            "QPushButton:hover { background-color: #3a4a6c; }"
        )
        refresh_btn.clicked.connect(self._refresh)
        btn_row.addWidget(refresh_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

    def _refresh(self):
        self.table.setRowCount(0)
        for entry in self._qm.list_quarantined():
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(entry["original_name"]))
            self.table.setItem(row, 1, QTableWidgetItem(entry["original_path"]))
            self.table.setItem(row, 2, QTableWidgetItem(entry.get("reason", "")))
            self.table.setItem(row, 3, QTableWidgetItem(entry.get("timestamp", "")))

            qid = entry["id"]

            restore_btn = QPushButton("恢复")
            restore_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            restore_btn.setStyleSheet(
                "QPushButton { background-color: #4ecca3; color: #1a1a2e; border: none; "
                "border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: bold; }"
                "QPushButton:hover { background-color: #3dbb94; }"
            )
            restore_btn.clicked.connect(lambda checked, i=qid: self._restore(i))
            self.table.setCellWidget(row, 4, restore_btn)

            del_btn = QPushButton("删除")
            del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            del_btn.setStyleSheet(
                "QPushButton { background-color: #e74c3c; color: white; border: none; "
                "border-radius: 4px; padding: 2px 8px; font-size: 11px; }"
                "QPushButton:hover { background-color: #c0392b; }"
            )
            del_btn.clicked.connect(lambda checked, i=qid: self._delete(i))
            self.table.setCellWidget(row, 5, del_btn)

    def _restore(self, qid):
        reply = QMessageBox.question(
            self, "确认恢复",
            "确定要将此文件恢复到原始位置吗？\n请确保该文件是安全的。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            if self._qm.restore_file(qid):
                QMessageBox.information(self, "恢复", "文件已恢复。")
            else:
                QMessageBox.warning(self, "失败", "恢复失败。")
            self._refresh()

    def _delete(self, qid):
        reply = QMessageBox.question(
            self, "确认删除",
            "永久删除后无法恢复，确定吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            if self._qm.delete_permanently(qid):
                QMessageBox.information(self, "删除", "文件已永久删除。")
            else:
                QMessageBox.warning(self, "失败", "删除失败。")
            self._refresh()


class SecurityWidget(QWidget):
    """安全扫描 + 隔离区 合并页面（内嵌 Tab）"""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        tabs = QTabWidget()
        tabs.setStyleSheet(
            "QTabWidget::pane { border: none; }"
            "QTabBar::tab { background-color: #16213e; color: #8892a8; padding: 8px 16px; "
            "border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 2px; }"
            "QTabBar::tab:selected { background-color: #1a2744; color: #4ecca3; }"
            "QTabBar::tab:hover { color: #e0e0e0; }"
        )
        tabs.addTab(ScanWidget(), "🔍 扫描")
        tabs.addTab(QuarantineWidget(), "🔒 隔离区")
        layout.addWidget(tabs)
