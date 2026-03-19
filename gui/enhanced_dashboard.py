import os
import sys
import time
import threading
from collections import defaultdict
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QProgressBar, QTextEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QColor

try:
    import pyqtgraph as pg
    PYQTGRAPH_AVAILABLE = True
except ImportError:
    PYQTGRAPH_AVAILABLE = False

class RealTimeChart(QWidget):
    """实时数据图表组件"""
    def __init__(self, title, color="#4ecca3"):
        super().__init__()
        self.title = title
        self.color = color
        self.data_points = []
        self.max_points = 60  # 60秒数据
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        title_label = QLabel(self.title)
        title_label.setFont(QFont("Microsoft YaHei UI", 10, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #e0e0e0; background: transparent;")
        layout.addWidget(title_label)

        if PYQTGRAPH_AVAILABLE:
            # 创建图表
            self.plot_widget = pg.PlotWidget()
            self.plot_widget.setBackground('#16213e')
            self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
            self.plot_widget.setLabel('left', '值')
            self.plot_widget.setLabel('bottom', '时间 (秒)')

            # 创建数据线
            self.curve = self.plot_widget.plot(pen=pg.mkPen(color=self.color, width=2))
            layout.addWidget(self.plot_widget)
        else:
            # 降级到简单进度条
            self.progress_bar = QProgressBar()
            self.progress_bar.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #2a3a5c;
                    border-radius: 5px;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #4ecca3;
                }
            """)
            layout.addWidget(self.progress_bar)

    def update_data(self, value):
        """更新数据点"""
        self.data_points.append((time.time(), value))
        # 保持最大点数
        if len(self.data_points) > self.max_points:
            self.data_points.pop(0)

        if PYQTGRAPH_AVAILABLE:
            # 更新图表
            times = [t - self.data_points[0][0] for t, v in self.data_points]
            values = [v for t, v in self.data_points]
            self.curve.setData(times, values)
        else:
            # 更新进度条
            self.progress_bar.setValue(int(value))

class ThreatStatisticsPanel(QWidget):
    """威胁统计面板"""
    def __init__(self):
        super().__init__()
        self.threat_counts = defaultdict(int)
        self.setup_ui()
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_stats)
        self.update_timer.start(5000)  # 每5秒更新

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel("📊 威胁统计 (24小时)")
        title.setFont(QFont("Microsoft YaHei UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color: #e0e0e0; background: transparent;")
        layout.addWidget(title)

        # 统计卡片网格
        stats_layout = QVBoxLayout()

        self.stats_cards = {}
        threat_types = [
            ("病毒文件", "#e74c3c"),
            ("可疑进程", "#f39c12"),
            ("网络威胁", "#9b59b6"),
            ("系统异常", "#e67e22")
        ]

        for threat_name, color in threat_types:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: #16213e;
                    border-radius: 8px;
                    border: 1px solid #1e2d4a;
                }}
            """)
            card_layout = QHBoxLayout(card)

            icon_label = QLabel("⚠️")
            icon_label.setFont(QFont("Segoe UI", 16))
            card_layout.addWidget(icon_label)

            info_layout = QVBoxLayout()
            name_label = QLabel(threat_name)
            name_label.setFont(QFont("Microsoft YaHei UI", 9))
            name_label.setStyleSheet("color: #8892a8; background: transparent;")
            count_label = QLabel("0")
            count_label.setFont(QFont("Microsoft YaHei UI", 14, QFont.Weight.Bold))
            count_label.setStyleSheet(f"color: {color}; background: transparent;")

            info_layout.addWidget(name_label)
            info_layout.addWidget(count_label)
            card_layout.addLayout(info_layout)
            card_layout.addStretch()

            stats_layout.addWidget(card)
            self.stats_cards[threat_name] = count_label

        layout.addLayout(stats_layout)

    def update_stats(self):
        """更新统计数据"""
        # 这里应该从日志或数据库获取真实数据
        # 暂时使用模拟数据
        import random
        for threat_type, label in self.stats_cards.items():
            current = int(label.text())
            # 模拟小幅波动
            new_value = max(0, current + random.randint(-2, 3))
            label.setText(str(new_value))

class SystemResourceMonitor(QWidget):
    """系统资源监控面板"""
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_resources)
        self.update_timer.start(1000)  # 每秒更新

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel("💻 系统资源")
        title.setFont(QFont("Microsoft YaHei UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color: #e0e0e0; background: transparent;")
        layout.addWidget(title)

        # CPU使用率图表
        self.cpu_chart = RealTimeChart("CPU使用率 (%)", "#4ecca3")
        layout.addWidget(self.cpu_chart)

        # 内存使用率图表
        self.memory_chart = RealTimeChart("内存使用率 (%)", "#3498db")
        layout.addWidget(self.memory_chart)

        # 磁盘使用率图表
        self.disk_chart = RealTimeChart("磁盘使用率 (%)", "#e74c3c")
        layout.addWidget(self.disk_chart)

    def update_resources(self):
        """更新系统资源数据"""
        try:
            import psutil

            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=None)
            self.cpu_chart.update_data(cpu_percent)

            # 内存使用率
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            self.memory_chart.update_data(memory_percent)

            # 磁盘使用率 (C盘)
            disk = psutil.disk_usage('C:')
            disk_percent = disk.percent
            self.disk_chart.update_data(disk_percent)

        except ImportError:
            # 如果没有psutil，使用模拟数据
            import random
            self.cpu_chart.update_data(random.uniform(10, 80))
            self.memory_chart.update_data(random.uniform(20, 90))
            self.disk_chart.update_data(random.uniform(30, 70))

class EnhancedDashboard(QWidget):
    """增强版仪表盘"""
    def __init__(self, monitor_manager):
        super().__init__()
        self.monitor_manager = monitor_manager
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # 顶部标题
        header = QLabel("🎯 智能监控仪表盘")
        header.setFont(QFont("Microsoft YaHei UI", 18, QFont.Weight.Bold))
        header.setStyleSheet("color: #e0e0e0; background: transparent;")
        main_layout.addWidget(header)

        # 创建选项卡布局
        from PyQt6.QtWidgets import QTabWidget
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e2d4a;
                background-color: #0f1a30;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #16213e;
                color: #8892a8;
                padding: 8px 16px;
                margin-right: 2px;
                border-radius: 6px 6px 0 0;
            }
            QTabBar::tab:selected {
                background-color: #1e2d4a;
                color: #e0e0e0;
            }
        """)

        # 实时监控选项卡
        realtime_tab = QWidget()
        realtime_layout = QHBoxLayout(realtime_tab)

        # 左侧：威胁统计
        self.threat_stats = ThreatStatisticsPanel()
        realtime_layout.addWidget(self.threat_stats, 1)

        # 右侧：系统资源
        self.system_monitor = SystemResourceMonitor()
        realtime_layout.addWidget(self.system_monitor, 2)

        self.tab_widget.addTab(realtime_tab, "📈 实时监控")

        # 扫描进度选项卡
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)

        self.scan_progress = QProgressBar()
        self.scan_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #2a3a5c;
                border-radius: 5px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4ecca3, stop:1 #3dbb94);
            }
        """)
        scan_layout.addWidget(self.scan_progress)

        self.scan_log = QTextEdit()
        self.scan_log.setReadOnly(True)
        self.scan_log.setMaximumHeight(200)
        scan_layout.addWidget(self.scan_log)

        self.tab_widget.addTab(scan_tab, "🔍 扫描进度")

        # 威胁详情选项卡
        threat_tab = QWidget()
        threat_layout = QVBoxLayout(threat_tab)

        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(4)
        self.threat_table.setHorizontalHeaderLabels(["时间", "威胁类型", "文件/进程", "状态"])
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.threat_table.setStyleSheet("""
            QTableWidget {
                background-color: #16213e;
                color: #e0e0e0;
                border: 1px solid #1e2d4a;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #1e2d4a;
                color: #e0e0e0;
                border: none;
                padding: 8px;
            }
        """)
        threat_layout.addWidget(self.threat_table)

        # 操作按钮
        actions_layout = QHBoxLayout()
        isolate_btn = QPushButton("隔离选中")
        isolate_btn.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: #1a1a2e;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #e67e22; }
        """)
        actions_layout.addWidget(isolate_btn)

        delete_btn = QPushButton("删除选中")
        delete_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #c0392b; }
        """)
        actions_layout.addWidget(delete_btn)

        actions_layout.addStretch()
        threat_layout.addLayout(actions_layout)

        self.tab_widget.addTab(threat_tab, "⚠️ 威胁详情")

        # 日志选项卡
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        
        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setStyleSheet("""
            QTextEdit {
                background-color: #16213e;
                color: #e0e0e0;
                border: 1px solid #1e2d4a;
                border-radius: 8px;
                font-family: 'Courier New';
                font-size: 10px;
            }
        """)
        log_layout.addWidget(self.log_viewer)
        
        self.tab_widget.addTab(log_tab, "📋 日志")

        main_layout.addWidget(self.tab_widget)

    def update_scan_progress(self, value, text=""):
        """更新扫描进度"""
        self.scan_progress.setValue(value)
        if text:
            self.scan_progress.setFormat(f"{text} ({value}%)")

    def add_scan_log(self, message):
        """添加扫描日志"""
        timestamp = time.strftime("%H:%M:%S")
        self.scan_log.append(f"[{timestamp}] {message}")

    def add_threat(self, threat_type, target, status="检测到"):
        """添加威胁记录"""
        row_count = self.threat_table.rowCount()
        self.threat_table.insertRow(row_count)

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        self.threat_table.setItem(row_count, 0, QTableWidgetItem(timestamp))
        self.threat_table.setItem(row_count, 1, QTableWidgetItem(threat_type))
        self.threat_table.setItem(row_count, 2, QTableWidgetItem(target))
        self.threat_table.setItem(row_count, 3, QTableWidgetItem(status))

        # 设置颜色
        if status == "已隔离":
            color = QColor("#4ecca3")
        elif status == "已删除":
            color = QColor("#e74c3c")
        else:
            color = QColor("#f39c12")

        for col in range(4):
            item = self.threat_table.item(row_count, col)
            item.setForeground(color)

    def add_log(self, message):
        """添加日志消息"""
        from PyQt6.QtCore import pyqtSlot
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
        
        timestamp = time.strftime("%H:%M:%S")
        log_text = f'<span style="color:{color}">[{timestamp}] {message}</span>'
        
        self.log_viewer.append(log_text)
        sb = self.log_viewer.verticalScrollBar()
        sb.setValue(sb.maximum())