"""
高级功能面板 - 集成行为分析、网络安全、隐私保护、性能监控
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QPushButton, QProgressBar, QTableWidget, 
    QTableWidgetItem, QTextEdit, QSpinBox, QCheckBox,
    QScrollArea, QGridLayout, QGroupBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QColor, QFont
from datetime import datetime
from core.utils import get_logger

logger = get_logger()

# 尝试导入各个模块，如果失败则提供模拟实现
try:
    from core import get_behavior_analyzer
    BEHAVIOR_AVAILABLE = True
except Exception as e:
    logger.warning(f"行为分析模块加载失败: {e}")
    BEHAVIOR_AVAILABLE = False
    get_behavior_analyzer = None

try:
    from core import get_network_monitor, get_intrusion_detector
    NETWORK_AVAILABLE = True
except Exception as e:
    logger.warning(f"网络安全模块加载失败: {e}")
    NETWORK_AVAILABLE = False
    get_network_monitor = None
    get_intrusion_detector = None

try:
    from core import get_privacy_cleaner
    PRIVACY_AVAILABLE = True
except Exception as e:
    logger.warning(f"隐私保护模块加载失败: {e}")
    PRIVACY_AVAILABLE = False
    get_privacy_cleaner = None

try:
    from core import get_system_monitor
    PERFORMANCE_AVAILABLE = True
except Exception as e:
    logger.warning(f"性能监控模块加载失败: {e}")
    PERFORMANCE_AVAILABLE = False
    get_system_monitor = None


class AdvancedFeaturesPanel(QWidget):
    """高级功能主面板"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.setup_timers()
    
    def setup_ui(self):
        """设置UI"""
        layout = QVBoxLayout(self)
        
        # 创建选项卡
        self.tabs = QTabWidget()
        
        # 创建各个功能标签页
        if BEHAVIOR_AVAILABLE:
            self.behavior_tab = BehavioralAnalysisTab()
            self.tabs.addTab(self.behavior_tab, "🧠 行为分析")
        else:
            self.tabs.addTab(self._create_unavailable_widget("行为分析模块"), "🧠 行为分析")
        
        if NETWORK_AVAILABLE:
            self.network_tab = NetworkSecurityTab()
            self.tabs.addTab(self.network_tab, "🌐 网络安全")
        else:
            self.tabs.addTab(self._create_unavailable_widget("网络安全模块"), "🌐 网络安全")
        
        if PRIVACY_AVAILABLE:
            self.privacy_tab = PrivacyProtectionTab()
            self.tabs.addTab(self.privacy_tab, "🔒 隐私保护")
        else:
            self.tabs.addTab(self._create_unavailable_widget("隐私保护模块"), "🔒 隐私保护")
        
        if PERFORMANCE_AVAILABLE:
            self.performance_tab = PerformanceMonitoringTab()
            self.tabs.addTab(self.performance_tab, "📊 性能监控")
        else:
            self.tabs.addTab(self._create_unavailable_widget("性能监控模块"), "📊 性能监控")
        
        layout.addWidget(self.tabs)
    
    def _create_unavailable_widget(self, module_name):
        """创建模块不可用提示"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        label = QLabel(f"⚠️ {module_name}暂不可用\n\n可能原因：\n\n"
                      "1. 依赖包未安装\n"
                      "2. 模块导入失败\n\n"
                      "解决方案：\n"
                      "pip install -r requirements.txt")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet("color: #8892a8; font-size: 14px;")
        layout.addStretch()
        layout.addWidget(label)
        layout.addStretch()
        
        return widget
    
    def setup_timers(self):
        """设置定时更新"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_all_tabs)
        self.update_timer.start(2000)  # 每2秒更新一次
    
    def update_all_tabs(self):
        """更新所有标签页"""
        try:
            if BEHAVIOR_AVAILABLE and hasattr(self, 'behavior_tab'):
                self.behavior_tab.update_data()
            if NETWORK_AVAILABLE and hasattr(self, 'network_tab'):
                self.network_tab.update_data()
            if PERFORMANCE_AVAILABLE and hasattr(self, 'performance_tab'):
                self.performance_tab.update_data()
        except Exception as e:
            logger.debug(f"更新标签页失败: {e}")


class BehavioralAnalysisTab(QWidget):
    """行为分析标签页"""
    
    def __init__(self):
        super().__init__()
        self.analyzer = get_behavior_analyzer() if BEHAVIOR_AVAILABLE else None
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # 标题
        title = QLabel("实时行为分析")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(12)
        title.setFont(title_font)
        layout.addWidget(title)
        
        if not self.analyzer:
            layout.addWidget(QLabel("⚠️ 行为分析模块不可用，请检查依赖安装"))
            layout.addStretch()
            return
        
        # 异常进程表格
        self.anomaly_table = QTableWidget()
        self.anomaly_table.setColumnCount(5)
        self.anomaly_table.setHorizontalHeaderLabels([
            "进程名", "PID", "风险分数", "行为数", "状态"
        ])
        self.anomaly_table.setRowCount(0)
        layout.addWidget(QLabel("异常检测的进程:"))
        layout.addWidget(self.anomaly_table)
        
        # 最近异常
        layout.addWidget(QLabel("最近异常行为:"))
        self.anomaly_log = QTextEdit()
        self.anomaly_log.setReadOnly(True)
        self.anomaly_log.setMaximumHeight(150)
        layout.addWidget(self.anomaly_log)
        
        # 控制按钮
        button_layout = QHBoxLayout()
        refresh_btn = QPushButton("刷新数据")
        refresh_btn.clicked.connect(self.update_data)
        button_layout.addWidget(refresh_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
    
    def update_data(self):
        """更新数据"""
        if not self.analyzer:
            return
        
        try:
            # 获取异常进程
            for pid, score_data in self.analyzer.process_scores.items():
                if score_data["overall_score"] > self.analyzer.anomaly_threshold:
                    # 查找是否已在表格中
                    found = False
                    for row in range(self.anomaly_table.rowCount()):
                        if int(self.anomaly_table.item(row, 1).text()) == pid:
                            found = True
                            break
                    
                    if not found and self.anomaly_table.rowCount() < 20:
                        row = self.anomaly_table.rowCount()
                        self.anomaly_table.insertRow(row)
                        
                        self.anomaly_table.setItem(row, 0, QTableWidgetItem(score_data["process_name"]))
                        self.anomaly_table.setItem(row, 1, QTableWidgetItem(str(pid)))
                        score_item = QTableWidgetItem(f"{score_data['overall_score']:.1f}")
                        if score_data['overall_score'] > 80:
                            score_item.setBackground(QColor(255, 100, 100))
                        self.anomaly_table.setItem(row, 2, score_item)
                        self.anomaly_table.setItem(row, 3, QTableWidgetItem(
                            str(len(list(self.analyzer.process_behaviors[pid])))
                        ))
                        self.anomaly_table.setItem(row, 4, QTableWidgetItem("⚠️ 异常"))
            
            # 更新异常日志
            anomalies = self.analyzer.get_anomalies(limit=5)
            log_text = ""
            for anomaly in anomalies:
                log_text += f"[{anomaly['timestamp'].strftime('%H:%M:%S')}] {anomaly['process_name']}(PID:{anomaly['pid']}): {anomaly['score']:.1f}\n"
            self.anomaly_log.setText(log_text if log_text else "暂无异常")
        
        except Exception as e:
            logger.debug(f"行为分析数据更新失败: {e}")


class NetworkSecurityTab(QWidget):
    """网络安全标签页"""
    
    def __init__(self):
        super().__init__()
        self.network_monitor = get_network_monitor() if NETWORK_AVAILABLE else None
        self.intrusion_detector = get_intrusion_detector() if NETWORK_AVAILABLE else None
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # 标题
        title = QLabel("网络安全防护")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(12)
        title.setFont(title_font)
        layout.addWidget(title)
        
        if not self.network_monitor:
            layout.addWidget(QLabel("⚠️ 网络安全模块不可用，请检查依赖安装"))
            layout.addStretch()
            return
        
        # 可疑连接表格
        self.connection_table = QTableWidget()
        self.connection_table.setColumnCount(5)
        self.connection_table.setHorizontalHeaderLabels([
            "远程地址", "本地端口", "进程", "风险分数", "操作"
        ])
        self.connection_table.setRowCount(0)
        layout.addWidget(QLabel("可疑网络连接:"))
        layout.addWidget(self.connection_table)
        
        # 威胁警报
        layout.addWidget(QLabel("安全威胁警报:"))
        self.alert_log = QTextEdit()
        self.alert_log.setReadOnly(True)
        self.alert_log.setMaximumHeight(120)
        layout.addWidget(self.alert_log)
        
        # 控制按钮
        button_layout = QHBoxLayout()
        refresh_btn = QPushButton("刷新连接")
        refresh_btn.clicked.connect(self.update_data)
        button_layout.addWidget(refresh_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
    
    def update_data(self):
        """更新数据"""
        if not self.network_monitor:
            return
        
        try:
            # 监控网络连接
            connections = self.network_monitor.monitor_connections()
            suspicious = self.network_monitor.get_suspicious_connections(threshold=40)
            
            # 更新可疑连接表格
            self.connection_table.setRowCount(len(suspicious[:10]))
            for row, conn in enumerate(suspicious[:10]):
                self.connection_table.setItem(row, 0, QTableWidgetItem(conn.get("remote_addr", "N/A")))
                self.connection_table.setItem(row, 1, QTableWidgetItem(
                    conn.get("local_addr", "N/A").split(":")[-1]
                ))
                self.connection_table.setItem(row, 2, QTableWidgetItem(conn.get("process_name", "未知")))
                
                score_item = QTableWidgetItem(f"{conn['risk_score']:.1f}")
                if conn['risk_score'] > 70:
                    score_item.setBackground(QColor(255, 150, 100))
                self.connection_table.setItem(row, 3, score_item)
                
                block_btn = QPushButton("阻止")
                block_btn.clicked.connect(lambda checked, ip=conn["remote_addr"].split(":")[0]: 
                    self.block_ip(ip))
                self.connection_table.setCellWidget(row, 4, block_btn)
            
            # 获取检测到的威胁
            if self.intrusion_detector:
                alerts = self.intrusion_detector.get_alerts(limit=5)
                alert_text = ""
                for alert in alerts:
                    if isinstance(alert, dict):
                        alert_text += f"[{alert.get('timestamp', datetime.now()).strftime('%H:%M:%S')}] "
                        if 'target' in alert:
                            alert_text += f"DDoS威胁: {alert['target']}\n"
                        elif 'target_ports' in alert:
                            alert_text += f"端口扫描: {alert['target_ip']}\n"
                        else:
                            alert_text += f"安全事件\n"
                
                self.alert_log.setText(alert_text if alert_text else "暂无威胁警报")
        
        except Exception as e:
            logger.debug(f"网络安全数据更新失败: {e}")
    
    def block_ip(self, ip_address):
        """阻止IP"""
        try:
            if self.network_monitor:
                self.network_monitor.block_remote_ip(ip_address)
                logger.info(f"已阻止IP: {ip_address}")
        except Exception as e:
            logger.error(f"阻止IP失败: {e}")


class PrivacyProtectionTab(QWidget):
    """隐私保护标签页"""
    
    def __init__(self):
        super().__init__()
        self.cleaner = get_privacy_cleaner() if PRIVACY_AVAILABLE else None
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # 标题
        title = QLabel("隐私保护与数据安全")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(12)
        title.setFont(title_font)
        layout.addWidget(title)
        
        if not self.cleaner:
            layout.addWidget(QLabel("⚠️ 隐私保护模块不可用，请检查依赖安装"))
            layout.addStretch()
            return
        
        # 隐私清理选项
        group = QGroupBox("隐私数据清理")
        group_layout = QVBoxLayout()
        
        self.clean_browser_cb = QCheckBox("清理浏览器数据 (历史、Cookie、缓存)")
        self.clean_browser_cb.setChecked(True)
        group_layout.addWidget(self.clean_browser_cb)
        
        self.clean_temp_cb = QCheckBox("清理系统临时文件")
        self.clean_temp_cb.setChecked(True)
        group_layout.addWidget(self.clean_temp_cb)
        
        self.clean_registry_cb = QCheckBox("清理注册表痕迹 (MRU列表等)")
        self.clean_registry_cb.setChecked(True)
        group_layout.addWidget(self.clean_registry_cb)
        
        self.clean_clipboard_cb = QCheckBox("清理剪贴板")
        self.clean_clipboard_cb.setChecked(False)
        group_layout.addWidget(self.clean_clipboard_cb)
        
        group.setLayout(group_layout)
        layout.addWidget(group)
        
        # 清理日志
        layout.addWidget(QLabel("最近的清理操作:"))
        self.cleanup_log = QTextEdit()
        self.cleanup_log.setReadOnly(True)
        self.cleanup_log.setMaximumHeight(120)
        layout.addWidget(self.cleanup_log)
        
        # 清理按钮
        button_layout = QHBoxLayout()
        clean_btn = QPushButton("立即清理")
        clean_btn.clicked.connect(self.perform_cleanup)
        clean_btn.setStyleSheet("background-color: #4ecca3; color: white; padding: 8px;")
        button_layout.addWidget(clean_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
    
    def perform_cleanup(self):
        """执行清理"""
        if not self.cleaner:
            return
        
        try:
            results = []
            
            if self.clean_browser_cb.isChecked():
                success, msg = self.cleaner.clean_chrome_history()
                results.append(f"Chrome清理: {msg}")
                success, msg = self.cleaner.clean_firefox_history()
                results.append(f"Firefox清理: {msg}")
            
            if self.clean_temp_cb.isChecked():
                success, msg = self.cleaner.clean_system_temporary_files()
                results.append(f"临时文件清理: {msg}")
            
            if self.clean_registry_cb.isChecked():
                success, msg = self.cleaner.clean_registry_artifacts()
                results.append(f"注册表清理: {msg}")
            
            if self.clean_clipboard_cb.isChecked():
                success, msg = self.cleaner.clean_clipboard()
                results.append(f"剪贴板清理: {msg}")
            
            log_text = f"[{datetime.now().strftime('%H:%M:%S')}] 清理完成\n"
            log_text += "\n".join(results)
            
            self.cleanup_log.setText(log_text)
            logger.info("隐私数据清理完成")
        
        except Exception as e:
            logger.error(f"隐私清理失败: {e}")
            self.cleanup_log.setText(f"错误: {str(e)}")


class PerformanceMonitoringTab(QWidget):
    """性能监控标签页"""
    
    def __init__(self):
        super().__init__()
        self.monitor = get_system_monitor() if PERFORMANCE_AVAILABLE else None
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # 标题
        title = QLabel("性能监控")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(12)
        title.setFont(title_font)
        layout.addWidget(title)
        
        if not self.monitor:
            layout.addWidget(QLabel("⚠️ 性能监控模块不可用，请检查依赖安装"))
            layout.addStretch()
            return
        
        # 性能指标网格
        grid = QGridLayout()
        
        # CPU使用率
        grid.addWidget(QLabel("CPU使用率:"), 0, 0)
        self.cpu_progress = QProgressBar()
        self.cpu_progress.setMaximum(100)
        grid.addWidget(self.cpu_progress, 0, 1)
        self.cpu_label = QLabel("0%")
        grid.addWidget(self.cpu_label, 0, 2)
        
        # 内存使用率
        grid.addWidget(QLabel("内存使用率:"), 1, 0)
        self.mem_progress = QProgressBar()
        self.mem_progress.setMaximum(100)
        grid.addWidget(self.mem_progress, 1, 1)
        self.mem_label = QLabel("0 MB")
        grid.addWidget(self.mem_label, 1, 2)
        
        layout.addLayout(grid)
        
        # 性能统计
        layout.addWidget(QLabel("性能统计数据:"))
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        layout.addWidget(self.stats_text)
        
        # 刷新按钮
        button_layout = QHBoxLayout()
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self.update_data)
        button_layout.addWidget(refresh_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
    
    def update_data(self):
        """更新性能数据"""
        if not self.monitor:
            return
        
        try:
            snapshot = self.monitor.capture_snapshot()
            
            if snapshot:
                # 更新CPU
                cpu_percent = snapshot["process"]["cpu_percent"]
                self.cpu_progress.setValue(int(cpu_percent))
                self.cpu_label.setText(f"{cpu_percent:.1f}%")
                
                # 更新内存
                mem_mb = snapshot["process"]["memory_rss"] / (1024 * 1024)
                mem_percent = snapshot["process"]["memory_percent"]
                self.mem_progress.setValue(int(mem_percent))
                self.mem_label.setText(f"{mem_mb:.1f} MB")
                
                # 更新统计数据
                avg_stats = self.monitor.get_average_stats(sample_count=10)
                if avg_stats:
                    stats_text = (
                        f"采样数: {avg_stats['sample_count']}\n"
                        f"平均CPU: {avg_stats['avg_cpu_percent']:.1f}%\n"
                        f"平均内存: {avg_stats['avg_memory_rss'] / (1024*1024):.1f} MB\n"
                        f"峰值内存: {avg_stats['max_memory_rss'] / (1024*1024):.1f} MB\n"
                        f"监控时长: {avg_stats['duration']:.1f}秒"
                    )
                    self.stats_text.setText(stats_text)
        
        except Exception as e:
            logger.debug(f"性能数据更新失败: {e}")
