# TheCatGuard
猫卫士TheCatGuard

## 🚀 最新更新：向360学习 + 全面功能升级

### ✨ 新增360风格功能

#### 1. 云查杀引擎 (Cloud Malware Scanner)
- **VirusTotal集成**：实时云端病毒库查询
- **哈希黑名单**：支持SHA256黑名单检测
- **URL安全检查**：检测钓鱼网站和恶意链接
- **缓存机制**：减少API调用，提升性能

#### 2. 行为启发式检测 (Behavioral Heuristic Detector)
- **进程行为评分**：0-100风险评分系统
- **多维度检测**：
  - 临时目录启动检测
  - 系统文件访问监控
  - 异常网络连接分析
  - 隐藏文件操作检测

#### 3. 进程注入检测 (Process Injection Detector)
- **远程线程注入检测**：监控CreateRemoteThread调用
- **DLL劫持防御**：检测恶意DLL替换
- **内存权限分析**：识别可疑的RWX内存区域
- **签名验证**：检查系统DLL的Microsoft签名

#### 4. 增强的扫描管道
- **多层检测流程**：
  1. 哈希黑名单 → 2. YARA规则 → 3. 云查杀 → 4. PE启发式
- **精确打击**：专门针对WannaCry等已知威胁优化

### 🎯 新增高级功能

#### 5. 实时可视化仪表盘 (Enhanced Dashboard)
- **系统资源监控**：CPU/内存/磁盘实时图表
- **威胁统计面板**：24小时威胁趋势分析
- **扫描进度可视化**：实时进度条和详细日志
- **威胁详情表格**：可排序的威胁列表

#### 6. 自动修复引擎 (Auto Fixer)
- **一键修复系统**：自动修复常见安全问题
- **注册表清理**：移除可疑启动项
- **Hosts文件修复**：清除恶意DNS劫持
- **浏览器重置**：修复主页和搜索引擎劫持
- **修复报告生成**：详细的修复结果报告

#### 7. 任务自动化调度器 (Task Scheduler)
- **定时扫描任务**：
  - 每日快速扫描（凌晨2:00）
  - 每周深度扫描（周日凌晨5:00）
- **自动维护**：
  - YARA规则自动更新（每4小时）
  - 隔离区自动清理（每日3:00）
  - 系统健康检查（每小时）

#### 8. 勒索软件专项防护 (Ransomware Defender)
- **文件加密检测**：监控大规模文件修改
- **SMB蠕虫防护**：445端口异常扫描防御
- **卷影副本保护**：防止勒索软件删除备份
- **紧急响应**：检测到威胁时自动创建还原点
- **进程隔离**：自动终止可疑加密进程

### 📊 技术提升对比

| 功能 | 升级前 | 升级后 | 提升程度 |
|------|--------|--------|----------|
| 检测方法 | 本地规则 | 云端+本地+行为+AI | 大幅扩展 |
| 误报控制 | 中等 | 低（多重验证） | 显著改善 |
| 威胁覆盖 | 已知威胁 | 未知威胁+零日攻击 | 全面覆盖 |
| 云端能力 | 无 | VirusTotal集成 | 新增 |
| 注入防护 | 无 | 多层检测 | 新增 |
| 自动化 | 手动 | 智能调度 | 新增 |
| 勒索防护 | 基础 | 专项防护 | 新增 |
| 可视化 | 基础 | 实时图表 | 新增 |
| 修复能力 | 手动 | 自动修复 | 新增 |

### ⚙️ 配置说明

在`config.json`中添加以下配置项：

```json
{
  "cloud_scanner": {
    "enabled": false,
    "api_key": "your_virustotal_api_key"
  },
  "heuristic_detection": {
    "enabled": true,
    "risk_threshold": 50
  },
  "injection_detection": {
    "enabled": true
  },
  "automation": {
    "enabled": true,
    "daily_scan_hour": 2,
    "weekly_scan_day": 6
  },
  "ransomware_protection": {
    "enabled": true,
    "auto_restore_point": true
  }
}
```

### 🔧 安装依赖

```bash
pip install -r requirements.txt
```

新增依赖：
- `pyqtgraph==0.13.3` - 实时图表
- `apscheduler==3.10.4` - 定时任务
- `numpy==1.24.0` - 数据计算
- `plyer==2.1.0` - 系统通知
- `cryptography==41.0.0` - 数据加密

### 🎯 使用方法

#### 1. 实时监控
- 主界面显示系统资源实时图表
- 威胁统计面板展示检测结果
- 扫描进度实时更新

#### 2. 自动化任务
- 系统会自动执行定时扫描和维护
- 在设置中可以调整任务时间

#### 3. 勒索软件防护
- 自动监控文件加密行为
- 检测到威胁时自动响应

#### 4. 自动修复
```python
from core.auto_fixer import AutoFixer
fixer = AutoFixer()
results = fixer.fix_startup_entries(suspicious_entries)
report = fixer.generate_fix_report(results)
```

### 🛡️ 安全特性

- **多层防御**：本地+云端+行为分析
- **实时监控**：ETW事件驱动的进程监控
- **智能隔离**：自动隔离高风险文件
- **行为分析**：学习360的行为检测模式
- **勒索防护**：专项反勒索软件保护
- **自动修复**：一键修复常见安全问题
- **任务自动化**：智能定时维护

### 📈 性能优化

- **缓存机制**：云查结果本地缓存
- **异步处理**：非阻塞的云端查询
- **智能过滤**：白名单和阈值过滤
- **资源控制**：限制扫描文件大小和超时
- **多线程**：并行处理提高效率

### 🔄 自动化特性

- **定时扫描**：每日快速扫描 + 每周深度扫描
- **规则更新**：自动下载最新YARA规则
- **隔离清理**：自动删除过期隔离文件
- **健康检查**：定期检查系统状态
- **智能告警**：去重和聚合减少噪音

---

*本项目已全面升级为企业级安全工具，具备360安全卫士的核心功能和更强的自动化能力。*
{
  "cloud_scanner": {
    "enabled": false,
    "api_key": "your_virustotal_api_key"
  },
  "heuristic_detection": {
    "enabled": true,
    "risk_threshold": 50
  },
  "injection_detection": {
    "enabled": true
  }
}
```

### 🔧 安装依赖

```bash
pip install -r requirements.txt
```

新增依赖：`requests` (用于云查杀API调用)

### 🎯 使用方法

1. **配置VirusTotal API**（可选）：
   - 注册VirusTotal账户获取API密钥
   - 在配置中设置`cloud_scanner.api_key`

2. **启动增强版扫描**：
   ```python
   from core.yara_scanner import YaraScanner
   scanner = YaraScanner()
   results = scanner.scan_file("suspicious.exe")
   ```

3. **监控进程行为**：
   ```python
   from core.monitor import MonitorManager
   manager = MonitorManager()
   manager.start_all()  # 自动启用所有检测
   ```

### 🛡️ 安全特性

- **分层防御**：本地+云端双重验证
- **实时监控**：ETW事件驱动的进程监控
- **智能隔离**：自动隔离高风险文件
- **行为分析**：学习360的行为检测模式
- **低误报**：多重验证减少误报

### 📈 性能优化

- **缓存机制**：云查结果本地缓存
- **异步处理**：非阻塞的云端查询
- **智能过滤**：白名单和阈值过滤
- **资源控制**：限制扫描文件大小和超时

---

*本项目参考360安全卫士的设计理念，致力于打造功能全面、检测准确的Windows安全工具。*
