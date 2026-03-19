# 猫卫士 (The Cat Guard) — 开发会话技术摘要

> 生成时间：2026-03-11

---

## 一、项目概述

**猫卫士** 是一款轻量级 Windows 主动防御与系统修复工具。  
技术栈：Python 3.14 + PyQt6 + psutil + watchdog + pywin32 + WMI + pywintrace + yara-python  
仓库地址：https://github.com/kuankuantj2831/TheCatGuard

---

## 二、本次会话完成的所有工作

### 阶段 1：项目分析与 Bug 修复
- 分析整个项目结构和代码
- 修复 `core/monitor.py`、`gui/mainwindow.py`、`core/repair.py`、`core/utils.py`、`assets/style.qss` 中的多个 Bug
- 全部 UI 文本从英文翻译为中文

### 阶段 2：功能增强
- **垃圾清理器**：`core/repair.py` 新增 `clean_junk()` 清理临时文件/缓存/回收站
- **开机自启**：`core/utils.py` 新增注册表自启管理（`enable_autostart` / `disable_autostart`）
- **批量启动器**：整合所有修复工具
- **单实例锁**：`main.py` 使用 `QLocalServer` 防止重复启动

### 阶段 3：UI 全面重构
- **`assets/style.qss`**：重写为深蓝/青色暗色主题
- **`gui/dashboard.py`**：新增 `StatusCard` 组件，5 个监控模块状态卡片 + 实时日志查看器
- **`gui/tools.py`**：新增 `ToolCard` 组件，6 个修复工具卡片 + 开机自启开关
- **垃圾清理 GUI 卡死修复**：移到 `QThread` 后台执行

### 阶段 4：代码优化（7 项改进）
- 优化监控轮询间隔
- 改进日志格式
- 减少内存占用
- 其他性能优化

### 阶段 5：Git 推送
- 推送到 `github.com/kuankuantj2831/TheCatGuard`

### 阶段 6：安全审计与修复（4 个漏洞）
- 修复进程监控绕过漏洞
- 修复注册表监控盲区
- 修复 USB 扫描不足
- 修复网络监控缺失

### 阶段 7：ETW 集成
- `core/monitor.py` — `ProcessMonitor` 改为 ETW/轮询混合模式
- 新增 `NetworkMonitor` 网络连接监控

### 阶段 8：v1.5 功能实现
- **`core/config.py`**：JSON 配置管理，线程安全，白名单/黑名单/监控间隔
- **`core/yara_scanner.py`**：5 条内置 YARA 规则，文件/目录/内存扫描
- **`core/quarantine.py`**：文件隔离区，JSON 索引，支持恢复/删除
- **`gui/settings.py`**：完整设置界面（监控间隔、端口、白/黑名单、YARA 配置）
- **`gui/security.py`**：安全扫描 + 隔离区管理双标签页

### 阶段 9：运行时 Bug 修复
| Bug | 原因 | 修复 |
|-----|------|------|
| 启动后无反应 | `config.py` 死锁：`load_config()` 持锁调用 `save_config()` | 拆分为 `_write_file()` 内部方法 |
| 托盘图标不显示 | PNG 格式在 Windows 托盘不可靠 | 生成多尺寸 ICO 文件 |
| 启动闪退 | `QLocalServer` 残留导致误判"已运行" | 添加 `QLocalServer.removeServer()` 清理 |

### 阶段 10：SYSTEM 提权
- **`main.py`**：
  - `_ensure_admin()` — 非管理员时通过 UAC (`ShellExecuteW runas`) 自动提升
  - `_try_elevate_to_system()` — 管理员下自动提权到 SYSTEM
  - `--system-elevated` 标志防止无限重启循环
- **`core/utils.py`**：
  - `is_system()` — 检测当前是否为 SYSTEM 用户
  - `elevate_to_system()` — 找到 `winlogon.exe` PID
  - `_create_system_process()` — 复制 winlogon.exe 的 SYSTEM 令牌，`CreateProcessAsUserW` 启动新进程
  - `_enable_privilege()` — 启用 `SeDebugPrivilege`

### 阶段 11：VPN 刷屏修复
- **网络监控**：
  - 新增 `_is_local_ip()` — 过滤 `127.0.0.1`、`::1`、`192.168.x.x`、`10.x.x.x` 等本地/私有地址
  - 新增 `_should_alert()` — 同一 (进程名, IP) 60 秒内只告警一次
- **USB 监控**：
  - 新增 `_reconnect_wmi()` — WMI 失败时自动重连
  - 持续失败 3 次后静默，降低轮询到 30 秒

---

## 三、当前文件结构

```
The Cat Guard/
├── main.py                  # 入口：UAC提权 → SYSTEM提权 → 单实例 → GUI
├── requirements.txt
├── assets/
│   ├── style.qss            # 深蓝暗色主题
│   ├── icon.ico             # 托盘图标
│   └── icon.png
├── core/
│   ├── __init__.py
│   ├── config.py            # JSON 配置管理（线程安全）
│   ├── monitor.py           # 6 个监控器 + MonitorManager
│   ├── quarantine.py        # 文件隔离区
│   ├── repair.py            # 系统修复工具集
│   ├── utils.py             # 工具函数 + SYSTEM 提权
│   └── yara_scanner.py      # YARA 扫描引擎
├── gui/
│   ├── __init__.py
│   ├── dashboard.py         # 仪表盘（状态卡片 + 日志）
│   ├── mainwindow.py        # 主窗口（5 标签页 + 托盘）
│   ├── security.py          # 安全扫描 + 隔离区
│   ├── settings.py          # 设置界面
│   ├── tools.py             # 系统修复工具页
│   └── utils.py             # QtLogHandler
```

---

## 四、Git 提交历史（本次会话）

| 提交 | 说明 |
|------|------|
| `83b727f` | v1.5.0 — 配置/YARA/隔离区/设置 |
| `6952aa9` | 修复托盘图标（PNG→ICO） |
| `10c4493` | 修复 config.py 死锁 |
| `9b1f0e8` | 修复单实例闪退 |
| `a21e2cd` | 自动管理员+SYSTEM 提权 |
| `2588443` | 网络监控过滤本地IP+告警去重, USB监控WMI自动重连 |

---

## 五、未完成的工作（下次继续）

计划实现六大主动防御能力，提升对抗 WannaCry/Memz 等真实恶意软件的能力：

1. **进程拦截（秒杀）** — 检测到可疑进程立即 `TerminateProcess`
2. **勒索软件行为检测** — 监控短时间内大量文件重命名/加密模式
3. **MBR 保护与备份** — 定期备份 MBR，检测覆写立即恢复
4. **关键文件影子备份** — 对用户文档做影子副本
5. **网络层 SMB 封锁** — 检测 445 端口异常扫描，防火墙阻断横向传播
6. **自保护看门狗** — 注册为 Windows 服务 + 互保机制

这些功能将实现在 `core/defender.py` 中，并集成到 GUI 仪表盘。

---

## 六、版本路线图

| 版本 | 内容 | 状态 |
|------|------|------|
| v1.0 | 基础监控 + 系统修复 + UI | ✅ 完成 |
| v1.5 | 配置管理 + YARA + 隔离区 + 白/黑名单 | ✅ 完成 |
| v2.0 | 主动防御（进程拦截/勒索检测/MBR保护/SMB封锁/自保护） | ⏳ 待实现 |
| v2.5 | 行为分析引擎 | 📋 规划中 |
| v3.0 | 产品化（安装包/自动更新/云端规则） | 📋 规划中 |
