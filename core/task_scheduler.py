import os
import time
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from .utils import get_logger
from .yara_scanner import YaraScanner
from . import config

logger = get_logger()

class AutomationScheduler:
    """自动化任务调度器"""

    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.yara_scanner = YaraScanner()
        self.is_running = False

    def start(self):
        """启动调度器"""
        if self.is_running:
            return

        try:
            # 配置调度器
            self.scheduler.configure(
                jobstores={},
                executors={
                    'default': {'type': 'threadpool', 'max_workers': 2}
                },
                job_defaults={
                    'coalesce': True,
                    'max_instances': 1,
                    'misfire_grace_time': 30
                },
                timezone='Asia/Shanghai'
            )

            # 添加定时任务
            self._schedule_tasks()

            # 启动调度器
            self.scheduler.start()
            self.is_running = True
            logger.info("自动化任务调度器已启动")

        except Exception as e:
            logger.error(f"启动任务调度器失败: {e}")

    def stop(self):
        """停止调度器"""
        if self.is_running:
            self.scheduler.shutdown(wait=True)
            self.is_running = False
            logger.info("自动化任务调度器已停止")

    def _schedule_tasks(self):
        """配置定时任务"""

        # 每日快速扫描 - 凌晨2:00
        self.scheduler.add_job(
            func=self._run_daily_quick_scan,
            trigger=CronTrigger(hour=2, minute=0),
            id='daily_quick_scan',
            name='每日快速扫描',
            replace_existing=True
        )

        # 每周深度扫描 - 每周日凌晨5:00
        self.scheduler.add_job(
            func=self._run_weekly_deep_scan,
            trigger=CronTrigger(day_of_week=6, hour=5, minute=0),  # 6=周日
            id='weekly_deep_scan',
            name='每周深度扫描',
            replace_existing=True
        )

        # 每4小时更新YARA规则
        self.scheduler.add_job(
            func=self._update_yara_rules,
            trigger=CronTrigger(hour='*/4', minute=30),  # 每4小时的30分
            id='yara_rules_update',
            name='YARA规则更新',
            replace_existing=True
        )

        # 每日清理过期隔离文件 - 凌晨3:00
        self.scheduler.add_job(
            func=self._cleanup_quarantine,
            trigger=CronTrigger(hour=3, minute=0),
            id='quarantine_cleanup',
            name='隔离区清理',
            replace_existing=True
        )

        # 每小时系统健康检查
        self.scheduler.add_job(
            func=self._system_health_check,
            trigger=CronTrigger(hour='*/1', minute=15),
            id='system_health_check',
            name='系统健康检查',
            replace_existing=True
        )

        logger.info("已配置定时任务: 每日扫描、每周深度扫描、规则更新、隔离清理、健康检查")

    def _run_daily_quick_scan(self):
        """执行每日快速扫描"""
        logger.info("开始执行每日快速扫描任务")

        try:
            # 扫描关键目录
            scan_dirs = [
                os.path.expandvars(r'%PROGRAMFILES%'),
                os.path.expandvars(r'%PROGRAMFILES(X86)%'),
                os.path.expandvars(r'%APPDATA%'),
                os.path.expandvars(r'%LOCALAPPDATA%'),
                os.path.expandvars(r'%TEMP%'),
                os.path.expandvars(r'%SYSTEMROOT%\System32'),
            ]

            total_threats = 0

            for scan_dir in scan_dirs:
                if not os.path.exists(scan_dir):
                    continue

                logger.info(f"扫描目录: {scan_dir}")
                results = self.yara_scanner.scan_directory(scan_dir, recursive=False)

                if results:
                    total_threats += len(results)
                    for result in results:
                        logger.warning(f"发现威胁: {result['file']} - {result['rule']}")

            logger.info(f"每日快速扫描完成，发现威胁: {total_threats} 个")

        except Exception as e:
            logger.error(f"每日快速扫描失败: {e}")

    def _run_weekly_deep_scan(self):
        """执行每周深度扫描"""
        logger.info("开始执行每周深度扫描任务")

        try:
            # 扫描全盘（排除系统目录以提高效率）
            scan_dirs = [
                "C:\\Users",
                "D:\\",  # 如果存在D盘
                "E:\\",  # 如果存在E盘
            ]

            total_threats = 0

            for scan_dir in scan_dirs:
                if not os.path.exists(scan_dir):
                    continue

                logger.info(f"深度扫描目录: {scan_dir}")
                results = self.yara_scanner.scan_directory(scan_dir, recursive=True)

                if results:
                    total_threats += len(results)
                    for result in results:
                        logger.warning(f"发现威胁: {result['file']} - {result['rule']}")

            logger.info(f"每周深度扫描完成，发现威胁: {total_threats} 个")

        except Exception as e:
            logger.error(f"每周深度扫描失败: {e}")

    def _update_yara_rules(self):
        """更新YARA规则"""
        logger.info("开始更新YARA规则")

        try:
            # 重新加载规则
            if self.yara_scanner.load_rules():
                logger.info("YARA规则更新成功")
            else:
                logger.warning("YARA规则更新失败")

        except Exception as e:
            logger.error(f"YARA规则更新异常: {e}")

    def _cleanup_quarantine(self):
        """清理过期隔离文件"""
        logger.info("开始清理过期隔离文件")

        try:
            from .quarantine import QuarantineManager
            quarantine = QuarantineManager()

            # 删除30天前的隔离文件
            days_old = 30
            cleaned_count = quarantine.cleanup_old_files(days_old)

            logger.info(f"隔离区清理完成，删除 {cleaned_count} 个过期文件")

        except Exception as e:
            logger.error(f"隔离区清理失败: {e}")

    def _system_health_check(self):
        """系统健康检查"""
        logger.debug("执行系统健康检查")

        try:
            import psutil

            # 检查CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                logger.warning(f"CPU使用率过高: {cpu_percent}%")

            # 检查内存使用率
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                logger.warning(f"内存使用率过高: {memory.percent}%")

            # 检查磁盘空间
            disk = psutil.disk_usage('C:')
            if disk.percent > 95:
                logger.warning(f"C盘空间不足: {disk.percent}% 使用")

            # 检查关键进程是否存在
            critical_processes = ['svchost.exe', 'explorer.exe', 'csrss.exe']
            for proc_name in critical_processes:
                found = False
                for proc in psutil.process_iter(['name']):
                    if proc.info['name'] and proc.info['name'].lower() == proc_name.lower():
                        found = True
                        break
                if not found:
                    logger.warning(f"关键进程不存在: {proc_name}")

        except Exception as e:
            logger.error(f"系统健康检查失败: {e}")

    def add_custom_task(self, task_id: str, func, trigger, **kwargs):
        """添加自定义任务"""
        try:
            self.scheduler.add_job(
                func=func,
                trigger=trigger,
                id=task_id,
                replace_existing=True,
                **kwargs
            )
            logger.info(f"自定义任务已添加: {task_id}")
        except Exception as e:
            logger.error(f"添加自定义任务失败 {task_id}: {e}")

    def remove_task(self, task_id: str):
        """移除任务"""
        try:
            self.scheduler.remove_job(task_id)
            logger.info(f"任务已移除: {task_id}")
        except Exception as e:
            logger.error(f"移除任务失败 {task_id}: {e}")

    def list_tasks(self):
        """列出所有任务"""
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                'id': job.id,
                'name': job.name,
                'next_run': job.next_run_time,
                'trigger': str(job.trigger)
            })
        return jobs

    def run_task_now(self, task_id: str):
        """立即执行任务"""
        try:
            job = self.scheduler.get_job(task_id)
            if job:
                job.func()
                logger.info(f"任务已手动执行: {task_id}")
                return True
            else:
                logger.warning(f"任务不存在: {task_id}")
                return False
        except Exception as e:
            logger.error(f"手动执行任务失败 {task_id}: {e}")
            return False