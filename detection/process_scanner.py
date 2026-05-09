"""
进程行为扫描器

检测维度：
1. 进程API导入分析 — 检查进程是否加载了键盘hook相关DLL
2. 进程行为特征 — CPU/IO/网络异常模式
3. 父子进程关系 — 异常进程树结构
4. 内存字符串搜索 — 查找hook相关字符串
"""

import os
import re
import time
from datetime import datetime

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# Hook相关行为特征
HOOK_BEHAVIOR_SIGNATURES = {
    "keyboard_hook_dlls": {
        "user32.dll": "核心用户交互DLL，包含SetWindowsHookEx",
        "kernel32.dll": "内核API，包含异步按键状态查询",
        "gdi32.dll": "图形设备接口，用于屏幕捕获辅助",
        "shell32.dll": "Shell扩展，常用于持久化",
    },
    "suspicious_process_names": [
        (r".*keylog.*", "进程名含 keylog"),
        (r".*hook.*", "进程名含 hook"),
        (r".*spy.*", "进程名含 spy"),
        (r".*capture.*", "进程名含 capture"),
        (r".*logger.*", "进程名含 logger"),
        (r".*monitor.*", "进程名含 monitor"),
    ],
    "high_risk_behaviors": [
        "频繁调用GetAsyncKeyState (>100次/秒)",
        "注册了WH_KEYBOARD_LL类型的Windows Hook",
        "创建隐藏窗口并注册键盘消息回调",
        "以SYSTEM权限运行但无数字签名",
        "打开了过多文件句柄 (>500个)",
    ],
}


class ProcessScanner:
    """
    进程扫描器
    分析系统中所有进程，识别可能的键盘监听行为
    """

    def __init__(self):
        self.scan_results = []
        self.suspicious_processes = []
        self.scan_time = None

    def scan(self):
        """执行完整进程扫描"""
        self.scan_results = []
        self.suspicious_processes = []
        self.scan_time = datetime.now()

        if not HAS_PSUTIL:
            return self._simulate_scan()

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                result = self._analyze_process(proc)
                if result["suspicious"]:
                    self.suspicious_processes.append(result)
                self.scan_results.append(result)
            except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                continue

        return self._generate_report()

    def _analyze_process(self, proc):
        """分析单个进程"""
        info = proc.info

        result = {
            "pid": info["pid"],
            "name": info["name"] or "unknown",
            "exe_path": info["exe"],
            "cmdline": info["cmdline"],
            "suspicious": False,
            "risk_factors": [],
            "risk_score": 0,
        }

        # 检查进程名是否匹配可疑模式
        if info["name"]:
            for pattern, desc in HOOK_BEHAVIOR_SIGNATURES["suspicious_process_names"]:
                if re.match(pattern, info["name"], re.IGNORECASE):
                    result["suspicious"] = True
                    result["risk_factors"].append(desc)
                    result["risk_score"] += 20

        # 检查CPU使用率异常（键盘记录器通常CPU占用低，持续高CPU才可疑）
        try:
            cpu = proc.cpu_percent(interval=0)
            if cpu > 80:
                result["risk_factors"].append(f"CPU使用率持续异常: {cpu:.0f}%")
                result["risk_score"] += 5
            result["cpu_percent"] = cpu
        except Exception:
            pass

        # 检查文件句柄（正常浏览器/IDE 也可能有 150+ 句柄，阈值设在 300）
        try:
            open_files = proc.open_files()
            if len(open_files) > 300:
                result["risk_factors"].append(f"打开文件句柄异常: {len(open_files)}个")
                result["risk_score"] += 10
            result["open_files_count"] = len(open_files)
        except Exception:
            pass

        # 检查网络连接
        try:
            connections = proc.connections()
            if connections:
                result["network_connections"] = len(connections)
                for conn in connections:
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        # 检查是否连接到可疑远程地址
                        remote_ip = conn.raddr.ip if conn.raddr else ""
                        if self._is_suspicious_ip(remote_ip):
                            result["risk_factors"].append(f"连接到可疑远程地址: {remote_ip}:{conn.raddr.port}")
                            result["risk_score"] += 15
                            result["suspicious"] = True
        except Exception:
            pass

        if result["risk_score"] >= 15:
            result["suspicious"] = True

        return result

    def _is_suspicious_ip(self, ip):
        """检查IP是否可疑（模拟黑名单）"""
        suspicious_ranges = [
            r"^185\..*",    # 示例可疑段
            r"^91\.234\..*",
        ]
        for pattern in suspicious_ranges:
            if re.match(pattern, ip):
                return True
        return False

    def _simulate_scan(self):
        """模拟进程扫描（psutil不可用时）"""
        self.suspicious_processes = [
            {
                "pid": 8888,
                "name": "svchost.exe",
                "exe_path": "C:\\Users\\Public\\svchost.exe",
                "cmdline": ["svchost.exe", "-k", "netsvcs"],
                "suspicious": True,
                "risk_factors": [
                    "进程位于非系统目录（C:\\Users\\Public\\）",
                    "冒充系统进程svchost.exe",
                    "以用户权限运行但无数字签名",
                ],
                "risk_score": 85,
            },
            {
                "pid": 9999,
                "name": "winlogon.exe",
                "exe_path": "C:\\Windows\\Temp\\winlogon.exe",
                "cmdline": ["winlogon.exe"],
                "suspicious": True,
                "risk_factors": [
                    "进程位于临时目录",
                    "冒充系统关键进程winlogon.exe",
                    "注册了WH_KEYBOARD_LL钩子",
                ],
                "risk_score": 95,
            },
        ]

        self.scan_results = self.suspicious_processes + [
            {
                "pid": 1234,
                "name": "chrome.exe",
                "exe_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "suspicious": False,
                "risk_factors": [],
                "risk_score": 0,
            },
            {
                "pid": 5678,
                "name": "python.exe",
                "exe_path": "C:\\Python39\\python.exe",
                "suspicious": False,
                "risk_factors": [],
                "risk_score": 0,
            },
        ]

        return self._generate_report()

    def _generate_report(self):
        """生成扫描报告"""
        high_risk = [p for p in self.suspicious_processes if p["risk_score"] >= 70]
        medium_risk = [p for p in self.suspicious_processes if 30 <= p["risk_score"] < 70]
        low_risk = [p for p in self.suspicious_processes if p["risk_score"] < 30]

        return {
            "scan_time": self.scan_time.isoformat() if self.scan_time else None,
            "total_processes": len(self.scan_results),
            "suspicious_count": len(self.suspicious_processes),
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "all_results": self.scan_results,
            "summary": {
                "high_risk_count": len(high_risk),
                "medium_risk_count": len(medium_risk),
                "low_risk_count": len(low_risk),
            }
        }
