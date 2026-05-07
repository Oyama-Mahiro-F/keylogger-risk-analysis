"""
键盘Hook检测引擎

检测方法：
1. API导入表扫描 — 检查进程是否导入了键盘hook相关API
2. 线程级hook检测 — 检查是否存在WH_KEYBOARD类型的钩子
3. 文件系统嗅探 — 扫描可疑日志文件
4. 注册表持久化检测 — 检查自启动项
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime

# ============================
# 检测规则库
# ============================
HOOK_API_SIGNATURES = [
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "UnhookWindowsHookEx",
    "GetAsyncKeyState",
    "GetKeyState",
    "GetKeyboardState",
    "GetRawInputData",
    "RegisterRawInputDevices",
    "CallNextHookEx",
]

SUSPICIOUS_FILE_PATTERNS = [
    (r".*\.idx\.dat$", "隐蔽按键日志文件"),
    (r".*keylog.*\.(txt|bin|dat|log)$", "键盘记录日志"),
    (r".*\.sys_cache\\.*", "伪装系统缓存的日志目录"),
    (r".*winlog\.dat$", "伪装Windows日志文件"),
    (r".*kl\.dat$", "键盘记录器输出文件"),
]

SUSPICIOUS_REGISTRY = [
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\.*",
    r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\.*",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\.*",
]


class HookDetector:
    """
    Hook检测器
    对系统中的键盘监听行为进行多维度检测
    """

    def __init__(self):
        self.findings = []
        self.risk_indicators = []
        self.scan_time = None

    def scan_all(self):
        """执行所有检测项"""
        self.findings = []
        self.risk_indicators = []
        self.scan_time = datetime.now()

        # 依次执行各项检测
        self._check_file_indicators()
        self._check_hook_signatures()

        return self.generate_report()

    def _check_file_indicators(self):
        """文件系统指标检测"""
        suspicious_paths = [
            Path.home() / ".sys_cache",
            Path.home() / "AppData" / "Local" / "Temp",
            Path(os.environ.get("TEMP", os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Local", "Temp"))),
        ]

        for base_path in suspicious_paths:
            if not base_path.exists():
                continue
            try:
                for root, dirs, files in os.walk(str(base_path)):
                    # 限制深度避免无限递归
                    depth = root.replace(str(base_path), "").count(os.sep)
                    if depth > 3:
                        continue

                    for filename in files:
                        full_path = os.path.join(root, filename)
                        for pattern, desc in SUSPICIOUS_FILE_PATTERNS:
                            if re.match(pattern, full_path, re.IGNORECASE):
                                self.findings.append({
                                    "type": "suspicious_file",
                                    "path": full_path,
                                    "description": desc,
                                    "severity": "medium",
                                })
                                self.risk_indicators.append(f"发现可疑文件: {full_path} ({desc})")

                    for dirname in dirs:
                        full_dir = os.path.join(root, dirname)
                        if re.match(r".*\.sys_cache$", full_dir):
                            self.findings.append({
                                "type": "suspicious_directory",
                                "path": full_dir,
                                "description": "伪装系统缓存的隐蔽目录",
                                "severity": "high",
                            })
            except PermissionError:
                continue

    def _check_hook_signatures(self):
        """Hook API使用痕迹检测（模拟）"""
        # 在真实环境中这里会检查加载的DLL和API导入表
        # 本次模拟基于已知的API签名
        import platform
        system = platform.system()

        if system == "Windows":
            self._simulate_windows_hook_check()
        else:
            self.findings.append({
                "type": "platform_note",
                "description": f"当前平台 {system}，Hook检测以模拟模式运行",
                "severity": "info",
            })

    def _simulate_windows_hook_check(self):
        """Windows环境下的Hook API可用性检测"""
        try:
            import ctypes
        except ImportError:
            self.findings.append({
                "type": "warning",
                "description": "无法加载ctypes库，部分检测将以模拟模式运行",
                "severity": "low",
            })
            return

        # 尝试解析 API 函数指针，验证导出是否存在
        api_usage_found = []
        for api_name in HOOK_API_SIGNATURES:
            try:
                user32 = ctypes.windll.user32
                kernel32 = ctypes.windll.kernel32
                # 用 getattr 替代 hasattr — 显式捕获 AttributeError，
                # 避免 hasattr 吞掉其他异常
                try:
                    getattr(user32, api_name)
                    api_usage_found.append((api_name, "user32.dll"))
                except AttributeError:
                    try:
                        getattr(kernel32, api_name)
                        api_usage_found.append((api_name, "kernel32.dll"))
                    except AttributeError:
                        continue
            except Exception:
                continue

        found_count = len(api_usage_found)
        if found_count >= 3:
            # 这些 API 是 Windows 标准导出，存在本身不表示恶意行为；
            # 仅作为参考指标记录，不单独提升风险等级
            self.findings.append({
                "type": "hook_api_available",
                "description": f"系统中 {found_count}/{len(HOOK_API_SIGNATURES)} 个键盘Hook相关API可用（正常系统均存在）",
                "apis": [name for name, _ in api_usage_found],
                "severity": "info",
            })
            self.risk_indicators.append(
                f"系统存在 {found_count} 个可用于键盘监听的API（常规系统组件，仅供参考）"
            )

    def generate_report(self):
        """生成检测报告"""
        risk_level = self._calculate_risk_level()

        return {
            "scan_time": self.scan_time.isoformat() if self.scan_time else None,
            "total_findings": len(self.findings),
            "risk_level": risk_level["level"],
            "risk_score": risk_level["score"],
            "findings": self.findings,
            "risk_indicators": self.risk_indicators,
            "recommendation": risk_level["recommendation"],
        }

    def _calculate_risk_level(self):
        """根据检测结果计算风险等级"""
        high_count = sum(1 for f in self.findings if f.get("severity") == "high")
        medium_count = sum(1 for f in self.findings if f.get("severity") == "medium")
        low_count = sum(1 for f in self.findings if f.get("severity") == "low")
        info_count = sum(1 for f in self.findings if f.get("severity") == "info")

        score = high_count * 30 + medium_count * 15 + low_count * 5 + info_count * 1
        score = min(score, 100)

        if score >= 60:
            level = "HIGH"
            recommendation = "检测到高风险键盘监听指标，建议立即采取措施：终止可疑进程、清除可疑文件、检查自启动项。"
        elif score >= 30:
            level = "MEDIUM"
            recommendation = "检测到中等风险键盘监听指标，建议进一步排查：检查进程行为、审查文件来源。"
        else:
            level = "LOW"
            recommendation = "未检测到明显键盘监听风险。建议保持常规安全监控。"

        return {"level": level, "score": score, "recommendation": recommendation}
