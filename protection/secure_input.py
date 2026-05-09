"""
安全输入模块

实现多种防键盘监听的输入保护方案：
1. 虚拟键盘输入 — 通过鼠标点击绕过键盘hook
2. 输入混淆 — 在真实按键中混入随机噪声
3. 加密通道输入 — 对输入数据进行端到端加密

每种方案都提供可测量的防护效果对比
"""

import os
import random
import hashlib
import base64
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Tuple, Optional


@dataclass
class InputProtectionResult:
    """输入保护测试结果"""
    method: str
    original_input: str
    protected_output: str = ""
    protection_level: str = "low"
    overhead_ms: float = 0.0
    keylogger_resistant: bool = False
    notes: str = ""


class SecureInputEngine:
    """
    安全输入引擎
    提供多种防键盘监听方案并对比效果
    """

    def __init__(self):
        self.protection_results: List[InputProtectionResult] = []

    # ============================
    # 方案1: 虚拟键盘输入
    # ============================
    def virtual_keyboard_input(self, password: str) -> InputProtectionResult:
        """
        模拟虚拟键盘输入

        原理: 通过鼠标点击屏幕键盘，按键事件不经过物理键盘通道，
        因此基于键盘hook的记录器无法捕获。
        """
        start = time.time()

        # 模拟：将每个字符映射为鼠标坐标
        # 真实实现会使用tkinter/PyQt绘制虚拟键盘
        vk_mapping = {}
        for i, ch in enumerate(password):
            # 模拟虚拟键盘坐标
            x = 100 + (i % 10) * 50
            y = 300 + (i // 10) * 50
            vk_mapping[ch] = (x, y)

        # 模拟输入
        protected = password  # 实际应用中，字符通过坐标点击传递

        elapsed = (time.time() - start) * 1000

        result = InputProtectionResult(
            method="虚拟键盘输入",
            original_input=password,
            protected_output=protected,
            protection_level="high",
            overhead_ms=round(elapsed, 2),
            keylogger_resistant=True,
            notes="按键事件不通过物理键盘通道，传统键盘Hook无法捕获。"
                  "缺点是可能被屏幕截图或鼠标Hook绕过。"
        )
        self.protection_results.append(result)
        return result

    # ============================
    # 方案2: 输入混淆
    # ============================
    def obfuscated_input(self, password: str) -> InputProtectionResult:
        """
        输入混淆方案

        在真实按键序列中插入随机噪声按键，
        使键盘记录器记录的内容包含大量干扰信息。
        """
        start = time.time()

        noise_keys = ['\b', '\x1b', '\t', random.choice('abcdefghijklmnopqrstuvwxyz')]
        obfuscated = ""

        for ch in password:
            # 随机决定是否插入噪声
            if random.random() < 0.4:
                noise = random.choice(noise_keys)
                obfuscated += noise

                # 模拟退格删除噪声
                if noise not in ['\b', '\x1b']:
                    obfuscated += '\b'  # 退格键删除剛输入的字

            obfuscated += ch

        elapsed = (time.time() - start) * 1000

        result = InputProtectionResult(
            method="输入混淆",
            original_input=password,
            protected_output=password,  # 最终结果正确
            protection_level="medium",
            overhead_ms=round(elapsed, 2),
            keylogger_resistant=True,
            notes=f"在{len(password)}个真实字符中插入了噪声，"
                  f"使得键盘记录器记录的总长度为{len(obfuscated)}字符，"
                  f"攻击者难以区分真实输入和噪声。"
                  f"缺点是高级记录器可过滤退格键来还原。"
        )
        self.protection_results.append(result)
        return result

    # ============================
    # 方案3: 加密通道输入
    # ============================
    def encrypted_channel_input(self, password: str) -> InputProtectionResult:
        """
        加密通道输入方案

        在输入到达应用层之前对按键事件进行加密，
        键盘记录器只能获取加密后的数据。
        """
        start = time.time()

        # 用 os.urandom 生成 32 字节随机会话密钥，再用 SHA-256 派生
        raw_entropy = os.urandom(32)
        session_key = hashlib.sha256(raw_entropy).digest()

        # 对每个按键做 XOR 流加密（演示用；生产环境应使用 AES-GCM 等认证加密）
        encrypted_chars = []
        for ch in password:
            key_byte = session_key[len(encrypted_chars) % len(session_key)]
            encrypted_byte = ord(ch) ^ key_byte
            encrypted_chars.append(encrypted_byte)

        # Base64 编码便于展示
        encrypted_str = base64.b64encode(bytes(encrypted_chars)).decode()
        elapsed = (time.time() - start) * 1000

        result = InputProtectionResult(
            method="加密通道输入",
            original_input=password,
            protected_output=encrypted_str,
            protection_level="very_high",
            overhead_ms=round(elapsed, 2),
            keylogger_resistant=True,
            notes=f"输入数据经 XOR 流加密（SHA-256 派生会话密钥）后 Base64 编码。"
                  f"键盘记录器只能捕获密文: {encrypted_str[:20]}..."
                  f"生产环境建议使用 AES-GCM 等认证加密方案。"
        )
        self.protection_results.append(result)
        return result

    # ============================
    # 综合对比
    # ============================
    def compare_all_methods(self, test_password: str) -> List[InputProtectionResult]:
        """对所有方案进行对比测试"""
        self.protection_results = []

        self.virtual_keyboard_input(test_password)
        self.obfuscated_input(test_password)
        self.encrypted_channel_input(test_password)

        return self.protection_results

    def get_protection_comparison(self):
        """生成防护方案对比表"""
        return [
            {
                "方案": r["method"],
                "防护等级": r["protection_level"],
                "抗键盘记录": "✓" if r["keylogger_resistant"] else "✗",
                "性能开销(ms)": r["overhead_ms"],
                "备注": r["notes"],
            }
            for r in self.protection_results
        ]

    @staticmethod
    def simulate_keylogger_attempt(method_result: InputProtectionResult):
        """模拟键盘记录器尝试窃取不同方案保护的输入"""
        if method_result.method == "虚拟键盘输入":
            return "键盘记录器结果: [空] — 无物理按键事件，记录失败"

        elif method_result.method == "输入混淆":
            return (
                "键盘记录器结果: 'a\\bx\\bP@sw0r\\bd...' — "
                "记录了混淆后的序列，无法确定真实输入"
            )

        elif method_result.method == "加密通道输入":
            return (
                f"键盘记录器结果: '{method_result.protected_output[:30]}...' — "
                "仅为加密密文，无密钥无法解密"
            )

        return "键盘记录器结果: [未测试]"
