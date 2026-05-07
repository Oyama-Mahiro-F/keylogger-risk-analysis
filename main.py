#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
键盘监听风险机理分析与防护验证系统 — 主程序

============================================================
  课程: 信息安全编程技术与实例开发
  题目: 键盘监听风险机理分析与防护验证程序
============================================================

运行流程:
  1. [风险模拟] 启动键盘hook模拟，展示记录机理
  2. [检测识别] 执行多维检测，输出风险评分
  3. [防护验证] 测试三种防护方案的效果
  4. [结果汇总] 生成完整的风险分析报告
"""

import sys
import io
import os
import time
import json
from datetime import datetime
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from risk_simulation.key_hook import (
    KeyboardHookSimulator,
    cleanup_hook_artifacts,
    simulate_hook_api_calls,
    get_simulated_hook_signature,
    KNOWN_KEYLOGGER_SIGNATURES,
)
from risk_simulation.logger import SmartKeyLogger, SENSITIVE_PATTERNS
from detection.hook_detector import HookDetector
from detection.process_scanner import ProcessScanner
from detection.risk_scorer import RiskScorer
from protection.anti_hook import AntiHookProtection
from protection.secure_input import SecureInputEngine


def print_banner():
    """打印系统标题"""
    banner = r"""
╔══════════════════════════════════════════════════════════════╗
║     键盘监听风险机理分析与防护验证系统                          ║
║     Keylogger Risk Mechanism Analysis & Protection System    ║
║     信息安全编程技术与实例开发 · 平时作业                       ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_section(title):
    """打印章节标题"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def run_risk_simulation(duration=5):
    """
    第一阶段: 风险模拟
    展示键盘hook如何工作
    """
    print_section("第一阶段：风险机理模拟")

    # 展示已知的键盘记录API签名
    print("\n[1.1] 已知键盘Hook相关API签名:")
    print("-" * 40)
    for sig, desc in KNOWN_KEYLOGGER_SIGNATURES.items():
        print(f"  • {sig}")
        print(f"    └─ {desc}")

    # 展示API调用链
    print("\n[1.2] 模拟恶意程序API调用链:")
    print("-" * 40)
    call_chain = simulate_hook_api_calls()
    for dll, api, param in call_chain:
        print(f"  [{dll}] {api}({param})")

    # 展示Hook行为特征
    print("\n[1.3] 键盘Hook行为特征签名:")
    print("-" * 40)
    sig = get_simulated_hook_signature()
    print(f"  Hook类型: {sig['hook_type']}")
    print(f"  核心DLL:  {sig['dll_name']}")
    print(f"  相关API:  {', '.join(sig['api_calls'][:4])}")
    print(f"  文件特征: {', '.join(sig['file_indicators'][:3])}")
    print(f"  注册表:   {sig['registry_keys'][0]}")

    # 启动键盘Hook模拟 (短暂运行)
    print(f"\n[1.4] 启动键盘Hook模拟 ({duration}秒)...")
    print("  [!] 模拟键盘监听中，请勿输入敏感信息...")
    print("  [!] 此时任何键盘输入都可能被记录")

    hook = KeyboardHookSimulator(stealth_mode=True)
    hook.start(duration=duration)

    # 等待模拟完成
    time.sleep(duration + 1)
    hook.stop()

    stats = hook.get_stats()
    if stats:
        print(f"\n[1.5] 键盘Hook运行统计:")
        print(f"  运行时长: {stats['duration_seconds']} 秒")
        print(f"  捕获按键: {stats['keys_captured']} 次")
        print(f"  按键速率: {stats['keys_per_second']} 次/秒")
        print(f"  日志路径: {stats['log_path']}")
        print(f"  隐蔽模式: {'启用' if stats['stealth_mode'] else '关闭'}")

    # 检查是否真实记录了按键
    log_file = Path.home() / ".sys_cache" / ".idx.dat"
    if log_file.exists():
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            print(f"\n  日志文件内容 (最近5条):")
            for line in lines[-5:]:
                entry = json.loads(line)
                print(f"    [{entry['timestamp']}] 按键: {entry['key']}")

    return hook, stats


def run_detection():
    """
    第二阶段: 检测识别
    执行多维检测和风险评分
    """
    print_section("第二阶段：风险检测与评分")

    # Hook检测
    print("\n[2.1] Hook检测器扫描...")
    print("-" * 40)
    detector = HookDetector()
    hook_report = detector.scan_all()

    print(f"  扫描时间: {hook_report['scan_time']}")
    print(f"  发现问题: {hook_report['total_findings']} 个")
    print(f"  风险等级: {hook_report['risk_level']}")
    print(f"  风险评分: {hook_report['risk_score']}/100")
    for indicator in hook_report['risk_indicators']:
        print(f"  [→] {indicator}")

    # 进程扫描
    print("\n[2.2] 进程扫描器分析...")
    print("-" * 40)
    scanner = ProcessScanner()
    proc_report = scanner.scan()

    print(f"  扫描进程: {proc_report['total_processes']} 个")
    print(f"  可疑进程: {proc_report['suspicious_count']} 个")
    print(f"  高风险: {proc_report['summary']['high_risk_count']}")
    print(f"  中风险: {proc_report['summary']['medium_risk_count']}")
    print(f"  低风险: {proc_report['summary']['low_risk_count']}")

    if proc_report['high_risk']:
        print(f"\n  [!] 高风险进程详情:")
        for proc in proc_report['high_risk']:
            print(f"    PID {proc['pid']} - {proc['name']}")
            print(f"    路径: {proc['exe_path']}")
            print(f"    风险分: {proc['risk_score']}")
            for factor in proc['risk_factors']:
                print(f"      • {factor}")

    # 风险评分
    print("\n[2.3] 综合风险评分...")
    print("-" * 40)
    scorer = RiskScorer()

    # 构造评分输入
    file_findings = [
        {"description": "存在隐蔽按键日志文件", "severity": "high"},
        {"description": "日志存储在伪装系统目录", "severity": "high"},
        {"description": "日志文件近期被写入", "severity": "medium"},
    ]

    process_findings = [
        {"description": "进程导入了键盘Hook API", "severity": "high"},
        {"description": "频繁调用GetAsyncKeyState", "severity": "medium"},
        {"description": "进程伪装为系统进程", "severity": "high"},
    ]

    persistence_findings = [
        {"description": "注册了Run自启动项", "severity": "high"},
        {"description": "修改了启动文件夹", "severity": "medium"},
    ]

    api_findings = [
        {"description": "检测到WH_KEYBOARD_LL钩子", "severity": "high"},
        {"description": "检测到GetAsyncKeyState轮询", "severity": "medium"},
    ]

    risk_report = scorer.evaluate(
        file_findings=file_findings,
        process_findings=process_findings,
        persistence_findings=persistence_findings,
        api_findings=api_findings,
    )

    print(f"  综合风险评分: {risk_report['total_score']}/100")
    print(f"  风险等级: {risk_report['risk_level']}")
    print(f"  风险量图: [{risk_report['risk_bar']}]")

    print(f"\n  各维度评分:")
    for dim, info in risk_report['dimension_scores'].items():
        bar = "█" * int(info['score'] / 10) + "░" * (10 - int(info['score'] / 10))
        print(f"    {dim} ({info['weight']}): {info['score']}/100 [{bar}]")

    print(f"\n  处理建议:")
    print(f"  {risk_report['recommendation']}")

    return hook_report, proc_report, risk_report


def run_protection():
    """
    第三阶段: 防护验证
    测试三种输入保护方案
    """
    print_section("第三阶段：防护方案验证")

    test_password = "MyP@ssw0rd2024!"

    # 反Hook防护
    print("\n[3.1] 反Hook防护引擎...")
    print("-" * 40)
    protection = AntiHookProtection()

    result = protection.enable_protection()
    print(f"  防护状态: {result['status']}")
    for p in result['protections']:
        print(f"    {p}")

    # 模拟检测到Hook
    warning = protection.detect_hook_attempt()
    print(f"\n  [!] 检测到Hook尝试:")
    print(f"    时间: {warning['timestamp']}")
    print(f"    类型: {warning['type']}")
    print(f"    操作: {warning['action_taken']}")

    status = protection.get_protection_status()
    print(f"\n  防护统计:")
    print(f"    Hook阻止次数: {status['hook_attempts_blocked']}")
    print(f"    告警总数: {status['total_warnings']}")

    # 安全输入方案对比
    print(f"\n[3.2] 安全输入方案对比 (测试密码: {test_password})")
    print("-" * 40)

    engine = SecureInputEngine()
    results = engine.compare_all_methods(test_password)

    for result in results:
        print(f"\n  方案: {result.method}")
        print(f"  防护等级: {result.protection_level}")
        print(f"  性能开销: {result.overhead_ms}ms")
        print(f"  抗键盘记录: {'✓ 是' if result.keylogger_resistant else '✗ 否'}")
        print(f"  说明: {result.notes[:80]}...")
        # 模拟键盘记录器尝试
        attempt = engine.simulate_keylogger_attempt(result)
        print(f"  {attempt}")

    # 防护建议
    print(f"\n[3.3] 防护最佳实践建议:")
    print("-" * 40)
    report = AntiHookProtection.generate_protection_report()
    for i, practice in enumerate(report['best_practices'], 1):
        print(f"  {i}. {practice}")

    return protection, engine, results


def generate_final_report(sim_stats, detection_results, protection_results):
    """生成最终汇总报告"""
    print_section("最终汇总报告")

    hook_report, proc_report, risk_report = detection_results
    protection, engine, prot_results = protection_results

    report = {
        "report_metadata": {
            "title": "键盘监听风险机理分析与防护验证报告",
            "course": "信息安全编程技术与实例开发",
            "generated_at": datetime.now().isoformat(),
            "version": "1.0",
        },
        "risk_simulation": {
            "hook_api_signatures": list(KNOWN_KEYLOGGER_SIGNATURES.keys()),
            "simulation_stats": sim_stats,
        },
        "detection": {
            "hook_detection": {
                "findings": hook_report["total_findings"],
                "risk_level": hook_report["risk_level"],
                "risk_score": hook_report["risk_score"],
            },
            "process_scan": {
                "total": proc_report["total_processes"],
                "suspicious": proc_report["suspicious_count"],
                "high_risk": proc_report["summary"]["high_risk_count"],
            },
            "risk_scoring": {
                "total_score": risk_report["total_score"],
                "risk_level": risk_report["risk_level"],
                "dimensions": risk_report["dimension_scores"],
            },
        },
        "protection": {
            "anti_hook": protection.get_protection_status(),
            "secure_input_methods": [
                {
                    "method": r.method,
                    "protection_level": r.protection_level,
                    "resistant": r.keylogger_resistant,
                    "overhead_ms": r.overhead_ms,
                }
                for r in prot_results
            ],
            "best_practices": AntiHookProtection.generate_protection_report()["best_practices"],
        },
    }

    # 导出报告
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"risk_analysis_report_{timestamp}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)

    print(f"\n  完整报告已保存至: {report_path}")
    print(f"  报告大小: {os.path.getsize(report_path)} bytes")

    # 摘要
    print(f"\n{'─'*60}")
    print(f"  综合风险等级: {risk_report['risk_level']}")
    print(f"  综合风险得分: {risk_report['total_score']}/100")
    print(f"  检测问题总数: {hook_report['total_findings'] + proc_report['suspicious_count']}")
    print(f"  防护方案数:   {len(prot_results)}")
    print(f"  防护建议数:   {len(AntiHookProtection.generate_protection_report()['best_practices'])}")
    print(f"{'─'*60}")

    return report


def main():
    """主函数"""
    print_banner()

    print("\n[系统初始化] ", end="")
    print("检查依赖...", end=" ")

    # 检查pynput
    try:
        import pynput
        print("pynput [OK]", end=" ")
    except ImportError:
        print("pynput [X] (部分功能将以模拟模式运行)", end=" ")

    # 检查psutil
    try:
        import psutil
        print("psutil [OK]", end=" ")
    except ImportError:
        print("psutil [X] (进程扫描将以模拟模式运行)", end=" ")

    print()

    # ========================================
    # 第一阶段: 风险模拟
    # ========================================
    hook, sim_stats = run_risk_simulation(duration=3)

    # ========================================
    # 第二阶段: 检测识别
    # ========================================
    detection_results = run_detection()

    # ========================================
    # 第三阶段: 防护验证
    # ========================================
    protection_results = run_protection()

    # ========================================
    # 生成最终报告
    # ========================================
    final_report = generate_final_report(
        sim_stats,
        detection_results,
        protection_results,
    )

    print(f"\n{'='*60}")
    print(f"  系统运行完毕。")
    print(f"  所有结果已保存到 output/ 目录")
    print(f"{'='*60}\n")

    cleanup_hook_artifacts()
    return final_report


if __name__ == "__main__":
    main()
