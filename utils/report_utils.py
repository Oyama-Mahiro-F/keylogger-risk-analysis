"""
报告工具模块
提供日志格式化、结果导出等功能
"""

import json
import os
from datetime import datetime
from pathlib import Path


def format_bytes(bytes_val):
    """格式化字节数"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} TB"


def export_to_json(data, filepath):
    """导出数据为JSON"""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    return filepath


def export_to_txt(data, filepath):
    """导出数据为文本"""
    with open(filepath, 'w', encoding='utf-8') as f:
        if isinstance(data, dict):
            for key, val in data.items():
                f.write(f"{key}: {val}\n")
        elif isinstance(data, list):
            for item in data:
                f.write(f"{item}\n")
        else:
            f.write(str(data))
    return filepath


def generate_timestamp():
    """生成时间戳"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def create_output_dir(name="output"):
    """创建输出目录"""
    output_dir = Path(__file__).parent.parent / name
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir
