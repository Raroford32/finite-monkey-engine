"""
漏洞扫描工具模块

此模块包含漏洞扫描所需的各种工具函数
"""

from .dialogue_manager import DialogueHistory
from .scan_utils import ScanUtils

__all__ = ['DialogueHistory', 'ScanUtils'] 