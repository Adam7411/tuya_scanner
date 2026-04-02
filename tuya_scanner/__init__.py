"""Tuya Scanner - Discover Tuya smart devices on your local network."""

from .scanner import TuyaScanner
from .device import TuyaDevice

__version__ = "1.0.0"
__all__ = ["TuyaScanner", "TuyaDevice"]
