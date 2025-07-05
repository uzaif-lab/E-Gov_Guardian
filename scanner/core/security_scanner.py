"""Core wrapper that re-exports SecurityScanner from the original module.

Keeping this thin proxy lets us gradually refactor the real implementation
out of *scanner.main_scanner* without breaking existing imports.
"""
from ..main_scanner import SecurityScanner as _SecurityScanner  # type: ignore

# Public re-export
SecurityScanner = _SecurityScanner

__all__ = ["SecurityScanner"] 