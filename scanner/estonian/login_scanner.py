"""Thin proxy to keep backwards-compatibility while we move
Estonian-specific logic into its own sub-package."""
from ..estonian_login_scanner import EstonianLoginScanner as _ELS  # type: ignore

EstonianLoginScanner = _ELS

__all__ = ["EstonianLoginScanner"] 