"""
VortexL2 Port Forward Management

Uses HAProxy for high-performance production-grade port forwarding.
This module provides compatibility with the existing interface.
"""

from __future__ import annotations

# Import HAProxy manager as the primary implementation
from vortexl2.haproxy_manager import HAProxyManager

# For backward compatibility
ForwardManager = HAProxyManager
