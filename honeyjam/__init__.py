"""HoneyJam - Windows Registry forensics toolkit.

A spiritual successor to RegRipper, built on top of the ``regipy`` parser.
"""

__version__ = "0.1.0"
__author__ = "sltcnb"

from honeyjam.models import Finding, PluginResult, Severity

__all__ = ["Finding", "PluginResult", "Severity", "__version__"]
