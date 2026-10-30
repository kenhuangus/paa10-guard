#!/usr/bin/env python3
"""Run paa-guard from a checkout or plugin folder without installing it (used by the plugin hook and MCP config)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from paa_guard.cli import main  # noqa: E402

sys.exit(main())
