#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USP Controller - Compatibility Wrapper
Forwards execution to the modular usp_main CLI entry point.
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent))

from usp_main import main

if __name__ == "__main__":
    sys.exit(main())
