#!/usr/bin/env python3
"""AD-Enum operator launcher; uses the project environment when installed."""
import os
from pathlib import Path
import sys

venv_python = Path(__file__).with_name(".venv") / "bin" / "python"
if venv_python.exists() and sys.prefix == sys.base_prefix:
    os.execv(str(venv_python), [str(venv_python), __file__, *sys.argv[1:]])

from ad_enum.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
