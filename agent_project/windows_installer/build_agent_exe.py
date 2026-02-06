#!/usr/bin/env python3
"""
Build SecretSnipe Agent as a standalone Windows executable.
Uses PyInstaller to create a single .exe that doesn't require Python installed.

Run this on a Windows machine with PyInstaller installed:
    pip install pyinstaller
    python build_agent_exe.py
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

AGENT_SCRIPT = "secretsnipe_enterprise_agent.py"
OUTPUT_NAME = "SecretSnipeAgent"
ICON_FILE = None  # Optional: path to .ico file

def build_exe():
    """Build the standalone executable"""
    
    script_dir = Path(__file__).parent
    agent_path = script_dir / AGENT_SCRIPT
    
    if not agent_path.exists():
        print(f"ERROR: Agent script not found: {agent_path}")
        sys.exit(1)
    
    print("=" * 60)
    print("  SecretSnipe Agent Executable Builder")
    print("=" * 60)
    print()
    
    # PyInstaller command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",           # Single executable
        "--console",           # Console application (for service)
        "--clean",             # Clean build
        f"--name={OUTPUT_NAME}",
        "--noconfirm",         # Don't ask for confirmation
        
        # Hidden imports that might be needed
        "--hidden-import=requests",
        "--hidden-import=json",
        "--hidden-import=logging",
        "--hidden-import=threading",
        "--hidden-import=socket",
        "--hidden-import=hashlib",
        "--hidden-import=platform",
        "--hidden-import=subprocess",
        "--hidden-import=re",
        "--hidden-import=pathlib",
        "--hidden-import=datetime",
        "--hidden-import=dataclasses",
        "--hidden-import=concurrent.futures",
        "--hidden-import=ctypes",
        "--hidden-import=winreg",
        
        str(agent_path)
    ]
    
    if ICON_FILE and Path(ICON_FILE).exists():
        cmd.insert(-1, f"--icon={ICON_FILE}")
    
    print(f"Building {OUTPUT_NAME}.exe...")
    print(f"Command: {' '.join(cmd)}")
    print()
    
    result = subprocess.run(cmd, cwd=script_dir)
    
    if result.returncode != 0:
        print(f"\nERROR: Build failed with code {result.returncode}")
        sys.exit(1)
    
    # Output location
    dist_dir = script_dir / "dist"
    exe_path = dist_dir / f"{OUTPUT_NAME}.exe"
    
    if exe_path.exists():
        print()
        print("=" * 60)
        print(f"  SUCCESS! Executable built: {exe_path}")
        print(f"  Size: {exe_path.stat().st_size / 1024 / 1024:.2f} MB")
        print("=" * 60)
        print()
        print("Next steps:")
        print(f"  1. Copy {exe_path} to your target Windows servers")
        print("  2. Run the installer with -AgentExePath parameter")
        print()
    else:
        print(f"\nERROR: Expected output not found: {exe_path}")
        sys.exit(1)

if __name__ == "__main__":
    build_exe()
