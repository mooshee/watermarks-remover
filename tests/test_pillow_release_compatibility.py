"""Exercise the actual optional Pillow pin without loading a model backend.

Author: Daniel Hallman
"""

from __future__ import annotations

import importlib.metadata
import subprocess
import sys
from pathlib import Path

import pytest


def test_pillow13_model_input_apis_and_metadata_roundtrip(tmp_path):
    try:
        version = importlib.metadata.version("Pillow")
        importlib.metadata.version("numpy")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("optional Pillow/numpy pin is not installed")
    if version != "13.0.0":
        pytest.skip("optional Pillow 13 pin is not installed")
    # Some research-backend tests intentionally install fake PIL modules. Keep
    # this actual-library acceptance isolated, without polluting those fixtures.
    fixture = Path(__file__).parent / "fixtures" / "pillow_release_compatibility.py"
    result = subprocess.run(
        [sys.executable, str(fixture), str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
