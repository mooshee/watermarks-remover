"""Exercise the actual optional Pillow pin without loading a model backend.

Author: Daniel Hallman
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PIL = pytest.importorskip("PIL")
Image = pytest.importorskip("PIL.Image")
PngImagePlugin = pytest.importorskip("PIL.PngImagePlugin")
np = pytest.importorskip("numpy")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service" / "scripts"))

from image_meta import clean_image, inspect_image


@pytest.mark.skipif(
    getattr(PIL, "__version__", None) != "13.0.0", reason="optional Pillow 13 pin is not installed"
)
def test_pillow13_model_input_apis_and_metadata_roundtrip(tmp_path):
    # Same stable APIs the optional adapters use: fromarray/open/convert/load.
    pixels = np.zeros((8, 8, 3), dtype=np.uint8)
    pixels[:, :, 0] = 123
    original = Image.fromarray(pixels).convert("RGB")
    source = tmp_path / "input.png"
    cleaned = tmp_path / "output.png"
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Software", "OpenAI")
    original.save(source, pnginfo=metadata)
    assert inspect_image(source).has_ai_metadata
    result = clean_image(source, cleaned)
    assert not result["still_has_ai_metadata"]
    with Image.open(cleaned) as reopened:
        restored = reopened.convert("RGB")
        restored.load()
        assert restored.size == (8, 8)
        assert restored.tobytes() == original.tobytes()
