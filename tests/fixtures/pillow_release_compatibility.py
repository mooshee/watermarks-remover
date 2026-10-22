"""Actual optional Pillow acceptance fixture; no model imports or downloads.

Author: Daniel Hallman
"""

import sys
from pathlib import Path

import numpy as np
from PIL import Image, PngImagePlugin

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "service" / "scripts"))

from image_meta import clean_image, inspect_image

directory = Path(sys.argv[1])
pixels = np.zeros((8, 8, 3), dtype=np.uint8)
pixels[:, :, 0] = 123
original = Image.fromarray(pixels).convert("RGB")
source = directory / "input.png"
cleaned = directory / "output.png"
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
