# Watermarks remover local release adaptation

Author: Daniel Hallman

The installed service uses its existing Python stdlib HTTP runtime and Python
format-specific parsers; keep this required vendor runtime rather than adding a
parallel service for one release path. The operator CLI remains Rust.

Release artifacts use deterministic inspection with exact byte preservation when
no applicable finding exists. Never format, paraphrase or call a rewrite backend
for source code, configuration, structured data, generated bundles or release
HTML. Unknown formats and failed inspection block that artifact. Preserve
functional font glyphs only when their CSS content and font context are verified.
An actual source finding requires a narrow source fix and affected tests/review.
Any metadata edit requires a diff and affected checks/review before publication.

Use the existing pytest and Ruff checks. Preserve user-owned local skill wording
when updating the installed canonical checkout. Do not change prose or media
rewrite behavior as part of a release-artifact adjustment.
