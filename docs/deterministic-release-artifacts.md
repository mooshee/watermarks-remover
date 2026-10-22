# Deterministic release artifacts

Author: Daniel Hallman

The local fork adds `options.deterministic_only=true` to `/clean` and `/clean/batch`.
Recognized source/configuration/data extensions and HTML select this path
automatically, including requests from an older client. Use the explicit option
for pinned Markdown or plain text. `/capabilities` advertises support under
`cleaning_modes.deterministic_only`.

This path performs strict UTF-8 and binary checks, deterministic Unicode and
format-specific metadata inspection, and no model, detector, formatter or
normalization calls. Unicode findings in source are retained for a narrow source
fix and normal tests/review. It never guesses whether a source string is safe
to change.

HTML cleanup removes only actual AI/provenance `<meta>` elements identified by
the parser and exact source spans. It never serializes the page or edits tags
inside JavaScript strings. Other provenance-like constructs remain unresolved
for review. Font Awesome U+F078/U+F0C9 are preserved only in actual CSS `content`
declarations with an explicit matching font family. Unclassified private-use
characters elsewhere remain unresolved.

The response includes exact input/output SHA-256 values, before/after inspection,
actions, functional glyph context, `changed`, `review_required` and one status:

| Status | Meaning |
| --- | --- |
| `inspected_no_change` | No applicable finding; exact original bytes returned. Publish those reviewed bytes with the receipt. |
| `cleaned` | Narrow metadata edits changed bytes. Diff, affected tests and review are required before pinning/publication. |
| `requires_review` | An applicable finding remains. The native client refuses output/backup writes; fix the source and inspect again. |

`release_ready` means no unresolved deterministic finding; it never substitutes
for tests/review of changed bytes or normal publication authorization. Unknown
formats, invalid UTF-8 and inspection errors are errors, not clean results.
Unsupported packages need a supported format-specific inspector; do not rename
a binary or assert blanket package coverage.

The Rust client in Hallman Platform exposes `--deterministic-only` and
`--metadata-only` (`also_layer_a_text=false`). It confirms the mode and hashes
before writes. The existing prose and media branches keep their established
behavior; meaning-changing prose, pixel and audio changes retain their own task
scope. These checks cannot prove human authorship or universal watermark absence.

The service retains the existing Python runtime because the vendor's format
parsers and optional media/ML tools use it. This local adaptation is not a Rust
rewrite. The native Rust client and supervisor remain separate from that parser
runtime.
