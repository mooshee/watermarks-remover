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

## Mach-O executable inspection

Thin 32/64-bit and universal (fat32/fat64) Mach-O executable bytes now select a
separate bounded inspector before any filename/text routing. `/inspect`, `/clean`
and their batch forms report `kind: executable`.
`cleaning_modes.mach_o_executable_inspection` advertises this support. Existing
native clients can use `--inspect` without pretending a binary is text. Executable
`/clean` is always deterministic and returns the exact input bytes only when no
finding requires review. `requires_review` omits `cleaned` and blocks client
output and backup writes. The service never
formats, rewrites, executes, disassembles, re-signs or edits the program.

The inspector checks executable headers, known CPU/header width, fat slice tables,
alignment and non-overlap, load-command extents and singleton families, segments,
sections, explicit supported section types and named attribute bits from Apple's
`loader.h`, symbol/link-edit ranges and bounded functional load strings. Unknown
section types or attribute bits require review even with a conventional name
such as `__text`; DTrace DOF metadata remains unsupported. A dylib
path is functional metadata, not prose: it is validated in its load-command
context and preserved, even when its text resembles an AI label. Ordinary code,
constants and string data are not decoded or passed to text detectors. Unknown
commands, unrecognized segment/section metadata and embedded plist/LLVM metadata
remain `requires_review`, not confirmed AI provenance. Uncovered file ranges,
link-edit data and internal signature gaps must be zero padding; nonzero unknown
bytes and malformed structures are errors. No magic-only or unknown-format clean
path exists.

Supported embedded signatures must have bounded, non-overlapping SuperBlob
CodeDirectories using recognized versions and hash algorithms. Code page hashes
must match all pre-signature bytes. CMS, entitlements, requirements, special-slot
external metadata, scatter/pre-encrypted/linkage data and unknown signature
children are not supported and block inspection rather than being certified
opaque. Unsigned executables may be structurally inspected, but no signature is
invented. Presence and page hashes do not establish signer trust or authenticity.

Limits: 256 MiB per artifact, 32 architectures, 4,096 load commands and sections
per slice, 16 MiB of load commands per slice, 32 MiB of signature data per slice,
64 signature children, 262,144 code hash slots and 4,096 bytes per functional
metadata string. Unsupported structures fail closed. The no-change receipt
includes identical SHA-256 hashes, `changed: false`, `actions: []` and explicit
scope limits. `release_ready` only means no unresolved finding within this
supported structural/metadata scope; it does not assert semantic code analysis,
malware safety, signature trust, external-resource inspection, universal watermark
absence or authorship. Normal tests, review and deployment authorization remain
required. Prose and media handling are unchanged.

Format definitions are checked against Apple's primary `mach-o/loader.h`,
`mach-o/fat.h`, `mach/machine.h` and `kern/cs_blobs.h` headers, including the local
Xcode SDK and [Apple's published source](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h).

The Rust client in Hallman Platform exposes `--deterministic-only` and
`--metadata-only` (`also_layer_a_text=false`). It confirms the mode and hashes
before writes. The existing prose and media branches keep their established
behavior; meaning-changing prose, pixel and audio changes retain their own task
scope. These checks cannot prove human authorship or universal watermark absence.
For either executable format, the tested installed client refuses review results
before displaying their report and says `service response did not include cleaned
bytes`; use `/inspect` to retain those findings. Output and backup writes remain
blocked. Successful no-change output is unaffected.

The service retains the existing Python runtime because the vendor's format
parsers and optional media/ML tools use it. This local adaptation is not a Rust
rewrite. The native Rust client and supervisor remain separate from that parser
runtime.

The operational fork release branch is `vendor/v0.7.0-local`, pinned to the
actually installed vendor base `321d93d`. The fork's upstream-tracking `main`
remains unchanged; this release does not silently upgrade the vendor package.
The shared installed skill-description wording is preserved.

## ELF executable inspection

`cleaning_modes.elf64_amd64_executable_inspection` advertises a separate read-only
path for ELF64 little-endian AMD64 `ET_EXEC` and `ET_DYN` executables. Magic-byte
routing selects it before filenames for `/inspect`, `/clean` and their batch
forms, including requests from existing native clients. Valid supported bytes
return `kind: executable`, deterministic mode, `inspected_no_change`, identical
SHA-256 values, `changed: false` and `actions: []`. An ELF `requires_review`
response omits `cleaned`; the native client must not write output or a backup.
The executable review-response/client limitation described above also applies.

Inspection validates header versions, class, byte order, AMD64 identity, ABI,
sizes and bounded program/section tables; load ordering, ranges, address/file
alignment, entry coverage and non-overlap; section names, string-table ranges,
symbol/dynamic string references and complete fixed-size entries; and note
owner/descriptor extents, terminators, padding and alignment. Nonzero bytes
outside sections and header tables are rejected. Complete section and name
tables are required; extended numbering, compressed sections and unsupported
architectures/encodings fail closed. Unknown program/section metadata, note
owners/types and GNU property types require review.

GNU build IDs, ABI tags, supported GNU properties, compiler comment strings,
GNU linker retention flags and ordinary runtime/linker metadata remain intact.
Explicit provenance section names, note owners, textual unknown-note descriptors
and compiler-comment metadata require review. Functional `.text.*`/`.data.*`
section names and symbol strings are not treated as provenance. Code, constants,
string data, debug payloads and functional linker paths are not searched as prose
or passed to Unicode/model/detector backends. Nothing is removed or modified.

Limits: 256 MiB per artifact; 4,096 program headers, sections, notes and GNU
properties per descriptor and compiler-comment strings; 16 MiB total section metadata and 16 MiB program-note
inspection; 4,096 bytes per inspected metadata/functional string; 1,048,576
symbol/dynamic entries. Unclassified metadata blocks output. A successful result
is bounded structural/metadata evidence, not semantic program validation,
signature trust, malware safety, external-resource inspection, universal watermark
absence or an authorship claim.

Definitions: [System V ELF ABI](https://gabi.xinuos.com/elf/),
[Linux ELF headers](https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h)
and [GNU C Library ELF definitions](https://github.com/bminor/glibc/blob/master/elf/elf.h).
The service keeps its vendor Python runtime; the operator client remains Rust.

Validation on the configured Python 3.12 runtime: 112 focused cases pass; the
full suite has 1,224 passes, two optional skips and four pre-existing media
failures. The same four failures reproduce on unchanged vendor base because the
host ffmpeg cannot load `libx265.216.dylib`. No media pipeline or host library is
changed by this release. All 102 Python files pass Ruff lint and format checks.

The first fork CI run also found 24 existing advisories in optional Pillow
12.3.0. The scorer, MarkLLM and CtrlRegen pins now consistently use Pillow 13.0.0;
the audited scorer requirements resolve and `pip-audit` reports no known
vulnerabilities. The optional Docker bases use Python 3.11 or 3.14, compatible
with the [Pillow 13 release](https://pillow.readthedocs.io/en/stable/releasenotes/13.0.0.html).
This does not enable an optional model backend or replace the installed core
service's Python 3.12 runtime.

The actual Pillow 13 install passed 106 affected image/container/scorer and
research-adapter tests, including `fromarray/open/convert/load` plus a metadata
strip with exact restored RGB pixels. That acceptance runs in a named child
fixture so importing real Pillow cannot pollute the research backends' fake-PIL
test fixtures. No model backend was loaded or downloaded.

Actual pre-deployment HTTP checks with the native client returned
`inspected_no_change` for the previously blocked dashboard JavaScript and the
hosted French HTML. Their original SHA-256 values were preserved. The older
installed client also passed against the new automatic source mode. A malformed
CSS string before valid icon rules is handled using CSS newline recovery; glyphs
inside malformed declarations remain unresolved.

CodeQL's two review findings identified potentially expensive whitespace regex
matching in font/content values. Those regexes were replaced with linear literal
value parsing; an actual 400,000-space declaration regression passes. The
reviewed metadata and byte-preservation behavior stays the same.
