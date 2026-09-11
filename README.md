# libdedsec

`libdedsec` (Deadly Security) is an API-only, pure C11 research prototype for
finding and experimentally decoding covert channels in plaintext, providing a
base for further research.

The name is taken from the Watch Dogs series. it reflects the urgency of getting AI security right before failures cause real harm (to put it very lightly). The library is developed with substantial agent assistance to quickly explore the attack space that agents can independently devise (as that's the attack model).

## Features

- Strict UTF-8 decoding with source-byte offsets; detection for malformed UTF-8, embedded NULs, BOMs, ISO-2022 designations, Unicode-17.0.0-pinned default-ignorable and bidi code points (including raw value/context observations), residual non-default-ignorable format controls, C1 control and non-ASCII whitespace property observations, standardized variation selectors (including a bounded Mongolian FVS lane), tags, noncharacters, iteration marks, and surface forms such as JSON escapes, URI percent escapes, RFC 2047, C trigraphs, and ANSI controls.
- Trial decoders for tag bytes, zero-width binary, variation-selector nibbles, bounded Mongolian FVS1/FVS2 bits, structurally gated bidi-isolate binary, bounded implicit-bidi LTR source-order records, ISO-2022 designations, generic trailing-EOL horizontal-whitespace widths, case, punctuation, parity, CESU-8 forms, Japanese iteration marks, fixed reviewed Unicode identity pairs (including canonical combining order), LF/CRLF/LINE-SEPARATOR representation lanes, Base64/Base32, Markdown unordered lists, Gemtext link separator representations, and conservative structural signals.
- Extensible modules, feature extraction and bit conversion, caller-defined code-point or token alphabets, bit-exact output with partial-byte retention, and transform-chain substring search with source-offset provenance.
- ABI-v5 retains the v4 detection callback kinds, which distinguish aggregate findings, non-bit raw
  property observations, and sub-threshold symbol observations. Parameter-free
  built-in lanes expose each candidate value, bit width, and raw byte span so
  callers can display provenance or conservatively glue selected
  non-overlapping lanes in source order.

## Build and test

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The project builds with `-std=c11 -pedantic -Wall -Wextra -Werror`. Tests cover generated carrier round trips, malformed UTF-8, and transformed search.

## Minimal API

```c
#include <dedsec.h>

dedsec_registry registry;
dedsec_registry_init(&registry);
if (dedsec_registry_add_builtins(&registry) != DEDSEC_OK) {
    /* handle allocation failure */
}

dedsec_view input = {bytes, byte_count};
dedsec_detect_all(&registry, input, on_finding, user_context);

dedsec_decode_request request = {"variation-nibbles", 0, NULL, 0};
dedsec_buffer candidate;
dedsec_buffer_init(&candidate);
dedsec_decode(&registry, "unicode", input, &request, &candidate);

/* Treat candidate as inert bytes; never execute it. */
dedsec_buffer_free(&candidate);
dedsec_registry_free(&registry);
```

Callbacks must inspect `finding.kind`. `DEDSEC_DETECTION_FINDING` is an
aggregate anomaly; `DEDSEC_DETECTION_OBSERVATION` is a zero-score, non-bit raw
property event; and `DEDSEC_DETECTION_SYMBOL` is a possible bit/nibble event
emitted even below the aggregate lane gate. A symbol is not independently an
alert. Collect reviewed symbol events, retain them for provenance, and pass a
non-overlapping caller-selected subset to
`dedsec_symbols_glue_source_order()`. See the
[composite-channel contract](docs/COMPOSITE_CHANNELS.md).

## Bit-exact decoding

`dedsec_decode()` returns only whole bytes. For forensic work use `dedsec_decode_bits()` and `dedsec_bitstream`; `bit_length` preserves a final partial byte, whose unused low bits are zero in storage. New modules should implement `decode_bits`; legacy `decode` modules are represented as whole-byte streams.

```c
dedsec_bitstream candidate;
dedsec_bitstream_init(&candidate);
dedsec_decode_bits(&registry, "unicode", input, &request, &candidate);
dedsec_bitstream_free(&candidate);
```

## Plaintext prefilter

`dedsec_bitstream_filter()` suppresses extracted streams that do not resemble
Latin-script plaintext. It recognizes literal UTF-8 plus up to two strict
Base16, Base32, Base32hex, Base64, or URL-safe Base64 layers. Non-degenerate
opaque byte streams—including ciphertext, compression, random noise, or an
EBCDIC byte stream lifted into Unicode—pass as `POSSIBLE` with
`DEDSEC_PLAINTEXT_OPAQUE_DATA`; the filter neither guesses nor decodes their
format, so carrier-side evidence remains essential. Promote
`DEDSEC_PLAINTEXT_LIKELY` for the conservative production path; reserve
`DEDSEC_PLAINTEXT_POSSIBLE` for secondary analysis. Non-byte-aligned sources
retain exact consumed/ignored bit counts, and ordered transform provenance
distinguishes operations applied before and after radix decoding.

This is explicitly not a ciphertext detector. A rejected result means "not
plausible supported plaintext," not "no hidden payload." See the
[plaintext filter contract and measurements](docs/PLAINTEXT_FILTER.md).

## Search

`dedsec_search()` applies each supplied transform chain to both corpus and needles, then reports transformed and source-byte offsets. Built-in transforms ASCII-case-fold, collapse or delete horizontal whitespace, and strip the Unicode-17.0.0-pinned default-ignorable property set; callers can add their own transforms. For archived web data, partition records outside the library and retain each document's URL, timestamp, declared charset, and raw hash in the caller's evidence model. See [the default-ignorable property contract](docs/DEFAULT_IGNORABLE_PROPERTIES.md), [residual format-control observation](docs/UNICODE_FORMAT_CONTROL_PROPERTIES.md), and [Unicode whitespace observation](docs/UNICODE_WHITESPACE_PROPERTIES.md).

## Limits and evidence handling

Scores are not probabilities, printable output is not proof of a message, and short random bitstreams can look meaningful. Unicode coverage is intentionally conservative; normalization, transcoding, full Unicode services, cryptanalysis, image analysis, metadata, networking, and indexing are out of scope. Preserve original bytes before charset conversion or normalization, which can destroy the signal under investigation.

See [the threat model](docs/THREAT_MODEL.md), [verified channels](docs/VERIFIED_CHANNELS.md), and [the second sampling pass](docs/SECOND_PASS.md).
The fixed reviewed Unicode identity registry and its evidence limits are in
[the identity-module contract](docs/IDENTITY_MODULE.md).
The Gemtext link grammar and separator lanes are described in the
[Gemtext module contract](docs/GEMTEXT_MODULE.md).
The bounded implicit-bidi source-order lane and its LTR/protocol constraints
are described in the [implicit bidi module contract](docs/IMPLICIT_BIDI_MODULE.md).
