# Gemtext link representation module

The `gemtext` built-in is a narrow, byte-preserving recognizer for complete
Gemtext link lines. It is not a URL normalizer and does not claim that two URLs
are equivalent. Its only semantic claim is that the line has the Gemtext link
shape accepted by the module:

```text
=>[ASCII SPACE or TAB run]URL[ASCII SPACE or TAB run]label\n
```

The prefix run may be empty (`=>URL` is a valid slot under this recognizer),
the URL is nonempty, and a label is either absent or nonempty. A separator with
no label is not a complete record. LF, CRLF, and a final unterminated line are
handled; a lone CR is not treated as a line ending. The parser requires strict
UTF-8 before it emits any observations. Malformed input remains the encoding
module's responsibility for detection and returns `DEDSEC_EUTF8` to decoding.

## Reviewed binary lanes

The module exposes four fixed, parameter-free conventions:

| Variant | Slot | Bit value | Provenance |
|---|---|---|---|
| `gemtext-prefix-width-low-bit` | complete link prefix run, including width 0 | `run_length & 1` | prefix run, or the complete `=>URL` header span when width is zero |
| `gemtext-prefix-space-tab-bits-msb` | nonempty prefix run containing only one kind | SPACE = 0, TAB = 1 | exact prefix run |
| `gemtext-label-width-low-bit` | nonempty label separator run | `run_length & 1` | exact label separator run |
| `gemtext-label-space-tab-bits-msb` | nonempty label separator run containing only one kind | SPACE = 0, TAB = 1 | exact label separator run |

The width lane does not treat an absent label as a bit. It emits a label
observation only when the grammar supplies a nonempty label-separator slot and
the label itself is nonempty. In contrast, a zero-length prefix is observable
in the prefix-width lane because the complete `=>URL` record establishes that
the prefix slot exists; its nonzero provenance span is the parsed link header
through the URL, not an invented zero-byte location.

Mixed SPACE/TAB runs are valid separator runs for width lanes but are excluded
from the type lanes. This avoids silently turning a ternary or mixed alphabet
into a binary decoder. The decoder variants append one MSB-first bit per
eligible complete link in raw source order. Output is a hypothesis and is not
proof of a payload.

The detector emits every reviewed symbol below the aggregate gate with
`DEDSEC_DETECTION_SYMBOL`, its one-bit value, and its raw source span. An
aggregate finding requires at least 32 observations, at least eight of each
value, and a 20% minority floor. Those counts reduce routine formatting noise
but do not establish intent; require repeated placement, framing/checksum,
cross-record recurrence, or a representative baseline before elevation.

## False positives and composition

Gemtext clients, exporters, editors, line-wrapping tools, and hand formatting
can legitimately choose one space, several spaces, or a tab. A line's label
separator is not a general whitespace identity, and URL normalization is out
of scope. A no-label line must not be used to supply a label bit.

Gemtext separator spans can overlap generic layout or line-ending observations.
Callers composing lanes must select a reviewed subset, retain each event's raw
byte offset and length, deduplicate overlaps, and account for every tested
polarity/alignment/slot rule. Blindly unioning all events manufactures
hypotheses. `dedsec_symbols_glue_source_order()` rejects overlapping spans and
is therefore suitable only after this caller-side selection.

The regression suite includes independently expected alternating `55 55 55
55` streams for all four lanes, uniform benign links, non-link text, no-label
links, final records, and malformed UTF-8 decoding.
