# Composite channel observations

An attacker can distribute one payload across several representation lanes so
that every lane remains below its standalone recurrence threshold. Detection
therefore exposes candidate symbols before aggregate promotion and permits a
caller to reconstruct a bounded source-order hypothesis.

## ABI-v4 callback contract

Every callback value has a `kind`:

- `DEDSEC_DETECTION_FINDING` is an aggregate rule result. Its score and
  evidence retain their existing meaning; `symbol_width` is zero.
- `DEDSEC_DETECTION_SYMBOL` is a possible parameter-free symbol. Its
  `symbol_value`, `symbol_width`, `byte_offset`, and `byte_length` identify the
  exact raw contribution. Its score is zero and it is not independently an
  alert.
- `DEDSEC_DETECTION_OBSERVATION` is a zero-score raw property event. It has no
  decoder hint, bit value, or symbol width and cannot be glued into bits.

Built-in fixed identity, Unicode binary/nibble, line-ending, layout,
ISO-2022/CESU-8, Markdown-marker, and validated radix lanes expose symbols.
Rules whose mapping is caller-defined, such as `token-map-msb` and
`codepoint-map-msb`, cannot assign a value during parameter-free detection;
the caller must emit equivalent events from its reviewed map.

Callbacks may copy the structure. Built-in identifier strings have static
lifetime. The input bytes remain caller-owned and unchanged; each event records
only offsets and lengths into that raw input.

## Source-order gluing

`dedsec_symbols_glue_source_order()` sorts a caller-selected event array by raw
byte offset and appends each value MSB-first. It rejects non-symbol records,
zero-length or invalid spans, invalid values/widths, and overlapping spans. The
array is not modified. The caller retains it as the provenance map for the
resulting bitstream.

Selection is deliberately external. Passing every observation is unsafe:
ordinary spaces, punctuation, line endings, and overlapping descriptions can
manufacture a candidate. A defensible composite trial should predeclare its
eligible lanes and require at least:

- two underlying feature families, deduplicated by feature rather than name;
- 32 total selected symbols and at least four from each participating lane;
- a 20% minority floor for a one-bit merged lane;
- non-overlapping, recurrent placement or caller-supplied record slots;
- explicit accounting for lane selection, polarity, alignment, and ordering;
- framing/checksum, independent cross-record recurrence, or another signal
  beyond output that merely resembles plaintext.

Absence is never a bit unless a supplied grammar defines the missing slot.
Overlapping events are never automatically counted as two bits; a grammar must
prove the features are orthogonal before a caller places them into separate
trials. Decoded output remains a hypothesis.

## Regression attacker

The executable test alternates two independently reviewed feature families in
raw source order: 16 hyphen-identity events and 16 Mongolian-FVS events encode
the four harmless bytes `OKOK`. Each family remains below its 32-symbol
standalone gate, so there is no aggregate finding. Detection still streams all
32 exact symbol spans, and the source-order gluer reconstructs the independent
expected output. A duplicate overlapping event is a negative control and is
rejected.
