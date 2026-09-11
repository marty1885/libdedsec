# Independently generated and verified channels

Four context-free agent exercises were asked to invent plaintext carriers and
prove round-trip recovery. All four completed; later results largely converged
on the same primitives. All used harmless payloads
(`OK` or `0101`). The table records mechanisms, not incident claims.

| Feature family | Verified carrier examples | Recovery | Primitive |
|---|---|---|---|
| Invisible symbols | ZWSP/ZWNJ binary; Unicode tag bytes | Exact | Code-point alphabet scanner |
| Bidi isolates | balanced empty LRI/RLI binary with PDI closers | Exact | Structural carrier gate plus isolate decoder |
| Variation syntax | `U+FE00..U+FE0F` nibble values | Exact | Base/selector validation plus radix decoder |
| Mongolian variation syntax | `U+1820 U+180B` / `U+1820 U+180C` | Conditional | Raw selector-pair lane; font and shaping context dependent |
| Script confusables | Latin `a` / Cyrillic `а` | Exact | Script runs and UTS #39 skeletons |
| Canonical aliases | composed/decomposed Hangul, Bengali, Devanagari | Exact before NFC | Normalized shadow plus raw-span signature |
| Compatibility aliases | Thai decomposition, Arabic presentation forms | Exact before NFKC | NFC/NFKC differential signature |
| Combining order | different mark orders, including equal-CCC marks | Exact | Grapheme cluster mark-order stream |
| Stateful encodings | redundant ISO-2022-JP designations | Exact from raw bytes | Decoder-state provenance and minimal-state comparison |
| UTF-7 redundancy | direct versus shifted printable ASCII | Exact from raw bytes | Per-scalar encoding provenance |
| Parser boundaries | bytes after embedded NUL | Exact with length-aware input | Competing-parser differential |
| Whitespace | trailing width and inter-word gap width | Exact | Run-length feature stream |
| Orthography | word-initial case and punctuation choice | Exact | Categorical token feature stream |
| Structure | word- and line-length parity | Exact | Numeric feature stream plus bit rule |
| Lexical choice | ordered synonym pairs | Exact with codebook | Caller-supplied token classifier |

The generalized model is:

```text
raw bytes -> decoded scalars + provenance -> tokens/clusters -> feature stream
          -> candidate symbol alphabet -> bit/nibble lanes -> inert candidates
          -> caller-supplied transform-chain search
```

## Confidence controls

- One unusual code point is not a message.
- Legitimate ZWJ/ZWNJ, emoji selectors, Arabic/Hebrew directionality, NFD text,
  and legacy mail encodings must remain possible.
- Prefer inconsistent representation within nearby repeated material over a
  document-wide encoding convention.
- Increase confidence for near-balanced repeated alphabets, regular placement,
  byte-aligned lengths, explicit framing, cross-document recurrence, and known
  user-supplied terms.
- Count every attempted alignment, bit order, transform chain, and feature rule.
  Multiple testing otherwise guarantees seductive coincidences.

## Prototype mapping

Direct built-ins cover the high-signal and easy-to-verify cases. Full
normalization aliases, grapheme segmentation, Script_Extensions, and confusable
skeletons require generated Unicode tables and are intentionally extension
points in this pure C11 prototype rather than partial hard-coded decoders.
