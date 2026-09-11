# Fixed Unicode identity module

The built-in `identity` module recognizes a reviewed registry of Unicode
representation identities. It is deliberately table-driven: a new family is
one entry with two exact UTF-8 spellings, a rule name, and a decode variant.
It is not a general synonym, parser, or normalization service.

| Variant | Zero spelling | One spelling | Scope limitation |
|---|---|---|---|
| `space-identity-bits` | `U+0020` SPACE | `U+00A0` NO-BREAK SPACE | Human-readable separation only; NBSP changes line breaks and tokenization. |
| `canonical-e-acute-identity-bits` | `U+00E9` | `U+0065 U+0301` | Exact canonical-equivalence pair; raw bytes and scalar count differ. |
| `hyphen-identity-bits` | `U+002D` HYPHEN-MINUS | `U+2011` NON-BREAKING HYPHEN | Visual joining function only; U+2011 changes line breaking. |
| `canonical-combining-order-bits` | `U+0061 U+0323 U+0301` | `U+0061 U+0301 U+0323` | Exact reviewed canonical-order pair only. The latter order is a raw anomaly before canonical reordering; no general grapheme/normalization claim is made. |
| `canonical-kelvin-identity-bits` | `U+004B` LATIN CAPITAL LETTER K | `U+212A` KELVIN SIGN | Exact canonical singleton: all four standard normalization forms map Kelvin sign to `K`. In scientific/unit typography or case-sensitive identifiers, raw spelling and semantics can still matter; require field grammar and baseline. |

`dedsec_registry_add_builtins()` registers this module. Decode with the
relevant variant through `dedsec_decode_bits()`; output is packed MSB-first and
retains a final partial byte. All spelling matching is over preserved raw
UTF-8 bytes after strict validation, so findings include original byte spans.

Detection is intentionally conservative: each identity needs at least 32
matched slots, at least eight examples of each spelling, and neither spelling
may account for less than 20% of slots. This reports a hypothesis only.
Neither a finding nor decodable output proves a payload.

Before adding a registry entry, require an exact harmless carrier, independent
round-trip reproduction, precise equivalence limits, negative controls,
realistic false-positive analysis, and a framing/grammar/checksum or
cross-record recurrence policy. Do not add malformed encodings or unspecified
parser behavior.
