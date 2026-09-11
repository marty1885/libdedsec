# Heterogeneous agent sampling pass

Four fresh-context agents received the same prompt. Model and reasoning effort
were the only controlled differences.

| Sample | Model | Reasoning | Distinct emphasis |
|---|---|---:|---|
| `luna_low` | GPT-5.6 Luna | low | CESU-8, BOM polarity, noncharacters, bidi isolates |
| `luna_max` | GPT-5.6 Luna | maximum | Higher-radix invisible alphabets, MIME/ANSI state, lexical parser equivalence |
| `terra_low` | GPT-5.6 Terra | low | JSON/URI/C/XML/MIME representation choices |
| `terra_max` | GPT-5.6 Terra | maximum | Japanese iteration marks, JSON numeric forms, XML namespace aliases, IPv6 width, C trigraph phase |

Every accepted proposal included an exact harmless carrier and a locally
reproduced extraction. The samples did generate new ideas. Increased reasoning
mostly produced broader semantic-equivalence classes; changing model family
shifted the search from Unicode/codec edge cases toward grammar-aware lexical
channels.

## Newly verified mechanism families

| Family | Examples | Prototype disposition |
|---|---|---|
| Configurable invisible radix | bidi opener type, U+2061..U+2064 math controls, U+1BCA0..U+1BCA3 shorthand controls, noncharacters | Implemented through `codepoint-map-msb/lsb`; suspicious ranges detected |
| Legacy codec equivalence | standard UTF-8 versus CESU-8 surrogate serialization | Dedicated detection and decoder implemented |
| Parser-source spelling | Format-specific literal, escape, numeric, and lexical forms | Implemented through caller-defined `token-map-msb/lsb`; common lexical markers detected |
| Structured semantic aliases | XML prefixes resolving to one namespace, CDATA/direct text, MIME Q/B, ANSI reset forms | Token alphabet supports controlled-region trials; full semantic validators remain extension modules |
| Domain lexical aliases | IPv6 hextet width, C11 trigraph/direct spelling | Token alphabet supports trials; markers detected where safe; domain parsers remain extensions |
| Non-Latin orthography | repeated ideograph versus U+3005 iteration mark | Dedicated decoder and anomaly signal implemented |
| Transport framing | UTF BOM choice, MIME quoted-printable soft breaks | Recorded as record-level features; requires caller-supplied record boundaries |

## Exact regression carriers added

The executable suite now contains agent-provided carriers that recover `OK`
for:

- noncharacter base-32 symbols;
- Latin/Cyrillic code-point-map binary;
- standard UTF-8 versus CESU-8 forms;
- JSON literal `水` versus `\\u6C34` spellings;
- four equivalent JSON representations of numeric one;
- Japanese doubled ideograph versus U+3005 iteration mark.

Earlier executable carriers remain for Unicode tags, ZWSP/ZWNJ, variation
selectors, ISO-2022 designations, and trailing-EOL horizontal-whitespace width.
A clean ordinary
prose fixture is included as a zero-finding negative control.

## Rejected or gated hypotheses

- Overlong UTF-8 is not an alternate UTF-8 spelling. It remains a strict decode
  error and is not exposed as a normal decoder.
- BOM choice is meaningful only across externally framed records. A single BOM
  is not treated as a payload.
- Format-specific equivalence claims require the matching grammar context. The
  generic token decoder does not assert semantic equivalence; the caller or a
  specialized module must establish it.
- Ternary alphabets require explicit length/radix framing. The current bit
  writer intentionally supports power-of-two alphabets only.

This division avoids pretending a substring recognizer is a standards-compliant
parser while still allowing bounded trials on a known field from an offline
snapshot.
