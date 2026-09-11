# Implicit bidi source-order collision lane

The `unicode` module includes one deliberately bounded implicit-bidi
observation. It is not a general Unicode Bidirectional Algorithm engine, a
renderer, or a semantic-equivalence claim.

## Exact record grammar

Only complete LF-terminated records matching one of these exact five-byte
spellings are observed:

| Bit | Scalars | UTF-8 bytes |
|---|---|---|
| 0 | `U+0061 U+05D0 U+0031 U+000A` (`L R EN B`) | `61 D7 90 31 0A` |
| 1 | `U+0061 U+0031 U+05D0 U+000A` (`L EN R B`) | `61 31 D7 90 0A` |

The leading ASCII `a` establishes the intended standalone LTR record context;
the module does not infer paragraph direction or run a renderer. Records must
end in LF exactly. CRLF, an unterminated final record, extra scalars, bidi
controls, and broad Hebrew/digit matches are not accepted as slots. Other lines
may be present as cover text, but they produce no symbols.

The UAX #9 result independently validated for explicit paragraph level 0 is
that both spellings display in scalar order `a`, `1`, ALEF, LF. This is a
visual-order collision only: decoding always preserves raw logical/source
order because source order is the evidence and the two records may have
different parser or application semantics. Higher-level protocols, markup,
segment boundaries, an RTL paragraph, or artificial context can change the
result and are outside this lane. See [UAX #9](https://www.unicode.org/reports/tr9/tr9-51.html)
for the normative algorithm and protocol rules.

## API names and evidence gate

The decoder variant is:

```text
implicit-bidi-ltr-source-order-bits-msb
```

It appends one MSB-first bit per exact record in raw source order. Detection
emits one `DEDSEC_DETECTION_SYMBOL` per record with a five-byte source span,
then emits an aggregate `implicit-bidi-source-order-collision` finding only
when there are at least 32 records, at least 8 of each spelling, and a 20%
minority floor. Symbols are observations, not proof of a message or intent.

The implementation validates the complete input with the repository's strict
UTF-8 scanner before parsing or emitting any lane symbols. A malformed input
therefore cannot yield partial candidate bits. The lane uses no runtime
Unicode, font, or bidi dependency and does not implement general UAX #9.

## False positives and composition

Mixed Latin/Hebrew prose, language exercises, generated tables, identifiers,
OCR, and test data can naturally contain these source-order permutations. LF
records are also relevant to existing line-ending/layout observations, so
callers composing ABI-v3 symbol events must select one reviewed non-overlapping
lane and preserve raw offsets. The source-order composite helper rejects an
implicit-bidi full-record span overlapping an LF event.

Before elevation, require an exact field/record contract, framing/checksum or
independently accounted recurrence, trial-count accounting, and a
representative baseline. No default intent claim is made by this module.

