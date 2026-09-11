# Plaintext bitstream filter

`dedsec_bitstream_filter()` is a conservative prefilter for extracted
bitstreams. It answers whether a supported interpretation is plausible
Latin-script plaintext, or whether a strong byte-lifted-Unicode representation
needs backend review. It is not a general hidden-data detector.

`DEDSEC_PLAINTEXT_REJECT` means neither plausible supported plaintext nor a
sufficiently strong opaque-data candidate. It must not be interpreted as
evidence that a carrier contains no hidden data. Short, constant, and
low-diversity streams remain outside the reliable scope.

## Runtime behavior

The filter tries the eight leading bit offsets, normal and per-byte reversed
bit order, and normal and inverted bits. Shifted, reversed, and inverted
interpretations receive trial penalties. It validates strict UTF-8 and scores
printable characters, controls, word shape, whitespace, vowel balance, and
common Latin letter transitions.

The input need not be byte-aligned. Complete bytes are interpreted at each
trial offset. A partial tail participates in the bit-balance test for a raw
opaque candidate, although it cannot be parsed as a byte or fed through a
canonical radix decoder. For example, a run of 33 caller-mapped five-bit Latin
symbols has a 165-bit source length and a five-bit tail and can still qualify
as opaque data.

The result separates `source_bit_length`, `source_bits_consumed`,
`assessed_trailing_bits`, and `ignored_trailing_bits`. `decoded_length` counts
bytes at the final assessment stage, so it may describe raw interpreted bytes
or the output of one or two radix decoders. It never replaces or rounds the
source bit length. `DEDSEC_PLAINTEXT_PARTIAL_BITS` records that the selected
source interpretation had a partial tail.

A bounded transform search recognizes strict, canonical Base16, RFC 4648
Base32, Base32hex, Base64, and URL-safe Base64. At most two encoding layers are
decoded. Per-byte reversal and inversion are tried both before and after radix
decoding. `transforms[]` records their application order; the older flag bits
only record whether each transform occurred anywhere. A printable radix
wrapper cannot qualify as plaintext by itself when its decoded content is
binary noise.

All trial phases remain eligible for opaque routing unless the source bits are
clearly low in serial complexity. Phase, reversal, and inversion penalties may
rank plaintext hypotheses but cannot lower a stream that independently
satisfies the opaque gate below `POSSIBLE`. Equal-score interpretations are
counted, and selection prefers smaller source offsets, more consumed source
bits, fewer bit operations, and then deeper canonical radix evidence. Numeric
flag values are never used as evidentiary ranking.

The `score` is a heuristic from 0 through 100, never a probability:

- `LIKELY`: score 90 or greater.
- `POSSIBLE`: score 70 through 89.
- `REJECT`: score below 70 for a sufficiently long candidate.
- `INSUFFICIENT`: fewer than six complete bytes can be interpreted.

Production callers seeking a low false-positive prefilter should promote
`LIKELY`. `POSSIBLE` is intended for forensic or secondary analysis.
An unrecognized byte stream of at least 16 bytes also passes as `POSSIBLE`
with `DEDSEC_PLAINTEXT_OPAQUE_DATA` when it contains at least eight distinct
byte values and its one-bit fraction lies between 25% and 75%. This preserves
AES-GCM ciphertext, compressed bytes, and other non-degenerate opaque outputs
for backend review. Those classes are information-theoretically confusable
with random noise from the bytes alone; the flag makes no attribution and must
be combined with carrier structure, recurrence, framing/checks, provenance,
or external operator knowledge. Constant and low-diversity streams remain
filtered. The default decision now uses the public run, KT, periodic, and
bounded LZ78 scorer ensemble. Clearly block-like or
simple short-period source bits remain filtered: for example,
an uppercase disclaimer followed by lowercase prose can be globally balanced
while consisting only of a long one-run and a long zero-run, and novelty case
can form an almost exact period-two stream. These source symbols remain
available with provenance for a separately declared run-length or periodic
decoder; they merely do not qualify as opaque data by literal bit packing.
Structure exposed primarily by periodic or dictionary
models can instead pass as `DEDSEC_PLAINTEXT_STRUCTURED_DATA`; that flag names
observed structure, not its format or purpose.
This same opaque path covers EBCDIC bytes lifted into Unicode when
their resulting UTF-8 byte stream meets the generic length, diversity, and bit
balance gates; no byte-lift-specific flag or code-page guess exists.

Strict UTF-8 validity is not treated as proof of printable text. C0/C1 control
scalars invalidate the plaintext score, and non-ASCII bytes receive no
automatic score bonus. A candidate containing them must qualify from the same
surrounding word and whitespace evidence as ASCII text, or through the
format-neutral opaque route.

`dedsec_bitstream_filter()` validates the public packed-storage invariant:
`bytes.len` must equal `ceil(bit_length/8)`, it must not exceed the buffer's
declared capacity, and unused low bits in the final storage byte must be zero.
For streams built by `dedsec_symbols_glue_source_order()`, callers retain the
original detection events as the mapping from bit ranges to raw carrier byte
spans. The filter's source-bit counts identify the selected subrange; they do
not replace those possibly noncontiguous event spans with a misleading byte
envelope.

## Reproduction

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DDEDSEC_BUILD_TOOLS=ON
cmake --build build
ctest --test-dir build --output-on-failure
python3 tools/make_plaintext_filter_fixtures.py \
  corpus/gutenberg/alice.txt research/plaintext_filter
build/dedsec_bitstream_benchmark research/plaintext_filter/*.txt
python3 tools/plaintext_filter_experiment.py \
  corpus/gutenberg research/plaintext_filter_eval_10000 --samples 10000
```

## Current empirical result

The end-to-end carrier fixture embeds a 37-byte instruction as raw text,
Base32, and Base64 through zero-width, variation-selector, and gap-width
channels. All nine correct extraction lanes returned `LIKELY` with score 100.

With the opaque routing gate enabled, the untouched four-book corpus produced
96 parameter-free extraction lanes: 24 were `REJECT`, 44 were too short, 28
were `POSSIBLE`, and none were `LIKELY`. The possible results are incidental
packed streams requiring carrier-side evidence, not detected payloads.

The post-repair payload experiment selected 1,000 real lines, 12 through 160
bytes, from the Gutenberg corpus. Results were:

| Input class | Candidates | Possible | Likely |
| --- | ---: | ---: | ---: |
| Raw/Base16/Base32/Base32hex/Base64/nested plaintext | 6,000 | 0 | 6,000 |
| Random, AES-GCM, and Base16/Base32/Base64 wrappers | 8,000 | 7,983 | 0 |

All tested plaintext reached `LIKELY`; no tested binary input did. As intended,
almost every random/AES-like input reached the noisy `POSSIBLE` secondary
queue: 17 short random samples failed the 16-byte opaque gate. These are
development measurements, not a certified production false-positive rate.
The plaintext comes from four historical English books, several negative
variants share source material, and operational corpora such as logs,
identifiers, source code, chat, and multilingual text remain untested.
