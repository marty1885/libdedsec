# Plaintext bitstream filter

`dedsec_bitstream_filter()` is a conservative prefilter for extracted
bitstreams. It answers whether a supported interpretation is plausible
Latin-script plaintext. It is not a general hidden-data detector.

`DEDSEC_PLAINTEXT_REJECT` means "not plausible supported plaintext." It must
not be interpreted as evidence that a carrier contains no hidden data.
Ciphertext, compressed data, binary formats, unsupported character encodings,
and plaintext shorter than six bytes are outside the reliable scope.

## Runtime behavior

The filter tries the eight leading bit offsets, normal and per-byte reversed
bit order, and normal and inverted bits. Shifted, reversed, and inverted
interpretations receive trial penalties. It validates strict UTF-8 and scores
printable characters, controls, word shape, whitespace, vowel balance, and
common Latin letter transitions.

A bounded transform search recognizes strict, canonical Base16, RFC 4648
Base32, Base32hex, Base64, and URL-safe Base64. At most two encoding layers are
decoded. A printable radix wrapper cannot qualify as plaintext by itself when
its decoded content is binary noise.

The `score` is a heuristic from 0 through 100, never a probability:

- `LIKELY`: score 90 or greater.
- `POSSIBLE`: score 70 through 89.
- `REJECT`: score below 70 for a sufficiently long candidate.
- `INSUFFICIENT`: fewer than six complete bytes can be interpreted.

Production callers seeking a low false-positive prefilter should promote
`LIKELY`. `POSSIBLE` is intended for forensic or secondary analysis.

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

The untouched four-book corpus produced 92 parameter-free extraction lanes:
52 were `REJECT` and 40 were too short; none were `POSSIBLE` or `LIKELY`.

The larger payload experiment selected 10,000 real lines, 12 through 160 bytes,
from the Gutenberg corpus. Results were:

| Input class | Candidates | Possible | Likely |
| --- | ---: | ---: | ---: |
| Raw/Base16/Base32/Base32hex/Base64/nested plaintext | 60,000 | 12 | 59,988 |
| Random, AES-GCM, and Base16/Base32/Base64 wrappers | 80,000 | 19 | 0 |

Thus `POSSIBLE` recovers all tested plaintext but is intentionally noisy;
`LIKELY` had 99.98% recall and no observed binary false positives in this
experiment. These are development measurements, not a certified production
false-positive rate: the plaintext comes from four historical English books,
several negative variants share source material, and operational corpora such
as logs, identifiers, source code, chat, and multilingual text remain untested.
