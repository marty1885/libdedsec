# Arabic bidi-control experiment

This experiment compares libdedsec's Unicode findings on authentic Arabic
newswire with deliberate and legitimate uses of Unicode bidi isolates.

## Corpus

The source is the Universal Dependencies Arabic-PADT test split, derived from
the Prague Arabic Dependency Treebank. The corpus is primarily newswire and is
licensed CC BY-NC-SA 3.0:

https://github.com/UniversalDependencies/UD_Arabic-PADT

The downloaded test file has SHA-256
`793c87bf173d491af2092ef7f87b04a2cf6c596490e7347a2065058a053a6389`.
Its 680 reconstructed source sentences contain 131,221 characters and 105,967
Arabic letters. They contain no explicit U+061C, U+200E, U+200F, U+202A through
U+202E, or U+2066 through U+2069 bidi controls.

Fifty approximately 2,048-character windows were evaluated in four forms:

- Untouched Arabic newswire.
- A legitimate-formatting hard negative that wraps existing Latin and numeric
  runs in balanced U+2066 LRI / U+2069 PDI pairs, following Unicode/W3C advice
  for isolating opposite-direction inline content.
- A raw hidden message using U+2066 LRI as zero, U+2067 RLI as one, and an
  immediate U+2069 PDI after every opener.
- The same message encoded with RFC 4648 Base32 before bidi embedding.

The hidden message was `Meet at the loading dock at midnight.` (37 bytes).
Extraction used the built-in `bidi-isolate-bits-msb` decoder. Its detector hint
is gated on at least 64 openers, both LRI and RLI, at least 10% minority symbols,
90% matched pairs, 50% empty isolates, and five openers per 100 base codepoints.

## Results

| Input | Windows | Bidi evidence | Controls / 1,000 cover chars | Generic bidi score | Binary hints | Plaintext likely |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Untouched Arabic | 50 | 0 | 0 | 0 | 0 | 0 |
| Legitimate isolated LTR runs | 50 | 0–68 | 0–30.371 | 0–75 | 0 | 0 |
| Raw hidden plaintext | 50 | 592 | 224.412–288.921 | 75 | 50 | 50 |
| Base32 hidden plaintext | 50 | 1,024 | 388.173–499.756 | 75 | 50 | 50 |

Every raw extraction contained 296 bits and every Base32 extraction contained
512 bits. All recovered messages scored 100 in the plaintext filter; Base32
was decoded to the original 37 bytes.

## Interpretation

The untouched corpus makes dense bidi encoding easy to identify, but the
current 0–100 detector score is insufficient by itself. Twenty-two of fifty
legitimate-formatting windows reached the same saturated score of 75 as every
stego window. The raw `evidence` count and density retained a large separation:
the legitimate maximum was 68 controls versus a stego minimum of 592.

The structural gate emitted no binary decoder hints for untouched or
legitimately formatted Arabic and emitted one for every deliberate carrier.
The extracted bitstream provides a second strong distinction. Legitimate LTR
isolates yielded at most 34 zero bits and were always `INSUFFICIENT`; deliberate
channels yielded hundreds of mixed bits and recovered `LIKELY` plaintext.

For production, the binary decoder hint—not the generic bidi finding—should
start extraction. The hint incorporates control-kind counts, pair structure,
empty-isolate ratio, and document-normalized density. The recovered stream must
then pass `dedsec_bitstream_filter()` as `LIKELY`.

This remains a deliberately dense channel and a limited corpus. Sparse
embedding, naturally control-rich documents, HTML rendered to plain text,
localization resources, chat exports, Persian/Urdu, and malicious use of
legitimate LTR substrings require separate evaluation.

## Reproduction

```sh
cmake -S . -B build -DDEDSEC_BUILD_TOOLS=ON
cmake --build build
python3 tools/arabic_bidi_experiment.py \
  corpus/arabic_padt/ar_padt-ud-test.conllu research/arabic_bidi --samples 50
```

The command generates detailed rows in `research/arabic_bidi/results.tsv` and
the aggregate in `research/arabic_bidi/summary.tsv`. The `research/` tree is
deliberately ignored; retain or archive those artifacts separately when an
experiment must be audited.
