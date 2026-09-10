# Bitstream entropy baseline

This experiment answers a narrow question: *what bitstreams do the existing
parameter-free trial decoders emit from ordinary text, and how do their simple
entropy measurements compare with known embedded lanes?* It does not establish
that high entropy indicates steganography. Random payloads, compressed text,
and accidental feature streams can all have high entropy; low-volume lanes make
any estimate especially noisy.

## Corpus and provenance

The acquisition script fetches four public-domain English books from Project
Gutenberg: *Alice's Adventures in Wonderland*, *Frankenstein*, *Moby-Dick*, and
*Pride and Prejudice*. They differ in narration, dialogue density, punctuation,
and nineteenth-century orthography. This is a starting baseline, not a claim of
language or genre coverage. Preserve downloaded files and record their SHA-256
hashes with each result.

```sh
sh tools/fetch_baseline_corpus.sh
find corpus/gutenberg -type f -name '*.txt' -exec sha256sum {} \; > corpus/gutenberg/SHA256SUMS
cmake -S . -B build -DDEDSEC_BUILD_TOOLS=ON
cmake --build build
python3 tools/make_stego_fixtures.py corpus/gutenberg/alice.txt corpus/stego --bits 1024
./build/dedsec_bitstream_benchmark corpus/gutenberg/*.txt corpus/stego/*.txt > corpus/trial_benchmark.tsv
./build/dedsec_bitstream_benchmark --detected-only corpus/gutenberg/*.txt corpus/stego/*.txt > corpus/detected_benchmark.tsv
./build/dedsec_bitstream_benchmark --valid-dsc1-only corpus/gutenberg/*.txt corpus/stego/*.txt > corpus/validated_benchmark.tsv
```

`make_stego_fixtures.py` emits three paired, readable cover variants with
deterministic `DSC1` + length + CRC-32 payload frames: zero-width (`U+200B`/`U+200C`),
variation-selector (`U+FE00`/`U+FE0F`), and one/two-space word gaps. Each lane's
`payload.<lane>.bin` and `.bit_length` files are the exact expected stream. The
gap lane covers every ASCII gap, so its stream is longer than the other two.
These are calibration fixtures, not samples of an operational scheme or a
representative collection of real-world stego.

The four-book choice is intentionally auditable and redistributable. It should
be extended with consented/appropriately licensed contemporary prose, technical
writing, chat-like text, Markdown, and non-English Unicode text before any
generalization. A useful future source for paired linguistic stego experiments
is the British National Corpus setup described by Yang et al. (2014), which
reported 1,000 roughly 20 KB cover sections and their generated stego text.
See [Practical Linguistic Steganography using Contextual Synonym Substitution
and a Novel Vertex Coding Method](https://aclanthology.org/J14-2006/).

## Measurements

Each TSV row is one document and one library decoder lane. `trial_benchmark.tsv`
contains every parameter-free trial extraction; `detected_benchmark.tsv` contains
only lanes named by a `dedsec_detect_all()` finding. `finding_count` and
`max_score` preserve that detector context. Empty means the lane had no symbols,
not that the document is clean. The metrics are:

- `bits`: extracted bit count, which bounds confidence in every estimate.
- `ones`: number of one bits.
- `bit_shannon`: Shannon entropy of the 0/1 marginal, in bits per extracted bit.
- `bit_min_entropy`: `-log2(max(P(0), P(1)))`, a conservative marginal measure.
- `byte_shannon`: Shannon entropy over complete packed bytes. Partial final bytes
  are excluded; byte alignment is the decoder's emitted alignment.
- `serial_cond_entropy`: conditional entropy of the next bit given the previous
  bit. It falls when an encoder repeats or frames adjacent symbols.
- `fft_peak_share`, `fft_flatness`, and `dominant_period_bits`: an FFT over the
  first power-of-two prefix (capped at 1,048,576 bits), with DC excluded. They
  respectively report the largest non-DC power share, spectral flatness, and
  that peak's period. They test for periodic structure; they are not a general
  test for random payloads or a detection score.
- `frame_status`: validates the optional benchmark `DSC1` frame. Only
  `valid-dsc1-crc32` is a positive usefulness signal; CRC-32 limits accidental
  acceptance but does not authenticate a message against an active adversary.

`--valid-dsc1-only` is the strict positive-reporting mode: it implies
`--detected-only` and suppresses every candidate except one with a valid frame.
It deliberately reduces false positives only for this pre-registered format;
an unknown format remains an investigative lead, not a positive result.

The layout detector additionally applies a conservative carrier gate before it
emits a binary-alphabet finding: at least 32 usable symbols, at least eight of
each value, and neither value below 20% of the usable symbols. This removes the
common false-positive pattern of a document with thousands of ordinary single
spaces and a few accidental double spaces. It can miss short or deliberately
biased plaintexts, so it is a detection trade-off that must be evaluated by
false-positive and false-negative rates on a larger matched corpus.

Compare each known stego file only to its corresponding lane: `zero_width.txt`
to `unicode/zwsp-zwnj-msb`, `variation_selector.txt` to
`unicode/variation-nibbles`, and `gap_width.txt` to `layout/gap-width-bits`.
The variation-selector fixture uses all 16 selector values, so each selector
encodes a genuine nibble and its decoded output exactly matches the frame.

## Initial run (2026-09-10)

The checked local trial run is in `corpus/trial_benchmark.tsv`; the detector-gated
run is in `corpus/detected_benchmark.tsv`; the strict positive set is in
`corpus/validated_benchmark.tsv`; its source hashes are in
`corpus/gutenberg/SHA256SUMS`. Across the four downloaded books, no zero-width,
variation-selector, tag, ISO-2022, or CESU-8 lane emitted a stream. Ordinary
word-gap streams were almost entirely zeros (`bit_shannon` 0.000000–0.000882),
whereas ordinary word-length and sentence-parity streams were already nearly
maximal (respectively 0.997828–0.999979 and 0.997913–1.000000). In other words,
the primary negative result is that marginal bit entropy cannot distinguish a
random embedded payload from several completely ordinary structural features.

The controlled streams are near-balanced, so marginal entropy does not establish
usefulness. The `DSC1` header, exact length, and CRC do: all three generated
carrier lanes should report `valid-dsc1-crc32`, while normal-corpus streams
should not. This demonstrates the required operational principle: define an
independent, low-false-positive validity condition *before* inspecting outputs.
For real protocols, prefer a cryptographic MAC/signature or externally known
message format over CRC-32.

Do not pool distinct lanes, discard empty rows, rank documents solely by entropy,
or call an entropy score a probability. Report the corpus version, hashes,
decoder/lane version, all attempted lanes, sample counts, and confidence
intervals or bootstrap intervals when aggregating documents.
