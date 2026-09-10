# Paired carrier-detection ROC experiment

This experiment measures whether the library's direct carrier families can
distinguish ordinary English prose from the *same prose* after embedding the
unencrypted bytes `Hello World`. It is deliberately a carrier-detection test;
it does not treat the extracted bitstream's entropy as a classifier.

## Method

`tools/roc_experiment.py` divides the four local Project Gutenberg books into
4,096-character windows. It selected 300 eligible windows and created one
paired stego copy of every window for each channel:

- zero-width: 88 `U+200B`/`U+200C` symbols, one per message bit;
- variation selector: 22 `U+FE00..U+FE0F` selectors, one per message nibble;
- gap width: 88 one/two-space gap choices, one per message bit.

Existing multi-space runs were normalized before window selection, because a
run wider than two is not an unambiguous `gap-width-bits` carrier. The scoring
program, `dedsec_carrier_score`, uses libdedsec's UTF-8 scanner and gap-feature
extractor. Its monotonic anomaly scores are: number of zero-width symbols,
number of variation selectors, and number of width-two gaps, respectively.

```sh
cmake -S . -B build -DDEDSEC_BUILD_TOOLS=ON && cmake --build build
python3 tools/roc_experiment.py corpus/gutenberg research/roc --max-windows 300
```

## Result, 2026-09-10

Each channel has 300 clean and 300 paired stego samples. The observed AUC is
1.000 for zero-width, variation-selector, and gap-width carriers. In this
corpus the maximum clean scores were 0, 0, and 0; the minimum stego scores were
88, 22, and 43. Thus simple carrier-presence/density thresholds perfectly
separate this experiment.

The command generates `summary.tsv`, per-channel ROC TSVs, `scores.tsv`, and
`roc.svg` under `research/roc`. The `research/` tree is deliberately ignored;
retain or archive those artifacts separately when an experiment must be audited.

## Interpretation and limits

This is evidence that the three *direct, representation-changing* channels are
detectable against this narrow English corpus at this embedding density. It is
not evidence that arbitrary linguistic steganography is detectable: a synonym,
grammar, or language-model encoder needs a matched conditional-language model
and its own paired benchmark. Nor does AUC 1.0 on these non-independent windows
prove a production false-positive rate; add diverse, contemporary, multilingual,
and naturally formatted sources before choosing a threshold.
