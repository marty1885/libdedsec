# Case-lane KT and PPM experiment

This paired exploratory experiment asks whether a deeper raw-bit model can
explain ordinary word-initial case lanes that the default order-one KT scorer
routes as opaque. It does not establish production thresholds.

Run it with:

```sh
python3 tools/case_model_experiment.py boot.txt Stream.desktop
```

For each observed lane, the script creates a deterministic SHA-256-derived
random-case control of identical length. This is a matched synthetic control,
not a substitute for a stratified natural or steganographic corpus.

## Results

The public C scorer, including its model-selection charge, reports:

| Input | Bits | Default KT | KT max order 4 | Selected order | Simplicity boundary |
|---|---:|---:|---:|---:|---:|
| `Stream.desktop` | 973 | 0.9828 | 0.7389 | 4 | 0.7581 |
| `boot.txt` | 559 | 0.8674 | 0.8709 | 1 | 0.7644 |

Thus maximum-order-four KT explains `Stream.desktop` as `SIMPLE`, while the
current convenience scorer's order-one call cannot. The script's matched
random-case control costs about 1.0475 bits per bit at fixed order four. The
large paired separation is promising, but testing one structured file does
not justify changing the default.

The order-four contexts expose strong local dependencies. For example, in
`Stream.desktop`, context `0110` is followed by one in 142 of 149 cases,
whereas `1011` is followed by zero in 134 of 154 cases. Repeated localization
and action records plausibly produce these patterns after the lossy case-only
projection.

The bounded PPM-style experiment is negative as an absolute coder. At depth
four it costs 0.9092 bits per observed `Stream.desktop` bit, and deeper models
become worse due to escape overhead. PPM escape coding is awkward on a binary
alphabet: a context has at most two symbols, so escape charges are large
relative to the information being coded. The randomized controls cost still
more, but a classifier based on that relative gap would require a conditioned
baseline unavailable to a standalone scan.

## Interpretation and next checks

Higher-order KT is the simplest promising direction. It is bounded, already
implemented, and needs no tokenizer, dictionary, parser, or learned model.
Before changing detection, evaluate maximum orders two through four over
stratified prose, logs, configuration, source, multilingual resources, and
paired payload carriers. Report results by carrier class and length. In
particular, measure whether order four cheaply memorizes short byte-shaped
payloads; that risk is why the convenience scorer currently fixes order one.

Classic binary PPM should not be promoted from this experiment. A bounded
context-tree mixture may be a better follow-up because it can exploit deeper
contexts without committing to one order or paying PPM escape costs, but it
likewise needs corpus evidence and an explicit model-complexity charge.

## Small system-corpus measurement

A follow-up sampled 21 installed `.desktop` files (including the submitted
file), 72 repository text/source files, and the first 200 sorted public text or
README files of 1--256 KiB under `/usr/share/doc`. Only lanes meeting the
opaque gate's basic shape--at least 128 bits, a 25--75% one fraction, and eight
distinct packed byte values--were assessed. This left 34 benign lanes: eight
desktop, three repository, and 23 system-document lanes.

| Set | Eligible | Simple at KT max 1 | max 2 | max 3 | max 4 | Newly explained by max 4 | Matched random controls simple at max 4 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Desktop | 8 | 1 | 1 | 2 | 2 | 1 | 0 |
| Repository | 3 | 1 | 1 | 1 | 1 | 0 | 0 |
| System docs | 23 | 12 | 13 | 13 | 13 | 1 | 0 |
| Total | 34 | 14 | 15 | 16 | 16 | 2 | 0 |

Maximum-order-four KT therefore explains `Stream.desktop` without explaining
any matched pseudorandom controls, but it improves only two of the 20 benign
lanes left unexplained by order one. This is a useful narrow feature, not a
general resolution of the case-channel false-positive problem. The sample is
local and convenience-selected, so the percentages are not population rates.

There is also an adversarial semantic conflict. Repeated binary de Bruijn
cycles have balanced order-zero and order-one statistics but become nearly
deterministic at their defining order. At 973 bits, the measured KT costs are:

| Repeated cycle | Period | KT max 1 | KT at explaining order |
|---|---:|---:|---:|
| Binary de Bruijn order 2 | 4 | 1.0065 | 0.0238 |
| Binary de Bruijn order 3 | 8 | 1.0065 | 0.0404 |
| Binary de Bruijn order 4 | 16 | 1.0065 | 0.0695 |

The current ensemble deliberately lets its periodic/LZ models mark such
structure for review after order-one KT fails. Simply replacing order-one KT
with order four would classify period-four and period-eight payload lanes as
`SIMPLE` before the periodic scorer could promote them. A future ensemble must
retain *which* model explains a lane: natural-case suppression cannot safely
equate all higher-order predictability with benignity.
