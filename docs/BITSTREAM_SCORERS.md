# Bitstream scorers

The scorer API measures whether an extracted bitstream is cheaply described by
several simple models. It does not decide whether a stream is steganography,
plaintext, encrypted, malicious, or benign.

## Public API

Five independent functions return a common
`dedsec_bitstream_scorer_result`:

- `dedsec_bitstream_scorer_runs()` KT-codes the transition mask. Its
  `statistic` is the number of switches. Both long clusters and almost-perfect
  alternation can therefore be cheap without using fragile fixed-width RLE.
- `dedsec_bitstream_scorer_kt()` evaluates KT-smoothed binary Markov models
  through the requested order, including model-selection cost. The aggregate
  scorer deliberately uses order one; callers may inspect orders through four.
- `dedsec_bitstream_scorer_periodic()` tests bounded periods and KT-codes the
  prediction errors. Its cost includes the chosen period and seed bits.
- `dedsec_bitstream_scorer_lz78()` reports phrase count and an estimated LZ78
  phrase-code length. The caller supplies a dictionary bound. Saturation stops
  at an exact assessed prefix and sets `DEDSEC_BITSTREAM_SCORE_LIMIT_REACHED`.
- `dedsec_bitstream_scorer_linear()` uses Berlekamp-Massey over GF(2). It
  reports the inferred recurrence length and estimates the cost of carrying
  the recurrence and seed. Work is bounded to the first 1,024 bits; longer
  inputs set `LIMIT_REACHED` and retain both source and assessed lengths.

Description lengths are Q48.16 bits. Divide `description_bits_q16` by 65,536
for model bits, or divide `bits_per_source_bit_q16` by 65,536 for normalized
cost over the assessed prefix. Integer fixed-point arithmetic keeps the core
library pure C11 without a runtime compression or math dependency.

Low cost means that one tried model describes the stream economically. It does
not mean the stream is innocent: run lengths, periodic choices, dictionary
phrases, or a linear recurrence may themselves carry a message. High cost
means only that these models did not explain the stream.

## Convenience heuristic

`dedsec_bitstream_score()` runs the runs, order-one KT, periodic, and LZ78
scorers with bounded defaults and
returns their complete results plus a review score and flags. It classifies:

- streams cheaply explained by transition or order-one KT models as
  `DEDSEC_BITSTREAM_SCORE_SIMPLE`;
- structure exposed primarily by periodic or LZ78 models with the
  corresponding structure flag and a review-worthy score;
- sufficiently long streams not explained by any model as
  `DEDSEC_BITSTREAM_SCORE_HIGH_UNEXPLAINED`;
- streams below 24 bits as `SHORT_SAMPLE`, with measurements but no aggregate
  review score.

The length-dependent boundary comes from the bounded case-channel experiment,
not a probability or universal corpus baseline. Applications with a suitable
corpus should retain raw results and use genre-, language-, carrier-, and
length-conditioned comparisons.

Berlekamp-Massey is deliberately excluded from the convenience heuristic. It
is quadratic, recognizes only a narrow linear-generator family, and is not
needed for triage: a stream produced by an unrecognized generator,
compression, or encryption remains review-worthy as high unexplained
complexity. Call `dedsec_bitstream_scorer_linear()` explicitly when linear
recurrence is itself an investigation hypothesis.

```c
dedsec_bitstream_score_result score;

if (dedsec_bitstream_score(&extracted, &score) == DEDSEC_OK) {
    size_t i;
    for (i = 0; i < score.scorer_count; ++i) {
        const dedsec_bitstream_scorer_result *model = &score.scorers[i];
        /* Display model identity, source/assessed lengths, normalized cost,
         * statistic, selected parameter, and flags. */
        (void)model;
    }
    /* score.score and score.flags are triage advice, not attribution. */
}
```

An application can tell its operator:

> Word-case extraction yielded 184 bits. The transition and order-one models
> did not explain it; the bounded result has high unexplained complexity.
> Retain for review. No format, key, framing, or intent was identified.

Or:

> The 512-bit stream is cheaply described by its switching pattern. Literal
> byte packing was not treated as opaque data. Source bits and carrier spans
> remain available for a run-length hypothesis.

## Plaintext filter integration

`dedsec_bitstream_filter()` calls the convenience scorer before trying byte
phases and transformations:

- `HIGH_UNEXPLAINED` may qualify sufficiently long, balanced, byte-diverse
  output as `DEDSEC_PLAINTEXT_OPAQUE_DATA`.
- periodic or dictionary evidence may qualify as
  `DEDSEC_PLAINTEXT_STRUCTURED_DATA` even when it is not plausible text.
- `SIMPLE` streams do not receive either data flag. This suppresses natural
  capitalization clusters and novelty case without deleting their bits.
- Recognizable plaintext and canonical radix decoding remain independent
  paths and can still produce `LIKELY`.

The filter result is intentionally less detailed. Applications that need to
explain or override the decision call `dedsec_bitstream_score()` on the same
preserved bitstream.

## Limits

Random-input convolutional codes, constrained codes with weak observable
bias, compression, ciphertext, and actual random data may remain mutually
indistinguishable to these generic models. A distribution-matching encoder can
also approach the natural carrier distribution. Recurrence across records,
caller-supplied grammar, framing/checks, and comparable clean baselines remain
independent evidence.

Short results are especially unstable. Measurements below 24 bits are exposed
so callers can correlate records, but the default scorer does not elevate
them. No scorer result proves absence of hidden information.
