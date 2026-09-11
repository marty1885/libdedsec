# Rejected and duplicate steganography hypotheses

This is an append-only decision register for red-team reviewers.  It prevents
the same weak claim from being rediscovered and counted as new coverage.  It is
not a claim that a feature is impossible: an entry may be reopened only by
demonstrating the specific missing fact named below, with exact carriers and an
independent reproduction.

`Rejected` means it must not be a normal decoder under the project boundary.
`Duplicate` means the feature family is already documented; it may still have
an implementation gap, but is not a new discovery. Detection candidates that
are merely grammar- or baseline-gated live in `docs/CANDIDATE_STEGNO.md`; they
are not rejected just because a decoder is unavailable.

## Reopen rule

Do not reopen an entry merely by showing a caller-supplied code-point/token map
can recover bits, by showing that the current built-ins emit no finding, or by
renaming the carrier.  A reopening report must name this entry and lead with
the new evidence that clears its stated bar: a conforming grammar, a
Unicode-version-pinned standardized relation, an independently reproduced
bounded round trip, and framing/recurrence evidence as appropriate.

## Rejected normal decoders

| Family | Status | Why it is not a normal decoder | What would change the disposition |
|---|---|---|---|
| Overlong UTF-8 and other malformed UTF-8 spellings | Rejected | They are invalid under strict UTF-8, and accepting them as equivalent depends on permissive or unspecified parser behavior. | Only an explicit, separately labelled forensic mode for raw malformed-input observations; never ordinary UTF-8 decoding. |
| BOM polarity/choice | Rejected as a standalone channel | A BOM is meaningful only at an externally supplied record boundary. One occurrence has no bit-slot grammar. | Caller-provided, validated record framing plus a multi-record feature contract. |
| Ternary/non-power-of-two symbol streams | Rejected without framing | Converting arbitrary ternary choices to bits leaves ambiguity in grouping and tail length. | Explicit symbol count/radix framing and a defined lossless packing rule. |
| Printable bytes alone | Rejected | Arbitrary printable choices have no representation-equivalence claim and create extreme multiple-testing false positives. | A standards-defined, bounded identity plus grammar and evidence gates; a synonym list alone is insufficient. |
| UTF-7 direct ASCII versus shifted ASCII | Rejected as a general plaintext/Unicode stealth channel | The shifted spelling is literal visible ASCII such as `+AEE-` in ordinary UTF-8 viewers, editors, diffs, and forensic tools. Equality after a separately selected UTF-7 decoder does not make the raw carrier visually unobtrusive. | A separately scoped, declared-UTF-7 artifact where the operational viewer reliably decodes the charset before human review, plus the normal grammar, recurrence, framing, and baseline evidence. It remains outside the current UTF-8/plaintext focus. |

## Rejected as general stealth channels

| Family | Status | Why it is not a general stealth channel | What could still be useful |
|---|---|---|---|
| ASCII `A` / FULLWIDTH `A` (`U+FF21`) | Rejected as general stealth; duplicate compatibility-alias family | The width difference is normally conspicuous in Latin text and ordinary in CJK/fullwidth contexts. NFKC mapping alone does not make it covert. | An application may use it as an explicit ASCII-only field-validation policy, but it is not a default steganography candidate. |
| Greek final sigma `U+03C2` / medial sigma `U+03C3` at word-final positions | Rejected as a normal identity decoder | Both letters case-fold to `U+03C3` and uppercase to `U+03A3`, but they are distinct positional Greek forms. A final `U+03C3` in ordinary Greek is visibly nonstandard orthography, not canonical, compatibility, semantic, or glyph identity. A correct Unicode `Final_Sigma` context is more complex than a broad Greek-block range. | A caller may request a narrowly grammar-gated spelling-anomaly observation with a pinned Unicode word-boundary/casing table and a baseline. That is not a general stealth decoder or a new built-in identity pair. |

## Already-covered or non-novel families

| Family | Status | Reminder for reviewers |
|---|---|---|
| Bidi isolates/openers | Duplicate | Different isolate opener spellings are the existing bidi-control family unless a genuinely different state/grammar property is shown. |
| Tags, variation selectors, zero-width controls, noncharacters, CESU-8, Japanese iteration marks, script confusables | Duplicate or existing built-in trial family | Check code and tests before claiming a gap. A new carrier spelling is not a new primitive. |
| Ordinary case, whitespace, punctuation, structural parity, lexical synonym choices | Existing generic/built-in family | They need a feature-level distinction and evidence gate; do not resubmit a renamed token alphabet. |

Grammar-dependent markup, line-break representation, and combining-mark order
are candidates rather than rejections. See `docs/CANDIDATE_STEGNO.md` for
their detection-first rules.
