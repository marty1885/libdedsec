# GPT-5.5 fresh-context sampling pass

This pass used three isolated fresh-context GPT-5.5 agents.  Each received the
same standalone hypothesis prompt and was prohibited from inspecting or
modifying the project.  Each wrote only to its own ignored directory under
`.agent-workspaces/`.  A different GPT-5.5 agent independently reproduced and
assessed each proposal before any implementation decision.

No claim below concerns the private offline corpus.  Every decoded bit string
was a harmless, locally specified round trip and remains only a channel
hypothesis.

## Ledger

| Sample | Model | Reasoning | Hypotheses | Independent validation | Disposition |
|---|---|---:|---:|---|---|
| `gpt55-low` | GPT-5.5 | low | 5 | Reproduced narrow round trips; each is an exact configured phrase or lexeme pair. | Reject: existing caller-defined token alphabet / ordered-synonym facility. |
| `gpt55-high` | GPT-5.5 | high | 6 | Reproduced narrow round trips; each is an exact token or scalar-profile pair. | Reject: existing caller-defined token alphabet / ordered-synonym facility. |
| `gpt55-xhigh` | GPT-5.5 | extra high | 4 | Reproduced narrow round trips; all are table-driven lexical alternatives. | Reject: existing caller-defined token alphabet / ordered-synonym facility. |

The agents tried 15 proposed channel instances in total.  All 15 were rejected
as *new primitives* after validation.  Consequently this pass intentionally
adds no decoder, detector, fixture, ABI surface, or payload-specific rule.

## Deduplicated results

| Underlying feature | Proposals considered | Validation result and caveat |
|---|---|---|
| Scheduled lexical/phrase alternatives | SI rescaling, redundant weekday dates, boolean wording, coordinate notation, numeral words; dialect spellings, kana/kanji, SI name/symbol, Greek name/glyph; CJK word variants and loanword accents | Exact extraction works under a caller-provided registry, but this is precisely a caller-defined token alphabet / ordered synonym-pair channel.  Natural style, locale, quoted text, and mixed authorship yield high false-positive rates. |
| Visible scalar or mark profiles | Arabic tatweel placement and Hebrew pointing | Exact profiles can be recognized, but are still configured scalar-token patterns; ordinary calligraphy, education, religious, and styled text are strong negative context. |
| Digit repertoire | ASCII versus Arabic-Indic digits; common versus financial CJK numerals | Numeric projection can be deterministic only in tightly configured fields.  This remains digit-shape/homoglyph- or lexical-alternative-adjacent and is already gated by prior scope; multilingual and OCR data make ambient matches likely. |

For every rejected item, a generic exact byte/scalar matcher with caller-defined
symbols already suffices.  Optional validators (SI arithmetic, Gregorian
weekday computation, coordinate parsing, or a numeric-context predicate) can
raise confidence in a caller extension, but they do not constitute a new
steganographic extraction primitive.

## Evidence controls retained

- An isolated matching token is not evidence of a message.
- Any future investigation must supply framing, recurrence, a checksum,
  cross-record correlation, or another independent signal before elevation.
- Strict UTF-8 remains required for Unicode-aware candidates.  No malformed
  encoding was proposed for normal decoding.
- The sampling stopped after all fresh proposals converged on the existing
  configurable token/profile abstraction; continuing would be circular.

The complete untrusted proposals and validator reports are intentionally kept
outside the tracked tree in `.agent-workspaces/` for audit during this working
session.

## Follow-up model-diversity null result

The same bounded fresh-context generation brief was submitted through OpenCode
to `opencode/muse-spark-1.3-contributor-free`.  Muse explicitly returned
`NULL RESULT` after roughly 30 seconds.  GPT-5.6 Luna independently confirmed
that the captured response contained no carrier, extraction procedure, round
trip, or primitive to validate.  The sample therefore contributes zero
implementation candidates and no regression tests.
