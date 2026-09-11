# Red-team model ledger

This ledger separates model idea generation from actual repository coverage.
An item is not treated as an incident or a discovered corpus payload.  It is a
candidate only until its exact carrier, extractor, implementation behavior,
negative controls, and evidence gates are independently checked.

| Pass | Model / reviewer | Scope inspected | Result | Disposition |
|---|---|---|---|---|
| `muse-coverage-evasion-1` | Muse Spark 1.3 Contributor Free, through OpenCode | Built-in detection/decoding against three proposed representation families | Submitted NBSP-space identity, canonical composition identity, and non-breaking-hyphen identity. | Pending independent verification at submission. |
| `codex-muse-reproduction-1` | Codex independent reproduction | Fresh `/tmp` C11 build; exact four-symbol carriers; `dedsec_detect_all()` and caller-supplied generic extraction | All three supplied carriers produce zero built-in findings. The generic map/token primitives recover `0101` (`0x50`, 4 bits). | Implementation gap verified; channel intent and evidence confidence remain unverified. |
| `luna-coverage-evasion-1` | GPT-5.6 Luna | Intended independent red-team report | Halted before use because the Muse report was written into its assigned workspace. | No Luna result; do not attribute that report to Luna. |
| `blue-identity-1` | Codex implementation | Fixed reviewed Unicode identity registry | Added the `identity` built-in and exact positive, negative, and malformed-input regressions for all three verified gaps. | Built-in implementation and executable validation completed; evidence gating remains caller/investigator work. |
| `luna-controller-trial-1` | GPT-5.6 Luna, high reasoning | Current source, tests, and documentation; bounded red-team coverage trial | Proposed LF/LINE SEPARATOR, ASCII/fullwidth `A`, and reversed combining-mark-order carriers. | All require independent validation; no implementation authorized by this row. |
| `terra-controller-validation-1` | GPT-5.6 Terra, high reasoning | Fresh build and independent probes of the Luna report | Reproduced all three raw generic-map round trips and zero current findings. | Defer all: LF/LINE SEPARATOR lacks a demonstrated grammar; fullwidth and combining-order are documented unimplemented families. |
| `blue-unicode-lines-and-marks-1` | Codex implementation | Three validated Unicode representation candidates | Added LF/LINE SEPARATOR and CRLF/LINE SEPARATOR lanes plus the reviewed exact combining-order identity pair. | Built-in and regression-validated; decoded bits remain hypotheses and default-alert use remains grammar/baseline-gated. |
| `blue-eol-hspace-1` | Codex implementation | Existing trailing-EOL whitespace feature | Generalized two-width trailing-horizontal-space detection and decoding. | Built-in and regression-validated; whitespace normalization remains a false-positive caveat. |
| `luna-redteam-round2` | GPT-5.6 Luna, high reasoning | Fresh source/test-led review of Unicode and documented parser-source tracks | Submitted LF/NEL, JSON solidus spelling, and quoted-printable soft-break placement. | Independently reproduced, then deferred: one existing opt-in Unicode observation and two duplicate generic-primitive tracks. |
| `terra-validate-luna-round2` | GPT-5.6 Terra, high reasoning | Fresh build and independently recreated Luna carriers | All three generic maps yielded `55 55 55 55` with zero built-in findings. | No new implementation: LF/NEL stays an opt-in observation; JSON/QP remain out-of-focus parser-source tracks. |
| `luna-redteam-round3` | GPT-5.6 Luna, high reasoning | Fresh source/test-led review | Submitted UTF-7 direct/shifted ASCII, C digraphs, and an HTML entity alias. | Interrupted before validation: UTF-7 fails raw-viewer stealth; C is format-specific; HTML violates the current Unicode-first scope. |
| `luna-redteam-round4` | GPT-5.6 Luna, high reasoning | Fresh Unicode/plaintext-only audit using updated raw-viewer rule | `NULL RESULT`: zero candidates survive scope, duplication, and evidence gates. | Saturation recorded; no validator or implementation required. |
| `terra-redteam-round1` | GPT-5.6 Terra, high reasoning | Fresh Unicode/plaintext-only audit | Submitted Mongolian FVS1/FVS2 and `a + U+0301`/`a + U+0341`. | Independently reproduced; both are duplicate families with exact opt-in implementation gaps, not evidence-gated findings. |
| `luna-validate-terra-round1` | GPT-5.6 Luna, high reasoning | Fresh strict-C11 reproduction plus local Unicode/rendering checks | Both exact 32-slot lanes yield `55 55 55 55` and zero built-in findings. | Defer: Mongolian needs a pinned shaping context; acute is conditional-default only in an explicitly NFC-required field. |
| `blue-mongolian-fvs-1` | Codex implementation | Independently reproduced Mongolian FVS1/FVS2 exact selector lane | Added a bounded raw FVS1/FVS2 detector and conditional decoder after `U+1820`. | Built-in and regression-validated; remains an opt-in, font/context-dependent covert-channel observation. |
| `blue-composite-symbols-1` | Codex implementation | Cross-family threshold-evasion attacker model | ABI-v3 callbacks expose parameter-free symbol values and exact spans; a generic source-order gluer reconstructs selected non-overlapping events. | Multiplexed 16+16-bit regression reconstructs `OKOK` with zero standalone aggregate findings; elevation remains caller/evidence-gated. |
| `muse-unicode-round-1` | Muse Spark 1.3 Contributor Free, through OpenCode | Fresh Unicode/plaintext hypothesis generation | Considered 9 hypotheses; submitted Greek final/medial sigma at final-word slots and rejected eight duplicates/weak ideas. | Independently validated, then rejected as a normal identity/stealth decoder; see `luna-sigma-validate-1`. |
| `luna-sigma-validate-1` | GPT-5.6 Luna, high reasoning | Independent final/medial Greek sigma reproduction | Confirmed strict UTF-8, case-fold/uppercase collapse, and normalization stability, but found a visible positional spelling distinction and unsafe broad-range grammar. | Reject built-in normal decoder; only a caller-requested, grammar/baseline-gated anomaly observation remains conceivable. |
| `gpt55-unicode-round-1` | Requested GPT-5.5, high reasoning (report self-identifies generically as GPT-5) | Fresh Unicode/plaintext hypothesis generation | Considered 18 hypotheses; submitted Arabic tatweel run length and SPACE/Braille Pattern Blank gap spelling. | Tatweel independently validated as an existing caller-configured, opt-in slot observation; no dedicated detector. Braille blank joins the existing opt-in gap/whitespace candidate track; it is not a new module. |
| `luna-tatweel-validate-1` | GPT-5.6 Luna, high reasoning | Independent U+0640 one/two-run reproduction | Confirmed strict-valid, normalization-stable raw runs and visible shaping distinction; found the mechanism already expressible with caller token/scalar facilities and unsafe to generalize by Arabic ranges. | Opt-in only with caller-defined complete slots; no built-in decoder or broad Arabic detector. |
| `terra-unicode-round2` | GPT-5.6 Terra, high reasoning | Fresh Unicode/plaintext coverage-evasion pass | `NULL RESULT` after 18 hypotheses; all were duplicate, grammarless, visibly weak, malformed, or circular under the current registers. | Saturation signal recorded; escalated to a fresh Sol pass for model diversity. |
| `sol-implicit-bidi-round1` | Sol red-team generation pass | Fresh Unicode/plaintext source-order review | Proposed exact LF-terminated `a/ALEF/1` versus `a/1/ALEF` records whose implicit UAX #9 LTR display order collides. | Sent to independent Luna validation; no general bidi implementation implied. |
| `luna-implicit-bidi-validate-1` | GPT-5.6 Luna, high reasoning | Independent UAX #9, strict UTF-8, normalization, FriBidi/ICU, and current-detector validation | Confirmed visual maps/levels and 32-slot `55 55 55 55` round trip; current built-ins emit zero findings. | Opt-in only: exact fixed grammar is feasible, but logical semantics, protocol context, overlap, false positives, and novelty block default elevation. |
| `blue-implicit-bidi-1` | Codex implementation | Bounded exact LTR source-order collision lane | Added strict prevalidation, exact five-byte LF records, ABI-v3 symbol provenance, standard 32/8/20% gate, decoder, and negative/interaction regressions. | Built-in and regression-validated observation; evidence-gated intent status remains unmet. |
| `blue-five-bit-opaque-filter-1` | Codex controller implementation | Non-byte-aligned five-bit packed Latin ciphertext | A 165-bit synthetic stream routes as `POSSIBLE | OPAQUE_DATA`. | Regression added; format attribution remains an operator/backend decision. |
| `luna-max-classical-filter-review-1` | GPT-5.6 Luna, max | Classical-cipher, arbitrary-width, phase, and transform-order audit | Six findings; reproduced accidental UTF-8 promotion, phase rejection, post-radix transform loss, tie loss, unassessed tails, and bounded hard-gate limitations. | Actionable defects accepted; policy tradeoffs retained. |
| `luna-max-opaque-threshold-review-1` | GPT-5.6 Luna, max | Opaque threshold and recursive decoding audit | Reproduced depth-two opaque loss, phase penalty rejection, numeric-flag tie loss, tail loss, and unavoidable random-data volume. | Actionable defects accepted; random-data ambiguity documented. |
| `luna-max-filter-api-review-1` | GPT-5.6 Luna, max | Filter API, source-bit accounting, and provenance audit | Reproduced ambiguous decoded length, missing bit-consumption metadata, hidden competing interpretations, and malformed packed storage acceptance. | API/result defects accepted; detection events remain the noncontiguous carrier provenance source. |
| `blue-filter-paranoia-repair-1` | Codex controller implementation | Repair of three independent Luna max audits | ABI v5 adds source/tail/ordered-transform metadata and fixes depth, phase, ranking, post-radix, UTF-8-control, and storage-validation defects. | Implemented with exact positive, negative, malformed, and ambiguity regressions. |
| `blue-case-serial-filter-1` | Codex controller implementation | False opaque promotion from natural case regimes | Globally balanced uppercase/lowercase blocks and period-two novelty case are low serial complexity despite shifted byte diversity. | Opaque promotion gated; symbols and provenance retained for explicit run-length/periodic analysis. |
| `research-case-complexity-1` | Codex controller experiment | Compression and sequential-complexity separation for the high-noise word-initial-case lane | 5,500 natural, 2,200 encoded, and 44 styled streams tested at 16–512 bits; raw DEFLATE fails short, while KT/period models separate strongly from about 40–64 bits in this bounded corpus. | Promising research result only; require broader stratified baselines before library thresholds. |
| `blue-bitstream-scorers-1` | Codex controller implementation | Public run, KT, periodic, LZ78, linear-complexity scorers and default-filter integration | Exact scorer, short/limit/malformed, opaque, periodic, and LFSR regressions pass; natural long controls remain simple. | Implemented as explainable triage; scores and structure flags are hypotheses, not probabilities or attribution. |

## Append an experiment

For every new model or verification pass, append **both** of the following:

1. One row to the ledger table above.
2. One `### <pass-id>` section under **Experiment records**, using this form:

```md
### <pass-id>

- Model / reasoning / workspace:
- Role: red team, validator, reproducer, or blue team.
- Scope and hypotheses tried:
- Exact carrier(s) or null result:
- Independent verification result:
- Coverage labels reached: model-known / generic primitive / built-in /
  regression-validated / evidence-gated.
- Outcome: implement, defer, reject, or null result.
- False-positive and evidence-gate caveats:
- Changed files and verification commands, if implementation occurred:
```

Keep reports in their isolated workspaces, but summarize the evidence needed to
audit the decision here. Never change a prior entry's ownership; append a
correction pass if attribution or validation changes. `NULL RESULT` is a
successful experiment outcome when the model cannot satisfy the candidate bar;
record its stopping reason and do not pad the report with weaker ideas.

## Experiment records

### muse-coverage-evasion-1

- Model / reasoning / workspace: Muse Spark 1.3 Contributor Free through
  OpenCode; report was misplaced in `.agent-workspaces/luna-detection-evasion/`.
- Role: red team.
- Scope and hypotheses tried: 11; three reported below and eight rejected or
  deduplicated by the author.
- Outcome: three candidates submitted for independent reproduction.
- False-positive and evidence-gate caveats: each candidate requires placement,
  framing, and recurrence controls; the individual limitations are in the table.

| Family | Exact binary choice | Built-in coverage status | What independent reproduction establishes | Critical caveat |
|---|---|---|---|---|
| Inter-word space identity | `U+0020` (`20`) / `U+00A0` (`C2 A0`) | Built-in layout whitespace features use ASCII space/tab run width only. | A four-gap `0101` carrier has zero findings; a caller-supplied Unicode code-point alphabet extracts four bits. | NBSP changes line-breaking and tokenization; it only preserves human-readable separation, not full semantic equivalence. Legitimate typography is common. |
| Canonical composition identity | `U+00E9` (`C3 A9`) / `U+0065 U+0301` (`65 CC 81`) | No built-in normalization-alias detector or decoder. | A four-slot `0101` carrier has zero findings; caller-supplied byte-token matching extracts four bits. | This is a known *family* but an unimplemented built-in. Natural NFC/NFD mixing is a substantial false-positive source. |
| Hyphen identity | `U+002D` (`2D`) / `U+2011` (`E2 80 91`) | Built-in punctuation choices cover only comma/semicolon and period/question mark. | A four-slot `0101` carrier has zero findings; caller-supplied Unicode code-point matching extracts four bits. | U+2011 deliberately changes line-breaking; visual/function similarity is not unrestricted semantic equivalence. Typography and identifiers naturally mix hyphens. |

Independent probe source and build products were kept in `/tmp`; no repository
source or test was changed.  The probe rebuilt with the required C11 warning
policy and printed `verified` only after checking all three zero-finding and
generic-extraction assertions.

### codex-muse-reproduction-1

- Model / reasoning / workspace: Codex independent reproduction; fresh `/tmp`
  build and probe, no project-source edits.
- Role: reproducer.
- Scope and hypotheses tried: the three exact Muse four-symbol carriers.
- Exact carriers or null result: SPACE/NBSP, `é`/`e + acute`, and
  hyphen-minus/non-breaking-hyphen, all with expected `0101` bits.
- Independent verification result: each yielded zero built-in findings and the
  appropriate generic caller map/token table yielded `0x50` at four bits.
- Coverage labels reached: model-known and generic primitive only at this pass.
- Outcome: verified implementation gaps; deferred elevation pending blue-team
  gates and regressions.
- False-positive and evidence-gate caveats: preserved from the Muse table;
  semantic equivalence is intentionally narrower than byte identity.
- Changed files and verification commands, if implementation occurred: none.

### luna-coverage-evasion-1

- Model / reasoning / workspace: GPT-5.6 Luna; intended
  `.agent-workspaces/luna-detection-evasion/`.
- Role: independent red team.
- Scope and hypotheses tried: none attributable to Luna.
- Exact carriers or null result: null result for attribution purposes; Muse
  wrote its report into this workspace before Luna could be used.
- Independent verification result: not applicable.
- Coverage labels reached: none.
- Outcome: halted; this pass must be rerun in a clean workspace if needed.
- False-positive and evidence-gate caveats: not applicable.
- Changed files and verification commands, if implementation occurred: none.

### blue-identity-1

- Model / reasoning / workspace: Codex implementation; review inputs from
  `.agent-workspaces/luna-detection-evasion/REPORT.md` and independent `/tmp`
  reproduction.
- Role: blue team.
- Scope and hypotheses tried: fixed Unicode identity registry for the three
  independently reproduced implementation gaps.
- Exact carriers: the three four-symbol `0101` carriers recorded above, plus
  32-slot alternating regression carriers.
- Independent verification result: all three original carriers had zero
  built-in findings and caller-provided extraction recovered the expected bits.
- Coverage labels reached: model-known, generic primitive, built-in,
  regression-validated; not evidence-gated.
- Outcome: implemented as the `identity` module; framing, grammar, recurrence,
  and trial accounting remain external evidence requirements.
- False-positive and evidence-gate caveats: NBSP and non-breaking hyphens alter
  line breaking; mixed NFC/NFD and ordinary typography remain expected.
- Changed files and verification commands: `src/module_identity.c`, registry,
  tests, and docs; strict C11 CTest, ASan/UBSan, and focused Clang analysis pass.

### luna-controller-trial-1

- Model / reasoning / workspace: GPT-5.6 Luna, high;
  `.agent-workspaces/luna-controller-trial-1/`.
- Role: red team.
- Scope and hypotheses tried: source/test-led detection-evasion review; three
  candidates submitted, with further bidi, selector/tag, legacy encoding,
  surface-syntax, BOM, and ordinary lexical-choice ideas rejected as duplicate,
  gated, or insufficiently distinct.
- Exact carriers or null result: alternating 32-slot `0101` lanes for LF
  (`0A`) / LINE SEPARATOR (`E2 80 A8`); `A` (`41`) / FULLWIDTH `A`
  (`EF BC A1`); and `a + U+0323 + U+0301` (`61 CC A3 CC 81`) /
  `a + U+0301 + U+0323` (`61 CC 81 CC A3`).
- Independent verification result: recorded by `terra-controller-validation-1`;
  do not rely on this author report alone.
- Coverage labels reached: model-known proposed; generic primitive claimed;
  built-in, regression-validated, and evidence-gated not established here.
- Outcome: deferred to independent validation; no source changes.
- False-positive and evidence-gate caveats: all candidates require bounded
  grammar, raw-byte preservation, balanced slots, framing/integrity or
  cross-record recurrence, and trial accounting.  Fullwidth forms and
  combining order have substantial natural-text false-positive sources.
- Changed files and verification commands, if implementation occurred: none;
  report includes its own fresh-build probe.

### terra-controller-validation-1

- Model / reasoning / workspace: GPT-5.6 Terra, high;
  `.agent-workspaces/terra-controller-validation-1/`.
- Role: independent validator.
- Scope and hypotheses tried: independently recreated all three exact Luna
  carriers against a fresh C11 build, without author-supplied code.
- Exact carriers or null result: the three 32-slot alternating lanes listed in
  `luna-controller-trial-1`; each generic extraction produced `55 55 55 55`.
- Independent verification result: `dedsec_detect_all()` returned zero
  findings for every carrier; caller-supplied code-point/token maps extracted
  32 bits.  Existing line-ending decoders recover only their ASCII LF subset,
  not the mixed LF/LINE-SEPARATOR lane.
- Coverage labels reached: model-known and generic primitive only.  No new
  built-in, executable regression, or evidence gate was justified.
- Outcome: defer all three.  LF/LINE SEPARATOR needs a named, demonstrated
  grammar that accepts both delimiters.  Fullwidth `A` is a documented
  compatibility-alias family needing Unicode-version-pinned data and a field
  contract.  Combining-mark order is the already documented combining-order
  family, also requiring pinned data and a bounded cluster grammar.
- False-positive and evidence-gate caveats: legitimate Unicode separators,
  CJK/fullwidth text, and decomposed-mark processing are realistic sources.
  Require 32 complete slots, at least eight of each spelling, 20% minority,
  exact placement, raw provenance, and framing/checksum or independently
  accounted recurrence before elevation.
- Changed files and verification commands, if implementation occurred: none.
  Fresh CMake build and CTest passed; the independently written public-API
  probe reported zero findings and `55555555` for each generic extraction.

### blue-unicode-lines-and-marks-1

- Model / reasoning / workspace: Codex implementation; repository working tree.
- Role: blue team.
- Scope and hypotheses tried: the validated LF/LINE SEPARATOR and
  CRLF/LINE SEPARATOR raw line-ending lanes, plus the exact canonical
  `a + dot-below + acute` / `a + acute + dot-below` order pair.
- Exact carriers or null result: each new lane has a 32-slot alternating
  `0101` regression carrier with expected `55 55 55 55`; constant-only lanes
  are detector negatives. The line decoders also receive truncated `E2 80` as
  a malformed UTF-8 negative.
- Independent verification result: the preceding Terra pass independently
  reproduced the raw generic-map behavior. This implementation adds fixed
  reviewed variants rather than treating generic maps as automatic detection.
- Coverage labels reached: model-known, generic primitive, built-in, and
  regression-validated. Evidence-gated is not reached.
- Outcome: implemented. The structure scanner treats CRLF as one token before
  LF, so it cannot leak an overlapping LF bit. The identity table matches only
  the reviewed canonical-order pair after strict UTF-8 validation.
- False-positive and evidence-gate caveats: default promotion still needs a
  line grammar or corpus baseline; combining-order observations need a
  normalization contract or baseline. Bits are hypotheses, not intent.
- Changed files and verification commands, if implementation occurred:
  `src/module_structure.c`, `src/module_identity.c`, tests, and docs;
  CMake Debug build with CTest passed.

### blue-eol-hspace-1

- Model / reasoning / workspace: Codex implementation; repository working tree.
- Role: blue team.
- Scope and hypotheses tried: existing trailing-EOL horizontal-whitespace
  feature, generalized from the legacy widths 1/2 convention.
- Exact carriers or null result: 32 lines with alternating one and two ASCII
  spaces before LF. The built-in low-bit lane yields `AA AA AA AA`; an explicit
  caller rule mapping width 1 to zero and width 2 to one yields `55 55 55 55`.
  Thirty-two one-space lines are a detector negative.
- Independent verification result: implementation regression verifies both
  streams and the balanced two-width detector gate.
- Coverage labels reached: built-in and regression-validated, in addition to
  the prior generic feature primitive. Evidence-gated is not reached.
- Outcome: implemented as `trailing-hspace-width-low-bit` and the
  caller-configured `trailing-hspace-rule`; only positive trailing runs become
  low-bit symbols.
- False-positive and evidence-gate caveats: editors, copy/paste, and whitespace
  stripping/normalization can create or erase the feature. Treat findings as
  hypotheses and require framing/recurrence or a baseline before elevation.
- Changed files and verification commands, if implementation occurred:
  `src/module_layout.c`, tests, and docs; strict C11 CMake Debug build with
  CTest passed.

### luna-redteam-round2

- Model / reasoning / workspace: GPT-5.6 Luna, high;
  `.agent-workspaces/luna-redteam-round2/`.
- Role: red team.
- Scope and hypotheses tried: three bounded representation claims after a
  source/test/docs review: LF/NEL line separators, RFC 8259 solidus spelling,
  and RFC 2045 quoted-printable soft-break placement.
- Exact carriers or null result: 32 alternating `x LF` (`78 0A`) / `x NEL`
  (`78 C2 85`) slots; a valid 32-string JSON array alternating `"/"` and
  `"\\/"`; and a declared quoted-printable body alternating `ab,` and
  `a=CRLFb,`. The author reported generic-map output `55 55 55 55` and zero
  built-in findings for each.
- Independent verification result: recorded by `terra-validate-luna-round2`;
  do not treat the author probe as validation.
- Coverage labels reached: model-known proposals and generic primitives only;
  built-in, regression-validated, and evidence-gated status were not reached.
- Outcome: defer pending independent validation; no source changes.
- False-positive and evidence-gate caveats: each claim needs a bounded
  conforming grammar, complete non-overlapping slots, 32 occurrences with at
  least eight of each and a 20% minority, trial accounting, and framing or
  cross-record recurrence. Default alerting also needs a field contract or
  corpus baseline.
- Changed files and verification commands, if implementation occurred: none;
  author report records an existing-build CTest pass and a temporary probe.

### terra-validate-luna-round2

- Model / reasoning / workspace: GPT-5.6 Terra, high;
  `.agent-workspaces/terra-validate-luna-round2/`.
- Role: independent validator.
- Scope and hypotheses tried: independently recreated all three Luna carriers
  against a fresh C11 build without using author code or conclusions.
- Exact carriers or null result: LF/NEL, valid JSON `"/"` / `"\\/"`, and
  header-declared quoted-printable `ab,` / `a=CRLFb,` lanes. Every supplied
  generic map yielded 32 bits `55 55 55 55`; `dedsec_detect_all()` returned
  zero findings.
- Independent verification result: LF/NEL is valid Unicode but is only the
  existing future line-break observation; it requires a caller-selected line
  grammar. JSON and quoted-printable have their stated narrow standardized
  relations but are duplicate generic parser-source/transport tracks, not
  built-in semantic detectors or implementation-ready gaps.
- Coverage labels reached: model-known and generic primitive only. No built-in,
  regression-validated, or evidence-gated coverage was established.
- Outcome: validated null implementation result; defer all three. No source
  change is authorized by this experiment.
- False-positive and evidence-gate caveats: NEL occurs in Unicode/mainframe
  conversion contexts; serializers may always escape solidus; mail tools and
  gateways routinely introduce quoted-printable soft breaks. All require a
  strict selected grammar, placement/balance controls, framing or recurrence,
  and a baseline or field contract before default alerting.
- Changed files and verification commands, if implementation occurred: none.
  Fresh CMake build and CTest passed; an independently written public-API probe
  reproduced the raw generic maps.

### luna-redteam-round3

- Model / reasoning / workspace: GPT-5.6 Luna, high;
  `.agent-workspaces/luna-redteam-round3/`.
- Role: red team.
- Scope and hypotheses tried: UTF-7 direct/shifted ASCII, ISO C11 array
  digraph punctuators, and an HTML named-reference case alias.
- Exact carriers or null result: `A` (`41`) / UTF-7 `+AEE-`
  (`2B 41 45 45 2D`); C `[`/`]` versus `<:`/`:>`; and `&amp;`/`&AMP;`.
- Independent verification result: validation was intentionally interrupted
  after review of the author report. The first carrier visibly renders as
  `+AEE-` in ordinary UTF-8 viewers, so a separately selected UTF-7 decoder
  cannot establish raw-carrier stealth. The second is a grammar-dependent C
  source track; the third violates the current Unicode-first scope.
- Coverage labels reached: model-known proposal only. No generic primitive,
  built-in, regression-validated, or evidence-gated status was accepted.
- Outcome: reject UTF-7 as a general plaintext/Unicode stealth channel;
  defer C as a future format-specific track; reject the HTML submission as
  out of scope. No implementation or validation continuation.
- False-positive and evidence-gate caveats: raw display must be evaluated
  before any semantic decoding claim. A declared legacy charset, C grammar, or
  markup grammar cannot by itself establish covertness or justify a default
  alert.
- Changed files and verification commands, if implementation occurred: none.

### luna-redteam-round4

- Model / reasoning / workspace: GPT-5.6 Luna, high;
  `.agent-workspaces/luna-redteam-round4/`.
- Role: red team.
- Scope and hypotheses tried: complete Unicode/plaintext review under the
  updated raw-viewer stealth rule; no candidate was submitted.
- Exact carriers or null result: `NULL RESULT`, count 0. The model found only
  duplicate built-ins/tracks, visibly conspicuous or format-specific ideas, or
  malformed/unspecified behavior. It explicitly declined to repeat LF/NEL,
  fullwidth, UTF-7, parser, or MIME proposals without new grammar, baseline,
  framing, recurrence, or detector evidence.
- Independent verification result: not applicable; no carrier or claim exists
  to reproduce.
- Coverage labels reached: none.
- Outcome: null result; stop this sampling path rather than pad it with weaker
  ideas.
- False-positive and evidence-gate caveats: no corpus was inspected; the null
  result establishes only this model/pass's bounded search saturation, not a
  claim of universal channel coverage.
- Changed files and verification commands, if implementation occurred: no
  project source changed. The report records an existing strict C11 build and
  CTest pass.

### terra-redteam-round1

- Model / reasoning / workspace: GPT-5.6 Terra, high;
  `.agent-workspaces/terra-redteam-round1/`.
- Role: red team.
- Scope and hypotheses tried: Unicode/plaintext-only review. Submitted two
  candidates and stopped rather than adding a third weak candidate.
- Exact carriers or null result: 32 alternating `U+1820 U+180B` (`E1 A0 A0 E1
  A0 8B`) / `U+1820 U+180C` (`E1 A0 A0 E1 A0 8C`) slots, and 32 alternating
  `a U+0301` (`61 CC 81`) / `a U+0341` (`61 CD 81`) slots; both use an explicit
  delimiter and expect `55 55 55 55`.
- Independent verification result: recorded by `luna-validate-terra-round1`;
  do not rely on the author report alone.
- Coverage labels reached: model-known and generic primitive proposed only;
  built-in, regression-validated, and evidence-gated status not established.
- Outcome: defer to independent validation; no source changes.
- False-positive and evidence-gate caveats: Mongolian selectors are shaping
  and context dependent; canonical acute spellings occur in legacy and uneven
  normalization data. Both need raw spans, complete bounded slots, balance,
  framing/recurrence, and trial accounting.
- Changed files and verification commands, if implementation occurred: none.

### luna-validate-terra-round1

- Model / reasoning / workspace: GPT-5.6 Luna, high;
  `.agent-workspaces/luna-validate-terra-round1/`.
- Role: independent validator.
- Scope and hypotheses tried: independently recreated the two Terra 32-slot
  carriers using a strict C11 public-API probe; inspected Unicode 16/ICU
  normalization data and bounded local rendering behavior without a corpus.
- Exact carriers or null result: both slots reproduce `55 55 55 55`; built-in
  detection returns zero findings. Malformed `C0 AF` is rejected by strict
  UTF-8 and produces only the invalid-UTF-8 finding.
- Independent verification result: `U+1820` plus FVS1/FVS2 is a strict-valid,
  non-normalizing, font/context-dependent selector lane; general FVS remains
  ternary because FVS3 exists. `a + U+0341` canonically decomposes to `a +
  U+0301`; local rendering was indistinguishable but not universal. The
  validator did not support the author's word “deprecated” for U+0341, which
  is not needed for the canonical-equivalence claim.
- Coverage labels reached: model-known and generic primitive only. Each is an
  exact implementation gap within an already documented feature family; neither
  is built-in, regression-validated, or evidence-gated.
- Outcome: defer. Mongolian is opt-in only with a Unicode-version-pinned
  shaping and slot grammar. The acute identity is opt-in generally and can be
  a conditional default anomaly only in an explicitly NFC-required field.
- False-positive and evidence-gate caveats: valid Mongolian orthography,
  fonts, keyboard/editor behavior, legacy data, and uneven normalization are
  plausible benign causes. Require 32 complete slots, 8/8/20% balance, exact
  placement, framing/checksum or independently accounted recurrence, and
  trial-count accounting before elevation.
- Changed files and verification commands, if implementation occurred: none.
  The validator records fresh strict C11 probe and CTest success.

### blue-mongolian-fvs-1

- Model / reasoning / workspace: Codex implementation; repository working
  tree, using the independent Terra/Luna reports above.
- Role: blue team.
- Scope and hypotheses tried: the reviewed exact `U+1820 + FVS1` / `U+1820 +
  FVS2` binary selector lane only. FVS3 and all other bases are intentionally
  outside the built-in bit convention.
- Exact carriers or null result: 32 alternating `E1 A0 A0 E1 A0 8B` /
  `E1 A0 A0 E1 A0 8C` slots decode MSB-first to `55 55 55 55`; all-FVS1 and
  all-FVS3 carriers are detector negatives; truncated UTF-8 is malformed.
- Independent verification result: Luna independently reproduced the source
  lane and confirmed it is strict-valid but font/context-dependent. It is not
  a claim of universal glyph or semantic equality.
- Coverage labels reached: model-known, generic primitive, built-in, and
  regression-validated. Evidence-gated is not reached.
- Outcome: implemented as `unicode/mongolian-fvs-binary-symbols` with decoder
  `mongolian-fvs1-fvs2-bits-msb`. The detector requires 32 symbols, at least
  eight of each value, and a 20% minority floor.
- False-positive and evidence-gate caveats: legitimate Mongolian shaping,
  fonts, keyboard input, and editor/toolchain transformations can produce
  selectors. Treat any extracted bits as a hypothesis; require a pinned
  shaping/field grammar, framing or recurrence, and trial accounting before
  elevation. Default-alert use needs a contract or baseline.
- Changed files and verification commands, if implementation occurred:
  `src/module_unicode.c`, `tests/test.c`, README, candidate/verified-channel
  docs, and this ledger; strict C11 CTest, Clang ASan/UBSan (with leak checks
  disabled for the ptrace-constrained environment), focused Clang analysis, and
  `git diff --check` passed.

### blue-composite-symbols-1

- Model / reasoning / workspace: Codex attacker/blue-team implementation;
  repository working tree.
- Role: red team and blue team.
- Scope and hypotheses tried: an attacker alternates several reviewed carrier
  families so every individual family remains below its aggregate recurrence
  gate, then reconstructs bits in raw source order.
- Exact carriers or null result: a 32-bit `OKOK` carrier alternates 16 reviewed
  hyphen-identity symbols with 16 `U+1820` Mongolian-FVS symbols. Each lane is
  below its 32-symbol gate; the callback nevertheless exposes all 32 exact
  values/spans and source-order gluing yields the independent expected bytes.
- Independent verification result: the two underlying lanes were independently
  reproduced in preceding passes. This regression validates their combination,
  not hidden intent or a corpus occurrence.
- Coverage labels reached: built-in symbol observation and regression-validated
  source-order composition. Composite evidence-gated status is not reached.
- Outcome: implemented. ABI version is intentionally raised to 3;
  `dedsec_finding.kind` distinguishes aggregate findings from symbol
  observations, and each symbol includes value, width, offset, and length.
- False-positive and evidence-gate caveats: blindly combining every ordinary
  event manufactures hypotheses. Callers must select reviewed lanes,
  deduplicate overlapping features, enforce recurrence/balance and trial
  budgets, and require framing/checksum or cross-record recurrence before
  elevation. Absence is not a bit without a supplied slot grammar.
- Changed files and verification commands, if implementation occurred: public
  header, core/composite implementation, eligible built-in modules, tests,
  README/controller/candidate/composite docs, and this ledger. GNU strict-C11
  CTest, Clang ASan/UBSan (leak checks disabled in the ptrace-constrained
  environment), focused Clang analysis across all modified emitters, and
  `git diff --check` passed.

### muse-unicode-round-1

- Model / reasoning / workspace: Muse Spark 1.3 Contributor Free through
  OpenCode; `.agent-workspaces/muse-unicode-round/`.
- Role: red team.
- Scope and hypotheses tried: Unicode/plaintext-only pass; nine hypotheses,
  with one proposed survivor: final `U+03C2` versus ordinary `U+03C3` at
  proposed Greek word-final slots.
- Exact carriers or null result: `CF 82` / `CF 83`; author supplied a
  32-symbol alternating carrier expecting `55 55 55 55`.
- Independent verification result: recorded by `luna-sigma-validate-1`.
- Coverage labels reached: model-known and generic primitive only.
- Outcome: reject as a normal built-in identity/stealth decoder.
- False-positive and evidence-gate caveats: the spelling distinction is
  visible to Greek readers; OCR, keyboard, learner, and editorial errors are
  plausible. A broad Greek-block range is not a valid Unicode word grammar.
- Changed files and verification commands, if implementation occurred: none.

### luna-sigma-validate-1

- Model / reasoning / workspace: GPT-5.6 Luna, high;
  `.agent-workspaces/luna-sigma-validate/`.
- Role: independent validator; it was instructed not to inspect Muse's report.
- Scope and hypotheses tried: recreated the final/medial sigma lane, examined
  local Unicode data (including case folding and SpecialCasing), normalization,
  strict UTF-8 behavior, grammar requirements, and repository coverage.
- Exact carriers or null result: `U+03C2` (`CF 82`) / `U+03C3` (`CF 83`);
  narrow test syntax yields alternating `55 55 55 55`.
- Independent verification result: both spellings are strict-valid and stable
  under NFC/NFD/NFKC/NFKD; final sigma folds to ordinary sigma and both
  uppercase to `U+03A3`. This destroys the carrier under folding/uppercasing,
  but does not make the forms semantic or glyph identities. Unicode's true
  `Final_Sigma` condition cannot be replaced by a broad Greek range.
- Coverage labels reached: model-known and generic primitive only.
- Outcome: reject normal decoder and fixed identity implementation. A caller
  may separately request a pinned-grammar spelling-anomaly observation.
- False-positive and evidence-gate caveats: real Greek orthography is heavily
  one-sided at word ends; misplaced forms can still arise from OCR, input,
  learners, editorial material, and transformations. Count/balance alone is
  not evidence of hidden data.
- Changed files and verification commands, if implementation occurred: none.

### gpt55-unicode-round-1

- Model / reasoning / workspace: requested GPT-5.5, high;
  `.agent-workspaces/gpt55-unicode-round/`. The report's self-description says
  only “GPT-5 agent context”; retain the requested orchestration model and do
  not treat the self-label as independent model verification.
- Role: red team.
- Scope and hypotheses tried: 18 Unicode/plaintext hypotheses. Submitted two:
  Arabic tatweel run length and SPACE/BRAILLE PATTERN BLANK in defined gap
  slots; the other 16 were rejected as duplicate, malformed, or weak.
- Exact carriers or null result: tatweel uses one `U+0640` (`D9 80`) versus two
  adjacent `U+0640` scalars in caller-defined joining-word slots; the gap
  spelling uses SPACE (`20`) versus `U+2800` (`E2 A0 80`). Both author
  diagnostics are alternating 32-slot streams expecting `55 55 55 55`.
- Independent verification result: `luna-tatweel-validate-1` confirmed that
  tatweel needs a complete caller slot grammar and is already expressible by
  configured token/scalar facilities. The braille blank proposal is admitted
  only to the existing opt-in gap/whitespace candidate track, without a new
  primitive.
- Coverage labels reached: model-known and generic primitive for tatweel;
  model-known candidate observation for the gap spelling.
- Outcome: retain tatweel as caller-configured opt-in observation only; retain
  the gap spelling as an opt-in candidate. Neither is a default alert or new
  built-in decoder.
- False-positive and evidence-gate caveats: tatweel is decorative/justification
  typography with shaping and field-context dependence. `U+2800` is a graphic
  braille character, not a semantic space; copy/paste, braille material, and
  accessibility tools make visual similarity insufficient. Both require exact
  grammar, raw spans, balance, recurrence/framing, and baseline/trial control.
- Changed files and verification commands, if implementation occurred: none.

### luna-tatweel-validate-1

- Model / reasoning / workspace: GPT-5.6 Luna, high;
  `.agent-workspaces/luna-tatweel-validate/`.
- Role: independent validator; it was instructed not to inspect other agent
  reports.
- Scope and hypotheses tried: exact one/two `U+0640` run lengths in a
  caller-defined Arabic joining slot, including UTF-8, normalization, joining,
  shaping, false positives, source-order provenance, and current generic
  facilities.
- Exact carriers or null result: one Tatweel is `D9 80`; two are `D9 80 D9
  80`. A narrow `U+0628 U+0640{1,2} U+0628` 32-slot alternating diagnostic
  reconstructs `55 55 55 55` before any display transformation.
- Independent verification result: U+0640 is a strict-valid modifier letter
  with Joining_Type Join_Causing, no normalization decomposition, and a
  visibly longer rendered form in tested Arabic fonts. It has Script=Common
  and broad Script_Extensions, so neither an Arabic block nor a loose script
  range is a safe grammar. Current caller token/scalar maps already provide
  extraction; a general detector would require a pinned Joining_Type table and
  explicit handling of transparent characters/marks.
- Coverage labels reached: model-known and generic primitive only.
- Outcome: opt-in only. Keep it as a caller-configured complete-slot
  observation; do not add a dedicated decoder, a broad Arabic-range scanner,
  or a default finding.
- False-positive and evidence-gate caveats: tatweel is intentional visible
  elongation used for decoration, headings, calligraphy, education, and
  justification. OCR, copy/paste, editors, accessibility processing, and
  kashida-aware applications may alter it. Emit one whole-slot event (not one
  per Tatweel), retain raw source order rather than visual RTL order, avoid
  overlap with generic events, and require grammar, balance, recurrence or
  framing, trial accounting, and baseline before elevation.
- Changed files and verification commands, if implementation occurred: none;
  local UCD, strict-C11 CTest, and font/shaping probes are recorded in the
  isolated validator report.

### terra-unicode-round2

- Model / reasoning / workspace: GPT-5.6 Terra, high;
  `.agent-workspaces/terra-unicode-round2/`.
- Role: red team.
- Scope and hypotheses tried: 18 fresh Unicode/plaintext hypotheses, with a
  specific brief to evade current symbol streams and source-order composition
  without rebranding the documented representation families.
- Exact carriers or null result: `NULL RESULT`.
- Independent verification result: not required: no survivor met the report's
  exact-carrier, bounded-slot, reproducible-round-trip, and novelty bar.
- Coverage labels reached: none beyond model exploration.
- Outcome: saturation signal, not a proof of exhaustive Unicode coverage. A
  separate Sol model-diversity pass was started under the same restrictions.
- False-positive and evidence-gate caveats: the pass stopped rather than
  padding the result with grammarless or visually weak candidates.
- Changed files and verification commands, if implementation occurred: none.

### gemini-flash-3.8-unicode-round1

- Model / reasoning / workspace: Gemini Flash 3.8, medium reasoning;
  externally supplied chat report (no repository workspace or local edits).
- Role: red team, model-diversity null-result pass.
- Scope and hypotheses tried: 10 Unicode/plaintext hypotheses: deprecated
  U+206A..U+206F state controls; supplementary musical and shorthand format
  controls; U+FFF9..U+FFFB interlinear annotation controls; U+034F CGJ;
  U+00AD soft hyphen; regional-indicator parity; valid UTF-8 for unassigned
  scalars; U+2800 versus SPACE; U+2060 versus noninitial U+FEFF; and equal-CCC
  combining-mark permutations.
- Exact carriers or null result: `NULL RESULT`; the supplied report gives
  escaped examples for the individual rejected families but no survivor or
  claimed payload recovery.
- Independent verification result: not required for a null result. The stated
  class-based coverage assertion was deliberately *not* adopted: this project
  has not established exhaustive handling of every `Cf`, `Cc`, `Co`, or
  Default-Ignorable scalar. Concrete duplicate/visibility/grammar objections
  are recorded only as hypotheses for future review.
- Coverage labels reached: none beyond model exploration.
- Outcome: a second model-diversity saturation signal. The U+2800 conclusion
  agrees with the existing candidate gate (no broad detector without a
  realistic baseline); CGJ, SHY, and legacy/supplementary format controls are
  duplicate candidates of existing control/combining/layout feature families
  unless a new bounded contract is demonstrated.
- False-positive and evidence-gate caveats: a `NULL RESULT` does not prove
  Unicode saturation. Unicode-version changes, script-specific grammar,
  renderer/font behavior, and unimplemented generic feature tables remain
  potential gaps and require exact independent reproduction before a result is
  elevated.
- Changed files and verification commands, if implementation occurred: none.

### sol-unicode-round2

- Model / reasoning / workspace: GPT-5.6 Sol, high;
  `.agent-workspaces/sol-unicode-round2/`.
- Role: red team, independent Unicode/plaintext coverage and evasion pass.
- Scope and hypotheses tried: 28 underlying-feature hypotheses. One survivor
  is an inventory gap in the existing Default_Ignorable_Code_Point (DICP)
  family, not a newly claimed channel mechanism; the other 27 were duplicates,
  visibly weak, grammarless, renderer-dependent, or malformed-input cases.
- Exact carriers or null result: the submitted strict UTF-8 diagnostic slots
  are `U+1780 U+17B4 |` (`E1 9E 80 E1 9E B4 7C`) for zero and
  `U+1780 U+17B5 |` (`E1 9E 80 E1 9E B5 7C`) for one. The report's 32-slot
  alternating fixture recovers `55 55 55 55` through the existing
  caller-defined code-point map, while its temporary probe reports zero
  current findings and symbols.
- Independent verification result: pending independent Luna reproduction. No
  implementation follows from this generation result.
- Coverage labels reached: model-known only; a coverage-gap claim is not a
  built-in implementation or evidence-gated finding.
- Outcome: `NOT SATURATED` at the repository-coverage level. The proposed
  generic response, if independently confirmed, is a version-pinned static
  DICP property table shared by detection and transforms, with specialized
  lanes retaining ownership and no implicit bit assignment for the whole
  non-power-of-two property set.
- False-positive and evidence-gate caveats: DICP membership is a raw anomaly
  property, not canonical, semantic, or universal visual equivalence. The
  claimed Khmer rendering is restricted to the reported Pango/Noto test stack;
  script grammar, font/version differences, historical material, and
  reserved-property ranges require conservative observation-only handling.
  Any binary lane remains caller-declared and needs strict complete input,
  slots, balance, framing/recurrence or checksum, baseline, and trial
  accounting.
- Changed files and verification commands, if implementation occurred: none;
  Sol reports an isolated strict-C11 CMake build and CTest pass.

### blue-default-ignorable-inventory-1

- Model / reasoning / workspace: Codex blue-team implementation after Sol
  generation and independent GPT-5.6 Luna validation; repository working tree.
- Role: close a validated implementation-coverage gap in the existing
  Default-Ignorable property family.
- Scope and hypotheses tried: replace two divergent hand-written subsets with
  one reviewed, Unicode-17.0.0-pinned static range predicate. The change is
  intentionally not a Khmer or LRM/RLM bit decoder.
- Exact carriers or null result: the independent diagnostic remains
  `U+1780 U+17B4 |` / `U+1780 U+17B5 |`; 32 alternating slots retain caller
  map output `55 55 55 55`. The built-in result is one aggregate
  `default-ignorable-candidates` observation, no generic bit symbols.
- Independent verification result: Luna confirmed property membership, strict
  UTF-8, current pre-fix evasion, generic extraction, bounded Pango/Noto Khmer
  rendering, and malformed-input ownership. It classified the result as a
  validated inventory gap, not a new feature family.
- Coverage labels reached: built-in implementation and executable regression
  validation; it is not evidence-gated intent detection.
- Outcome: `src/unicode_properties.c` owns the Unicode-17.0.0 static DICP
  ranges and is used by both Unicode observation and the stripping transform.
  Specialized lanes retain their separate symbol/rule ownership.
- False-positive and evidence-gate caveats: property membership does not prove
  visual, semantic, or canonical equality. Font/script/version behavior and
  reserved ranges remain reasons to require caller grammar, baseline,
  framing/recurrence, and trial accounting before elevating any hypothesis.
- Changed files and verification commands: `src/unicode_properties.c`,
  `src/module_unicode.c`, `src/search.c`, `src/internal.h`, CMake, tests,
  README, candidate docs, `docs/DEFAULT_IGNORABLE_PROPERTIES.md`, and this
  ledger. GNU C11 CMake/CTest, Clang ASan+UBSan CTest, `clang-tidy`
  `clang-analyzer-core.*` with warnings-as-errors, and `git diff --check`
  passed.

### ling-3-lightning-unicode-round-external

- Model / reasoning / workspace: Ling 3.0 Lightning, high;
  `.agent-workspaces/ling-3-lightning-unicode-round-external/`.
- Role: external red team.
- Scope and hypotheses tried: 16; it submitted `U+200E` LRM versus `U+200F`
  RLM as a purported opt-in directional-mark binary observation and rejected
  the remaining 15.
- Exact carriers or null result: an alternating 32-scalar LRM/RLM diagnostic
  maps through the generic caller code-point alphabet to `55 55 55 55`.
- Independent verification result: GPT-5.6 Luna reproduced the strict UTF-8
  carrier, current aggregate bidi finding, zero built-in symbols, and generic
  output (`findings=2`, `symbols=0`, `bidi=1`). It rejected the novelty claim:
  LRM/RLM are already in `U+200B..U+200F`, the existing bidi family, and the
  pinned DICP inventory.
- Coverage labels reached: model-known plus independent reproduction; no new
  primitive or dedicated decoder.
- Outcome: caller-defined mapping remains available under an explicit grammar,
  but no `directional-mark-bits-msb` lane is added. Generic DICP work supplies
  the relevant property observation.
- False-positive and evidence-gate caveats: the report's universal invisibility
  claim was rejected because LRM/RLM can alter bidi resolution in context.
  Natural mixed-direction text, caller grammar, baseline, and evidence gates
  remain mandatory.
- Changed files and verification commands, if implementation occurred: none.

### opencode-mimo-v2.5-free-unicode-evasion-round

- Model / reasoning / workspace: opencode/mimo-v2.5-free, standard;
  `.agent-workspaces/opencode-mimo-v2.5-free-unicode-evasion-round/`.
- Role: red team, source-aware Unicode/plaintext evasion pass.
- Scope and hypotheses tried: 10 grouped hypotheses: equal-CCC and multi-mark
  permutations, enclosing marks, CJK compatibility ideographs, ZWJ forms and
  two-control sequences, interlinear annotations, vertical orientation,
  Tatweel, and U+2800 gaps.
- Exact carriers or null result: `NULL RESULT`.
- Independent verification result: not required: no survivor met the report's
  exact slot/grammar/portable-rendering/novelty bar.
- Coverage labels reached: none beyond model exploration.
- Outcome: a cautious feature-family saturation signal, not an implementation
  coverage claim or proof of complete Unicode coverage.
- False-positive and evidence-gate caveats: equal-CCC and multi-mark cases
  remain combining-order family observations pending grammar/baseline evidence;
  CJK/vertical/script/font claims require bounded contracts.
- Changed files and verification commands, if implementation occurred: none.

### opencode-muse-spark-unicode-evasion-round

- Model / reasoning / workspace: Muse Spark 1.3 Contributor Free via OpenCode,
  high; `.agent-workspaces/opencode-muse-spark-unicode-evasion-round/`.
- Role: red team.
- Scope and hypotheses tried: 24; 23 rejected. The sole submitted survivor is
  a non-ASCII Unicode `White_Space` property-inventory gap, illustrated by
  `U+2009` THIN SPACE versus `U+202F` NARROW NO-BREAK SPACE in exact
  caller-declared digit-gap slots.
- Exact carriers or null result: `31 E2 80 89 32 7C` / `31 E2 80 AF 32 7C`,
  alternating 32 slots, with a caller map expected to recover `55 55 55 55`.
  The report claims current findings and symbols are both zero.
- Independent verification result: pending GPT-5.6 Luna reproduction; no
  implementation follows from generation alone.
- Coverage labels reached: model-known only.
- Outcome: submitted as a potential Unicode-`White_Space` property observation
  gap, not a default decoder or intent claim. The proposed remediation is a
  version-pinned generic property predicate and anomaly observation, preserving
  the existing ASCII hspace semantics.
- False-positive and evidence-gate caveats: THIN SPACE/NNBSP differ in width
  and break behavior and occur legitimately in French, SI, publishing, and
  copy/paste workflows. Any bit interpretation needs complete caller slots,
  baseline, framing/recurrence, balance, and trial accounting.
- Changed files and verification commands, if implementation occurred: none.

### luna-unicode-whitespace-validate-1

- Model / reasoning / workspace: GPT-5.6 Luna, high;
  `.agent-workspaces/luna-unicode-whitespace-validate/`.
- Role: independent validator for the Muse non-ASCII `White_Space` claim.
- Scope and hypotheses tried: exact strict UTF-8 carrier, current detector and
  generic decoder behavior, Unicode 17 property and normalization behavior,
  bounded rendering/wrapping, grammar/absence, and property-table design.
- Exact carriers or null result: independently reproduced `U+2009` / `U+202F`
  alternating slots and caller-map output `55 55 55 55`; current pre-fix
  built-ins emitted zero findings and zero symbols.
- Independent verification result: validated as a Unicode-`White_Space`
  inventory coverage gap, not a new whitespace feature family. Pango rendering
  was similar in the tested isolated field but wrapping differed; NFC/NFD
  preserve both scalars while NFKC/NFKD fold them to SPACE.
- Coverage labels reached: independent validation; no decoder justified.
- Outcome: a version-pinned generic property observation with raw scalar spans
  is justified. No default alert, automatic bits, or THIN/NNBSP decoder.
- False-positive and evidence-gate caveats: French/SI/math/publishing,
  copy/paste, field grammar, font/layout context, normalization loss, baseline,
  recurrence/framing, and trial accounting remain mandatory.
- Changed files and verification commands, if implementation occurred: none.

### blue-unicode-whitespace-inventory-1

- Model / reasoning / workspace: Codex blue-team implementation after Muse
  generation and independent Luna validation; repository working tree.
- Role: close the validated non-ASCII Unicode-`White_Space` observation gap.
- Scope and hypotheses tried: a Unicode-17.0.0 `White_Space` table, raw
  provenance delivery, overlap with existing byte-oriented layout handling,
  and caller-map-only decoding. No pair-specific decoder was considered.
- Exact carriers or null result: the 32 exact `1 U+2009 2 |` /
  `1 U+202F 2 |` slots emit 32 three-byte raw observations at their scalar
  offsets; the caller map retains independently expected `55 55 55 55`.
- Independent verification result: Luna validated the property and carrier
  before implementation. Regression tests cover all 32 raw spans/values,
  generic decoding, and malformed-tail suppression.
- Coverage labels reached: built-in property observation and executable
  regression validation; no evidence-gated intent status.
- Outcome: ABI v4 adds `DEDSEC_DETECTION_OBSERVATION`, a zero-score non-bit
  callback event. `unicode-white-space-scalar` emits one event for each
  strict-decoded non-ASCII Unicode-17 `White_Space=yes` scalar; `evidence` is
  the scalar code point. ASCII SPACE/TAB layout semantics and the bit gluer are
  unchanged.
- False-positive and evidence-gate caveats: observations are neither alerts
  nor payload evidence. They cannot be glued; normalization can erase the raw
  distinction. Caller grammar, baseline, recurrence/framing, and trial
  accounting remain required for any interpretation.
- Changed files and verification commands: `include/dedsec.h`, `src/core.c`,
  `src/internal.h`, `src/unicode_properties.c`, `src/module_unicode.c`,
  `tests/test.c`, README, controller/candidate/composite docs, new
  `docs/UNICODE_WHITESPACE_PROPERTIES.md`, and this ledger. GNU strict C11
  CMake/CTest, Clang ASan+UBSan CTest, `clang-tidy` analyzer checks with
  warnings-as-errors, and `git diff --check` passed.

### opencode-gemini-3.8-flash-unicode-evasion-round

- Model / reasoning / workspace: github-copilot/gemini-3.8-flash, standard;
  `.agent-workspaces/opencode-gemini-3.8-flash-unicode-evasion-round/`.
- Role: red team, source-aware Unicode/plaintext evasion pass after the DICP
  and non-ASCII `White_Space` property fixes.
- Scope and hypotheses tried: 20 grouped hypotheses across combining-order,
  normalization/compatibility, invisible/math/musical/shorthand controls,
  fillers, selectors, bidi, interlinear annotations, soft hyphen, whitespace,
  line breaks, confusables, Tatweel, implicit bidi, and composite evasion.
- Exact carriers or null result: `NULL RESULT`.
- Independent verification result: not required: no survivor was submitted.
- Coverage labels reached: none beyond model exploration.
- Outcome: a bounded post-fix saturation signal. The report's claims that the
  model space is “exhaustively saturated” or that no standards-defined channel
  remains are explicitly not adopted; finite model sampling and pinned property
  tables cannot establish that conclusion.
- False-positive and evidence-gate caveats: grammar-aware, baseline-driven,
  version-specific, and as-yet unexamined representation relationships remain
  possible even though no proposal in this pass cleared the bar.
- Changed files and verification commands, if implementation occurred: none.

### opencode-sonnet-5-unicode-evasion-round

- Model / reasoning / workspace: Claude Sonnet 5 via OpenCode; report was not
  produced because the provider security-filtered the requested red-team task.
- Role: attempted red team.
- Scope and hypotheses tried: unknown; no inspectable output was returned.
- Exact carriers or null result: neither. A security-filtered refusal is not a
  `NULL RESULT` and supplies no coverage evidence.
- Independent verification result: not applicable.
- Coverage labels reached: none.
- Outcome: unavailable model sample; retry only with a policy-compatible,
  defensive prompt if model diversity is still useful.
- False-positive and evidence-gate caveats: do not count refusal as saturation.
- Changed files and verification commands, if implementation occurred: none.

### external-gpt-5.6-sol-pro-khmer-round

- Model / reasoning / workspace: GPT-5.6 Sol Pro, high; externally supplied
  report, no repository workspace.
- Role: red team.
- Scope and hypotheses tried: 18; it submitted the already-known Khmer
  `U+1780 U+17B4` / `U+1780 U+17B5` pair with a synthetic 24-slot sync,
  payload, and complement-check frame.
- Exact carriers or null result: the report's frame yields hypothesized `41`
  under its caller-defined grammar. Its stated kill condition correctly notes
  that the carrier is duplicate if the project has version-pinned DICP
  discovery with raw value and dependency spans.
- Independent verification result: the property pair, strict carrier,
  caller-map output, and bounded rendering had already been independently
  reproduced by the Sol/Luna DICP cycle. The synthetic base/mark grammar is
  not natural Khmer, semantic equivalence is not claimed, and its frame is not
  promoted to a built-in decoder.
- Coverage labels reached: no new feature family or decoder.
- Outcome: the report exposed a remaining provenance, not detection, gap:
  the prior DICP table emitted only aggregate triage. Blue-team work now emits
  per-scalar raw observations and adjacent-scalar dependency observations for
  all strict-decoded DICP members, closing its stated kill condition without
  adding Khmer-specific semantics.
- False-positive and evidence-gate caveats: adjacent context is conservative,
  not a full grapheme/shaping contract. Caller grammar, renderer/profile or
  processing contract, baseline, recurrence/framing/checks, and trial
  accounting remain required. A passing synthetic complement check is only a
  decoding hypothesis.
- Changed files and verification commands, if implementation occurred: none
  from the external report; the blue implementation is recorded below.

### blue-default-ignorable-provenance-1

- Model / reasoning / workspace: Codex blue-team implementation; repository
  working tree.
- Role: close the DICP per-scalar provenance gap exposed by the external
  report's explicit kill condition.
- Scope and hypotheses tried: generic raw DICP value spans, adjacent local
  dependency spans, malformed ownership, and existing specialized symbols;
  no Khmer-specific framing or bit polarity.
- Exact carriers or null result: 32 alternating U+17B4/U+17B5 marks after
  U+1780 now produce 32 three-byte `default-ignorable-scalar` observations and
  32 six-byte `default-ignorable-adjacent-context` observations. The existing
  caller map retains `55 55 55 55`; no generic observations are emitted when a
  malformed tail invalidates the complete input.
- Independent verification result: prior Luna validation established the
  property/carrying pair; executable regression asserts raw offsets, lengths,
  code-point evidence, and malformed suppression.
- Coverage labels reached: built-in property observation and executable
  regression validation; no automatic decoder/evidence-gated intent status.
- Outcome: `default-ignorable-scalar` records the value bytes; adjacent
  context records the preceding scalar plus the value. Both are zero-score
  `DEDSEC_DETECTION_OBSERVATION` events and cannot be glued into bits.
- False-positive and evidence-gate caveats: property observations are not
  semantic or renderer equivalence. Adjacent context is not a full grapheme
  cluster; caller grammar and independently fixed rendering/processing
  contracts still govern any further inference.
- Changed files and verification commands: `src/module_unicode.c`, tests,
  README, default-ignorable/candidate docs, and this ledger; strict C11,
  Clang ASan+UBSan CTest, `clang-tidy` analyzer checks with warnings-as-errors,
  and `git diff --check` passed.

### opencode-kimi-k3-unicode-evasion-round

- Model / reasoning / workspace: kimi-k3 via GitHub Copilot, standard;
  `.agent-workspaces/opencode-kimi-k3-unicode-evasion-round/`.
- Role: red team.
- Scope and hypotheses tried: 15; it rejected DICP, whitespace, selector,
  iteration, line-break, and known grammar-dependent variants. One survivor
  is a proposed General_Category `Cc` property-inventory gap for non-NEL C1
  controls.
- Exact carriers or null result: `78 C2 9B 7C` / `78 C2 9F 7C`, alternating
  32 caller-declared slots, claimed current zero events and caller-map output
  `55 55 55 55`.
- Independent verification result: pending GPT-5.6 Luna validation; no
  implementation follows from generation alone.
- Coverage labels reached: model-known only.
- Outcome: submitted as a candidate zero-score raw `Cc`/C1 observation, not a
  decoder or semantic identity. Its proposed pinning must distinguish U+0085
  White_Space overlap and decide C0/DEL scope explicitly.
- False-positive and evidence-gate caveats: C1 controls can arise from legacy
  transcoding mistakes, terminal captures, protocol text, editors, or control
  display modes. Any appearance is not intent evidence; no bit value is
  assigned absent a complete caller grammar and evidence gates.
- Changed files and verification commands, if implementation occurred: none.

### luna-c1-control-validate-1

- Model / reasoning / workspace: GPT-5.6 Luna, high;
  `.agent-workspaces/luna-c1-control-validate/`.
- Role: independent validator for Kimi's C1 `Cc` property claim.
- Scope and hypotheses tried: strict UTF-8, current events, generic decoding,
  Unicode-17 category/property overlap, control/rendering hazards, and C0/DEL
  policy.
- Exact carriers or null result: U+009B/U+009F slots reproduce caller-map
  `55 55 55 55`; the pre-fix built-ins have no C1 observation. The ASCII `x`
  anchor also emits unrelated layout symbols, requiring rule/span attribution.
- Independent verification result: validated as a property-observation gap,
  not a stealth decoder. U+0085 is the sole C1 Unicode-`White_Space` overlap.
- Coverage labels reached: independent validation; no automatic decoder.
- Outcome: full Unicode-17 `Cc` property table is justified; default emission
  is C1-only zero-score raw observation so C0/DEL do not alter ASCII-layout
  semantics. U+0085 deliberately reports both properties on the same span.
- False-positive and evidence-gate caveats: terminal/parser/control behavior,
  legacy conversion, accessibility/display modes, grammar, baseline, and
  trial accounting rule out any generic invisibility or bit claim.
- Changed files and verification commands, if implementation occurred: none.

### blue-c1-control-inventory-1

- Model / reasoning / workspace: Codex blue-team implementation after Kimi
  generation and independent Luna validation; repository working tree.
- Role: close the C1 control raw-observation gap.
- Scope and hypotheses tried: complete pinned `Cc` table, C1-only default
  emission, U+0085 overlap, malformed suppression, and caller-map boundary.
- Exact carriers or null result: 32 `x U+009B |` / `x U+009F |` records emit
  32 two-byte `unicode-c1-control-scalar` observations and retain caller-map
  output `55 55 55 55`; malformed-tail input emits no Unicode C1 observations.
- Independent verification result: Luna validated property facts and current
  pre-fix gap. Regression also asserts that U+0085 emits both C1 and
  non-ASCII-whitespace observations at the same span.
- Coverage labels reached: built-in raw observation and executable regression
  validation; no decoder/evidence-gated intent status.
- Outcome: `unicode_properties.c` pins complete `Cc`; only U+0080..U+009F
  stream as zero-score observations. They are non-bit and cannot be glued.
- False-positive and evidence-gate caveats: C1 is not universally invisible or
  semantically interchangeable. Its event is forensic visibility only.
- Changed files and verification commands: property/module/header/tests,
  README/candidate docs, new `docs/UNICODE_CONTROL_PROPERTIES.md`, and this
  ledger. GNU strict C11 CTest, Clang ASan+UBSan CTest, `clang-tidy` analyzer
  checks with warnings-as-errors, and `git diff --check` passed.

### gpt55-xhigh-unicode-round2

- Model / reasoning / workspace: GPT-5.5, xhigh;
  `.agent-workspaces/gpt55-xhigh-unicode-round2/`.
- Role: red team.
- Scope and hypotheses tried: 18; one survivor is a concrete canonical
  singleton coverage gap, ASCII `K` versus U+212A KELVIN SIGN.
- Exact carriers or null result: the report claims 32 declared slots are
  currently unobserved and caller-map decode to `55 55 55 55`.
- Independent verification result: pending GPT-5.6 Luna validation.
- Coverage labels reached: model-known only.
- Outcome: submitted as an existing canonical-identity-family extension, not
  a new primitive; no implementation follows from generation alone.
- False-positive and evidence-gate caveats: scientific-unit typography,
  casefolding and normalization context, placement grammar, baseline,
  recurrence/framing, and trial accounting require independent review.
- Changed files and verification commands, if implementation occurred: none.

### luna-kelvin-validate-1

- Model / reasoning / workspace: GPT-5.6 Luna, high;
  `.agent-workspaces/luna-kelvin-validate/`.
- Role: independent validator for GPT-5.5's canonical singleton claim.
- Scope and hypotheses tried: strict UTF-8, current event/decode behavior,
  canonical normalization, bounded rendering, scientific/contextual caveats,
  and identity-table fit.
- Exact carriers or null result: independently reproduced caller map
  `U+004B -> 0`, `U+212A -> 1` and `55 55 55 55`; pre-fix built-ins emitted
  zero events. All NFC/NFD/NFKC/NFKD forms map U+212A to `K`.
- Independent verification result: validated existing canonical-identity
  registry gap, not a new feature family.
- Coverage labels reached: independent validation.
- Outcome: a reviewed generic identity-table entry is justified; no
  Kelvin-specific decoder or new primitive.
- False-positive and evidence-gate caveats: Kelvin is legitimate scientific
  typography and can carry unit/context meaning. Field grammar, recurrence or
  framing, baseline, and trial accounting remain mandatory.
- Changed files and verification commands, if implementation occurred: none.

### blue-canonical-kelvin-identity-1

- Model / reasoning / workspace: Codex blue-team implementation after GPT-5.5
  generation and independent Luna validation; repository working tree.
- Role: extend the reviewed canonical identity registry.
- Scope and hypotheses tried: exact `K` / Kelvin raw tokens, existing generic
  scan/decode/balance behavior, strict UTF-8, and malformed ownership.
- Exact carriers or null result: 32 alternating `4B` / `E2 84 AA` slots emit
  raw symbols and decode under `canonical-kelvin-identity-bits` to
  `55 55 55 55`; one-sided/31-slot/malformed controls reuse the generic
  identity regressions.
- Independent verification result: Luna confirmed canonical equivalence and
  the pre-fix gap before implementation.
- Coverage labels reached: built-in implementation and executable regression
  validation; no evidence-gated intent status.
- Outcome: added one exact table entry to `identity`; no bespoke code path.
- False-positive and evidence-gate caveats: canonical equality does not erase
  scientific, unit, typography, search, or field-context differences. Treat
  all decoded output as a grammar- and baseline-gated hypothesis.
- Changed files and verification commands: `src/module_identity.c`, tests,
  identity documentation, and this ledger. GNU strict C11 CTest, Clang
  ASan+UBSan CTest, `clang-tidy` analyzer checks with warnings-as-errors, and
  `git diff --check` passed.

### external-astra-pro-unicode-round1

- Model / reasoning / workspace: GPT-6 Astra Pro, extended review; externally
  supplied chat report with no repository access. The user corrected an
  earlier UI-based GPT-5.6 Sol Pro attribution.
- Role: red team, external Unicode/plaintext null-result pass.
- Scope and hypotheses tried: 11 grouped hypotheses: nonprinting/filler
  characters, noncanonical Hangul factorization, Malayalam chillu legacy
  spelling, overlay multiplicity, Arabic mark reordering, collation equality,
  grapheme-boundary phase, font-only alternate glyphs, missing-glyph
  collisions, order-insensitive permutations, and cross-record composition.
- Exact carriers or null result: `NULL RESULT`. It includes local falsification
  probes for selected Hangul, chillu, and duplicated-overlay specimens, but
  presents none as a viable carrier.
- Independent verification result: no repository claim or validation required
  for the null result. The report correctly limits its assertions to its
  supplied coverage description; its external normalization/rendering probes
  are informative but not a project conformance result.
- Coverage labels reached: none beyond model exploration.
- Outcome: another cautious feature-family saturation signal. It explicitly
  distinguishes this from implementation coverage and therefore does not
  contradict the independently pending Sol DICP inventory-gap validation.
- False-positive and evidence-gate caveats: rendering, collation, script
  grammar, caller-selected order, and composition need version-pinned,
  predeclared contracts and negative controls; a checksum or framing layered
  over a covered carrier does not create feature novelty.
- Changed files and verification commands, if implementation occurred: none.

### blue-gemtext-links-1

- Model / reasoning / workspace: GPT-5.6 Luna implementation worker;
  repository working tree.
- Role: blue-team implementation of the explicitly requested Gemtext format
  coverage; this is not evidence about a private corpus.
- Scope and hypotheses tried: complete Gemtext `=>` link records using the
  grammar-defined ASCII SPACE/TAB runs before the URL and between URL and a
  nonempty label. Four binary conventions were reviewed: prefix width low bit,
  prefix SPACE/TAB, label-separator width low bit, and label-separator
  SPACE/TAB.
- Exact carriers or null result: 32 complete links per convention, with
  alternating raw forms. Prefix-width uses `=>URL` / `=> URL`; prefix type uses
  `=> URL` / `=>\tURL`; label width uses one versus two ASCII spaces; label type
  uses SPACE versus TAB. Each independently decodes to `55 55 55 55`.
- Independent verification result: strict C11 build and CTest pass. Tests also
  cover uniform benign links, non-link text, no-label links, malformed UTF-8,
  LF/CRLF/final records, symbol provenance, and the 32-symbol aggregate gate.
- Coverage labels reached: built-in implementation, executable validation, and
  generic ABI-v3 symbol provenance. Evidence-gated status is not reached.
- Outcome: implemented as the narrowly scoped `gemtext` module. It emits
  sub-threshold symbols with raw spans and uses the standard 32 total, 8/8,
  20% minority aggregate gate. It makes no URL-equivalence claim.
- False-positive and evidence-gate caveats: clients, exporters, editors, and
  hand formatting can choose different separator runs. Mixed SPACE/TAB runs
  are excluded from type lanes; absent labels are never bits. Prefix width zero
  has a grammar-proven slot and receives the complete parsed header/URL span.
  Generic layout and line-ending events may overlap; callers must select and
  deduplicate events before source-order composition and require recurrence,
  framing/checksum, or baseline evidence before elevation.
- Changed files and verification commands, if implementation occurred:
  `include/dedsec.h`, `CMakeLists.txt`, `src/core.c`, new
  `src/module_gemtext.c`, `tests/test.c`, README, candidate documentation,
  `docs/GEMTEXT_MODULE.md`, and this ledger. GNU strict C11 CTest passed;
  sanitizer/static-analysis verification is pending the parent worker's final
  integration run.

### sol-implicit-bidi-round1

- Model / reasoning / workspace: Sol red-team generation pass; isolated
  generation workspace.
- Role: red team.
- Scope and hypotheses tried: Unicode/plaintext source-order collisions that
  avoid bidi formatting controls and current explicit-control lanes.
- Exact carriers or null result: LF-terminated `a U+05D0 1 LF` versus
  `a 1 U+05D0 LF`, with expected visual scalar order `a 1 U+05D0 LF` under
  explicit LTR paragraph level 0. The exact 32-slot alternating diagnostic
  expects `55 55 55 55`.
- Independent verification result: sent to Luna for strict UAX #9 and
  renderer-independent validation; no implementation was inferred from
  generation alone.
- Coverage labels reached: model-known only.
- Outcome: candidate submitted for validation.
- False-positive and evidence-gate caveats: source logical semantics differ;
  higher-level protocols and RTL contexts can change display. Any lane needs
  exact complete records, raw provenance, balance, framing/recurrence, and a
  baseline before elevation.
- Changed files and verification commands, if implementation occurred: none.

### luna-implicit-bidi-validate-1

- Model / reasoning / workspace: GPT-5.6 Luna, high reasoning;
  `.agent-workspaces/luna-implicit-bidi-validate/`.
- Role: independent validator.
- Scope and hypotheses tried: exact records, current UAX #9, strict UTF-8 and
  malformed behavior, normalization, FriBidi/ICU reorder maps, current
  detector coverage, grammar feasibility, and interaction risks.
- Exact carriers or null result: `61 D7 90 31 0A` / `61 31 D7 90 0A`; two
  implementations agreed on levels/maps and the 32 alternating source carrier
  visually serialized to the same bytes. Existing detection returned zero
  findings; a caller token map recovered `55555555`.
- Independent verification result: the equality is valid only for an exact
  standalone explicit-LTR grammar. It is source-order-only, semantically
  non-equivalent, and not a general UAX #9 result.
- Coverage labels reached: model-known, independent validation, and generic
  primitive; no built-in or evidence-gated status at validation time.
- Outcome: opt-in only; a bounded exact implementation is justified with no
  broad Bidi_Class scanner or runtime renderer.
- False-positive and evidence-gate caveats: logical/source order, higher-level
  protocol exclusions, ordinary mixed-direction text, LF/layout overlap,
  malformed-input handling, and full 32/8/20% plus recurrence/framing gates
  remain mandatory.
- Changed files and verification commands, if implementation occurred: none;
  the validator report records FriBidi/ICU probes, normalization checks, and
  strict C11/CTest validation.

### blue-implicit-bidi-1

- Model / reasoning / workspace: Codex implementation worker; repository
  working tree.
- Role: blue team.
- Scope and hypotheses tried: only the two independently validated exact
  five-byte LF records; no inferred paragraph direction, CRLF, broad script
  ranges, or general UAX #9 engine.
- Exact carriers or null result: 32 alternating complete records emit 32
  one-bit source spans and decode MSB-first to `55 55 55 55`; all-zero,
  all-one, 31-slot, noise, forced-near-miss, malformed, and overlap controls
  are covered.
- Independent verification result: strict complete-input UTF-8 validation
  precedes this lane; aggregate detection uses the standard 32 total, 8/8,
  20% minority gate; ABI-v3 provenance and overlapping LF layout events are
  asserted by tests.
- Coverage labels reached: built-in implementation and executable
  regression-validated; evidence-gated intent status is not reached.
- Outcome: implemented as the bounded `unicode` lane
  `implicit-bidi-ltr-source-order-bits-msb` with rule
  `implicit-bidi-source-order-collision`; retain opt-in/evidence-gated use.
- False-positive and evidence-gate caveats: visual equality is not semantic
  equality, and source bytes must be retained. Require an exact LTR field
  contract, framing/checksum or recurrence, trial accounting, and a baseline
  before elevation. The lane overlaps line-ending/layout spans and must be
  deduplicated during composition.
- Changed files and verification commands: `src/module_unicode.c`,
  `tests/test.c`, README, `docs/IMPLICIT_BIDI_MODULE.md`, candidate docs, and
  this ledger; strict C11 CMake build and CTest passed.

## Coverage labels

- **Model-known:** a model proposed or recognized the family.
- **Generic primitive:** a caller can provide a code-point or byte-token table.
- **Built-in implementation:** `dedsec_detect_all()` offers a relevant detector
  and a documented built-in decode variant.
- **Executable validation:** exact positive, negative, and malformed-input
  fixtures are in the test suite.
- **Evidence-gated:** grammar/framing/checksum/recurrence controls are
  implemented before a candidate is elevated.

At the time of red-team submission, only the first two labels applied. The
`blue-identity-1` pass now supplies built-in detection/decoding and executable
regression validation for these exact identities. Its minimum-count and
balance gate limits routine typography, but grammar, framing/checksum,
cross-record recurrence, and full trial accounting remain required before any
candidate is elevated.

### opencode-deepseek-v4.1-flash-unicode-evasion-round

- Model / reasoning / workspace: DeepSeek-V4.1-Flash via OpenCode, high;
  `.agent-workspaces/opencode-deepseek-v4.1-flash-unicode-evasion-round/`.
- Role: source-led Unicode/plaintext red team.
- Scope and hypotheses tried: 12 grouped hypotheses: prepended concatenation
  marks, Egyptian hieroglyph controls, interlinear annotations, C1 controls,
  supplementary variation selectors, join controls, NEL/paragraph separator,
  canonical singletons, composition, CESU-8 noise, soft-hyphen/bidi, and
  C0/PUA/noncharacters.
- Exact carrier(s) or null result: no admitted carrier. Its strict UTF-8
  `U+0600`/`U+0601` caller-map probe produced `55 55 55 55`, but did not
  establish inconspicuous equivalence or a slot grammar.
- Independent verification result: no validator is required for the null
  result. The report's source-backed CESU-8 noise observation was reproduced
  during triage: ordinary four-byte scalars were emitted as zero symbols even
  with no CESU-8 counterpart.
- Coverage labels reached: null result for a new channel; a CESU-8 detector
  false-symbol regression was added separately.
- Outcome: reject PCM/Egyptian controls as general stealth channels (retain
  them as reopenable, grammar/rendering-gated observation inventories); all
  other proposals duplicate documented families or gates. Normal astral-only
  text no longer emits glueable CESU-8 zero symbols.
- False-positive and evidence-gate caveats: PCM and Egyptian controls have
  script/shaping behavior and no portable invisibility contract. This bounded
  null result is not a Unicode saturation proof.
- Changed files and verification commands, if implementation occurred:
  `src/module_encoding.c`, `tests/test.c`, and this ledger; verification is
  recorded with the blue audit below.

### blue-cesu8-symbol-noise-1

- Model / reasoning / workspace: Codex blue-team audit prompted by the
  DeepSeek report; repository working tree.
- Role: defensive false-positive remediation.
- Scope and hypotheses tried: standard astral-only UTF-8 input versus an input
  that actually contains a CESU-8 surrogate-pair spelling.
- Exact carrier(s) or null result: two standard U+1F600 spellings
  (`F0 9F 98 80` twice) now emit zero `utf8-cesu8-form-bits-msb` symbols;
  the pre-existing mixed CESU-8 regression continues to decode `OK`.
- Independent verification result: this is a source-level detector behavior,
  not a new carrier claim.
- Coverage labels reached: executable regression validation after verification.
- Outcome: ordinary astral text is no longer an implicit all-zero contributor
  to source-order composition. CESU-8 remains a separately selected legacy
  representation analysis and malformed inputs remain findings.
- False-positive and evidence-gate caveats: this does not make a CESU-8
  surrogate spelling valid strict UTF-8 or elevate it to evidence of intent.
- Changed files and verification commands, if implementation occurred: GNU
  strict C11 CTest, Clang ASan/UBSan CTest, `clang-tidy` analyzer checks, and
  `git diff --check` passed after the related callback repair below.

### blue-gemtext-callback-ub-1

- Model / reasoning / workspace: Codex blue-team sanitizer remediation;
  repository working tree.
- Role: C11 callback correctness fix.
- Scope and hypotheses tried: ASan/UBSan invoked `dedsec_utf8_foreach()` with
  Gemtext's validation callback and reported an incompatible function-pointer
  type (`dedsec_status` return versus the required `int`).
- Exact carrier(s) or null result: any valid Gemtext link traversing the UTF-8
  validator exercised the issue; no steganographic carrier is involved.
- Independent verification result: UBSan identified the exact source location;
  the callback now returns the declared callback type and its normal continue
  value, zero.
- Coverage labels reached: sanitizer and static-analysis validation.
- Outcome: fixed; no API or behavior change.
- False-positive and evidence-gate caveats: none; this is type-safety only.
- Changed files and verification commands, if implementation occurred:
  `src/module_gemtext.c` and this ledger; GNU strict C11 CTest, Clang
  ASan/UBSan CTest, `clang-tidy` analyzer checks, and `git diff --check`
  passed.

### luna-unicode-round3

- Model / reasoning / workspace: GPT-5.6 Luna, high;
  `.agent-workspaces/luna-unicode-round3/`.
- Role: independent Unicode/plaintext red team.
- Scope and hypotheses tried: Hangul and Tibetan canonical composition,
  ANGSTROM/A-ring and OHM/Omega canonical singletons, `fi` and micro-sign
  compatibility alternatives, supplementary variation selectors, interlinear
  annotations, and equal-CCC mark order, plus documented duplicate families.
- Exact carrier(s) or null result: `NULL RESULT`. Each normalization near miss
  has an exact 32-slot caller-map `55 55 55 55` reproduction, but that is only
  generic extraction—not a viable channel claim.
- Independent verification result: source/test inspection and unchanged CTest
  passed. No survivor requires a validator.
- Coverage labels reached: model-known implementation-gap examples in the
  existing canonical identity family; no new feature family.
- Outcome: defer possible future identity-table inventory work; reject the
  compatibility, selector, interlinear, and mark-order resubmissions under
  their existing contracts. No code change.
- False-positive and evidence-gate caveats: script/font/shaping, unit and
  scientific semantics, normalization policy, and complete slot grammar make
  every near miss unsafe for default detection or decoding. This bounded null
  result is not a coverage or saturation proof.
- Changed files and verification commands, if implementation occurred: this
  ledger only; Luna reports unchanged CTest success.

### gpt53-spark-unicode-round1

- Model / reasoning / workspace: GPT-5.3 Codex Spark, xhigh;
  `.agent-workspaces/gpt53-spark-unicode-round1/`.
- Role: independent Unicode/plaintext red team.
- Scope and hypotheses tried: eleven grouped tracks: non-DICP controls,
  whitespace, C1, zero-width controls, BMP/supplementary selectors, tags,
  line endings, identity/normalization, grammar modules, composite evasion,
  and malformed input.
- Exact carrier(s) or null result: `NULL RESULT`. It listed exact raw samples
  for each near miss, including PCM, Egyptian, interlinear, C1, selectors,
  NEL/PS, and malformed controls, but supplied no admitted carrier.
- Independent verification result: registry/source comparison confirms every
  disposition is either an existing family/candidate/rejection or lacks the
  bounded portable equivalence contract. Its prose about non-DICP inventories
  is treated as a rejection rationale, not a claim they are already DICP
  observed.
- Coverage labels reached: no new labels; caller-map availability remains a
  generic primitive, not automatic detection.
- Outcome: null result; no validator or implementation is warranted.
- False-positive and evidence-gate caveats: standard script, typography,
  shaping, grammar, baseline, framing/recurrence, and overlap controls remain
  mandatory. This sampling pass is not a saturation proof.
- Changed files and verification commands, if implementation occurred: this
  ledger only; Spark made no repository changes.

### astra-low-unicode-evasion-round1

- Model / reasoning / workspace: GPT-6 Astra, low;
  `.agent-workspaces/astra-low-unicode-evasion-round1/`.
- Role: independent source-led Unicode/plaintext red team.
- Scope and hypotheses tried: eight grouped tracks: normalization inventory,
  mark order/multiplicity, script shaping, implicit-bidi variants, DICP,
  non-DICP controls, blank/line boundaries, and cross-record composition.
- Exact carrier(s) or null result: `NULL RESULT`. Concrete specimens included
  ANGSTROM/A-ring, Hangul decomposition, overlay multiplicity, chillu/tatweel,
  DICP selectors/fillers, PCM/interlinear/Egyptian controls, and NEL/PS.
- Independent verification result: the pass inspected current source and
  existing tests; it offered no survivor needing independent validation. Its
  test invocation was an existing-build smoke check only, not a fresh build.
- Coverage labels reached: no new labels or feature families.
- Outcome: null result. The five reviewed identity entries are explicitly not
  an exhaustive normalization inventory; expansion remains a separate finite
  coverage-audit task, not new-channel discovery.
- False-positive and evidence-gate caveats: existing feature names, caller
  maps, arbitrary framing, and inferred rendering contracts do not satisfy the
  admission bar. This is a bounded sampling result, not saturation proof.
- Changed files and verification commands, if implementation occurred: this
  ledger only; Astra made no repository changes.

### opencode-muse-spark-unicode-evasion-round2

- Model / reasoning / workspace: Muse Spark 1.3 Contributor Free via
  OpenCode, high; `.agent-workspaces/opencode-muse-spark-unicode-evasion-round/REPORT-ROUND2.md`.
- Role: source-led Unicode/plaintext red team and property-table audit.
- Scope and hypotheses tried: 24 grouped probes across DICP/non-DICP controls,
  whitespace/C1, selectors/tags, line endings, zero-width controls, canonical
  and compatibility identities, FVS, composition, and malformed input.
- Exact carrier(s) or null result: `NULL RESULT`; no survivor was submitted.
- Independent verification result: accept the null disposition only with a
  correction: the report labels `DE 80`/`DE 81` as U+0600/U+0601, but the
  correct UTF-8 bytes are `D8 80`/`D8 81`. Thus its PCM P1/P2 experiment did
  not test the stated scalars and is not counted as evidence. Earlier correctly
  encoded DeepSeek/Astra reviews already rejected PCM for lack of a portable,
  unobtrusive contract. The report's Unicode-17 DICP-table completeness claim
  agrees with the independently maintained pinned table, but is not the sole
  validation basis.
- Coverage labels reached: no new labels. The complete DICP inventory remains
  built-in raw observation coverage; unobserved non-DICP controls remain
  candidate/rejection inventories, not silently covered.
- Outcome: null result after correcting the invalid PCM probe attribution; no
  validator or implementation is warranted.
- False-positive and evidence-gate caveats: the report correctly preserves the
  grammar, shaping, rendering, baseline, framing, overlap, and trial-accounting
  gates; a caller-map round trip is never automatic detection.
- Changed files and verification commands, if implementation occurred: this
  ledger only; Muse made no repository changes.

### blue-non-ignorable-format-controls-1

- Model / reasoning / workspace: Codex blue team; repository working tree.
- Role: close the strict-valid Unicode format-control observation gap exposed
  by correctly interpreting the Muse/DeepSeek PCM reports.
- Scope and hypotheses tried: complete Unicode-17 `General_Category=Cf` table
  minus the existing `Default_Ignorable_Code_Point` predicate; PCM,
  interlinear, Egyptian, DICP exclusion, raw spans, dependency spans, and
  malformed-tail suppression.
- Exact carrier(s) or null result: `a U+0600 | b U+FFF9 | c U+13430` uses
  exact raw bytes `61 D8 80 7C 62 EF BF B9 7C 63 F0 93 90 B0`. It emits three
  value observations and three one-scalar preceding-context observations with
  exact raw offsets/lengths; malformed `61 D8 80 C0 AF` emits none.
- Independent verification result: UnicodeData 17.0.0 supplies the full `Cf`
  table; the residual is PCM, `U+FFF9..U+FFFB`, and `U+13430..U+1343F`.
  This replaces the invalid Muse `DE 80` PCM probe with the correct `D8 80`.
- Coverage labels reached: built-in raw property observation and executable
  regression validation; no bit decoder or evidence-gated intent claim.
- Outcome: generic zero-score observations
  `unicode-non-ignorable-format-control-scalar` and
  `unicode-non-ignorable-format-control-adjacent-context` are implemented.
  They cannot be source-order glued.
- False-positive and evidence-gate caveats: `Cf` is not an invisibility,
  semantic-equivalence, or intent property. Script shaping, annotations,
  layout, fallback/accessibility, field grammar, baseline, recurrence/framing,
  and trial accounting remain mandatory before any hypothesis is elevated.
- Changed files and verification commands: `src/unicode_properties.c`,
  `src/internal.h`, `src/module_unicode.c`, `tests/test.c`, README, candidate
  docs, `docs/UNICODE_FORMAT_CONTROL_PROPERTIES.md`, and this ledger. GNU
  strict C11 CTest, Clang ASan/UBSan CTest, `clang-tidy` analyzer checks, and
  `git diff --check` passed.

### blue-byte-lifted-unicode-filter-1

- Model / reasoning / workspace: Codex blue team; repository working tree.
- Role: preserve high-signal encoded payload hypotheses for backend review.
- Scope and hypotheses tried: strict UTF-8 byte-to-`U+00xx` lifting, without
  identifying a legacy code page or decoding a payload.
- Exact carrier(s) or null result: CP037 bytes for `HELLO WORLD HELLO WORLD`,
  lifted one byte per Unicode scalar, are serialized as
  `C3 88 C3 85 C3 93 C3 93 C3 96 40 C3 A6 C3 96 C3 99 C3 93 C3 84 40`
  followed by the same eleven-scalar sequence. The filter returns at least
  `POSSIBLE` and sets `DEDSEC_PLAINTEXT_BYTE_LIFTED_UNICODE`.
- Independent verification result: no EBCDIC table or decoder is used. The
  generic predicate requires at least 16 strict-decoded scalars, all at most
  `U+00FF`, with at least 12 high-Latin-1 scalars comprising at least half.
- Coverage labels reached: executable prefilter regression; not a decoded
  payload or EBCDIC attribution.
- Outcome: qualifying byte lifts pass the low-grade suppression filter into
  backend review as `POSSIBLE`, retaining their original bytes and an explicit
  representation flag.
- False-positive and evidence-gate caveats: Latin-1-heavy legitimate text can
  match; the flag names no charset and proves neither EBCDIC nor hidden data.
  Backend analysis must choose and account for any code-page hypothesis.
- Changed files and verification commands: `include/dedsec.h`,
  `src/bitstream_filter.c`, `tests/test.c`, README, plaintext-filter docs, and
  this ledger. GNU strict C11 CTest and Clang ASan/UBSan CTest passed;
  `clang-tidy` analyzer diagnostics for the new heuristic were clean (two
  pre-existing whole-file `memset` policy warnings were line-filtered), and
  `git diff --check` passed.

### blue-opaque-data-filter-correction-1

- Model / reasoning / workspace: Codex blue team after user correction;
  repository working tree.
- Role: correct the prefilter's evidence boundary.
- Scope and hypotheses tried: AES-GCM-like bytes, canonical Base32 wrapping of
  opaque bytes, CP037 bytes lifted into Unicode, and constant low-grade data.
- Exact carrier(s) or null result: the existing 32-byte AES-like fixture now
  returns `POSSIBLE | DEDSEC_PLAINTEXT_OPAQUE_DATA`; its Base32 wrapper returns
  the same plus `DEDSEC_PLAINTEXT_BASE32`. The lifted CP037 fixture reaches the
  same generic opaque path. Thirty-two zero bytes remain `REJECT`.
- Independent verification result: byte content alone cannot distinguish
  ciphertext, compression, EBCDIC, or random noise. Routing is based only on
  length (at least 16 bytes), byte diversity (at least eight values), and bit
  balance (25% through 75% one bits).
- Coverage labels reached: executable prefilter regression.
- Outcome: removed the current
  `DEDSEC_PLAINTEXT_BYTE_LIFTED_UNICODE` API flag and its special heuristic.
  All unexplained non-degenerate streams use `OPAQUE_DATA`; charset/key/format
  attribution belongs to the backend operator.
- False-positive and evidence-gate caveats: opaque random noise necessarily
  passes this routing gate. Carrier structure, recurrence, framing/checksums,
  provenance, and external knowledge must determine investigation priority.
- Changed files and verification commands: `include/dedsec.h`,
  `src/bitstream_filter.c`, `tests/test.c`, README, plaintext-filter docs, and
  this ledger. GNU strict C11 CTest, Clang ASan/UBSan CTest, whole-file
  `clang-tidy` analyzer checks, and `git diff --check` passed.
### `blue-five-bit-opaque-filter-1`

- Date: 2026-09-11.
- Model / reasoning: Codex controller implementation.
- Scope and hypothesis: an operator maps an Enigma-like Latin ciphertext to
  caller-defined `A=0` through `Z=25` five-bit symbols, producing a bitstream
  whose length is not divisible by eight.
- Exact regression: `QWERTYUIOPASDFGHJKLZXCVBNMQAZWSFX`, 33 symbols, is
  appended as 165 source bits with a five-bit final tail.
- Outcome: `dedsec_bitstream_filter()` returns `POSSIBLE` with
  `DEDSEC_PLAINTEXT_OPAQUE_DATA`, selects source bit offset zero, and assesses
  20 complete bytes. The original `dedsec_bitstream.bit_length` remains 165;
  no Enigma or alphabet attribution is made.
- False-positive caveat: arbitrary packed symbols can resemble random data.
  Opaque routing requires independent carrier structure, recurrence, framing,
  checks, provenance, or operator knowledge before elevation.

### `luna-max-classical-filter-review-1`

- Date / model / reasoning: 2026-09-11; GPT-5.6 Luna; max.
- Role: read-only adversarial review of classical-cipher and arbitrary-width
  bitstream routing.
- Hypotheses tried: continuously packed five-bit Latin ciphertext, bit phases,
  post-radix reversal, canonical-radix ambiguity, partial tails, Baudot-like
  short streams, and restricted alphabets.
- Reproduced outcome: actionable defects, not a null result. Exact fixtures
  demonstrated accidental shifted UTF-8 promotion, qualifying opaque data
  reduced to `REJECT` at nonzero phase, missing decode-then-reverse search,
  numeric flag tie-breaking, and a retained but unassessed five-bit tail.
- Caveat: short and low-diversity packed ciphertext remains a policy tradeoff;
  cipher attribution is outside the filter.

### `luna-max-opaque-threshold-review-1`

- Date / model / reasoning: 2026-09-11; GPT-5.6 Luna; max.
- Role: read-only independent opaque-routing audit.
- Hypotheses tried: two canonical radix layers around opaque bytes, nonzero
  phase, equal-score interpretations, hard length/diversity/balance gates,
  partial tails, and deterministic random controls.
- Reproduced outcome: depth-two payloads skipped opaque finalization; phase
  penalties invalidated qualifying opaque data; equal scores discarded opaque
  evidence; tail bits had no effect. Nearly all random controls passed, which
  is an unavoidable consequence of conservatively retaining ciphertext-like
  bytes rather than a separable ciphertext detector.
- Caveat: `POSSIBLE` remains a secondary queue requiring carrier evidence,
  recurrence, framing/checks, provenance, or rate limits.

### `luna-max-filter-api-review-1`

- Date / model / reasoning: 2026-09-11; GPT-5.6 Luna; max.
- Role: read-only independent API and provenance audit.
- Hypotheses tried: raw and nested decoded lengths, source consumption,
  ignored tails, winner collapse, transformed opaque candidates, and malformed
  public `dedsec_bitstream` storage.
- Reproduced outcome: `decoded_length` was stage-dependent without source-bit
  metadata; competing interpretations were hidden; partial tails were silent;
  and excess storage/nonzero padding were not rejected.
- Caveat: the filter cannot manufacture raw carrier byte spans after gluing.
  Callers retain the detection callback events; result bit ranges select among
  that noncontiguous provenance.

### `blue-filter-paranoia-repair-1`

- Date / model / reasoning: 2026-09-11; Codex controller implementation.
- Role: blue-team repair of the three Luna max audits.
- Scope and exact regressions: a 165-bit five-bit Latin stream with assessed
  tail; its 160-bit control; the accidental shifted-UTF-8 five-bit carrier;
  a 129-bit phase-one opaque carrier; an equal-score raw/reversed carrier;
  Base64-to-Base32-to-16-byte opaque data; Base64 then per-byte reversal;
  strict-valid encoded C1 controls; excess storage; and nonzero padding.
- Outcome: ABI v5 exposes source bit length, consumed bits, assessed/ignored
  tails, ordered transform steps, and equal-score interpretation count.
  Opaque qualification now runs at the recursion limit and cannot be demoted
  by phase/bit-operation penalties. Semantic ranking replaces numeric flag
  order. Bit transforms run after radix decoding. C0/C1 scalar controls cannot
  support plaintext scoring, and non-ASCII bytes receive no automatic score
  bonus. Packed-storage invariants are validated.
- False-positive caveat: arbitrary/random packed data deliberately remains
  eligible for `POSSIBLE | OPAQUE_DATA`; nothing here identifies Enigma,
  Baudot, EBCDIC, AES-GCM, compression, or intent.
- Verification: GNU and Clang strict ISO C11 builds and CTest passed; Clang
  ASan/UBSan CTest passed with leak detection disabled for the environment;
  whole-file `clang-tidy` `clang-analyzer-*` checks passed with warnings as
  errors; `git diff --check` passed. A fresh 1,000-line public Gutenberg run
  retained all 6,000 plaintext forms as `LIKELY`; 7,983 of 8,000 random/AES
  forms entered the deliberately noisy `POSSIBLE` queue and none were
  `LIKELY`.

### `blue-default-sensitivity-repair-1`

- Date / model / reasoning: 2026-09-11; Codex controller implementation.
- Role: reproduce and reduce parameter-free false alerts from ordinary text
  and source controls.
- Controls examined: the repository GPL license, C implementation and test
  files, README prose, plus executable C-like and Rust-like source snippets.
- Reproduced result before repair: every ordinary space/case/punctuation/line
  feature emitted a zero-score `SYMBOL` provenance record; GPL capitalization
  emitted a score-30 aggregate; C punctuation emitted score 25; long ordinary
  identifiers and words emitted score-15 Base32/Base64/Crockford findings;
  source literals emitted score-25 JSON-escape findings.
- Outcome: symbols remain available for caller-framed composite analysis but
  case and punctuation no longer emit aggregate findings. Parameter-free
  surface/radix and syntax spelling discovery is disabled; the direct surface
  decoders remain available only under caller-supplied grammar. New C, Rust,
  and GPL-like regression controls require zero `FINDING` events.
- False-positive caveat: a consumer that displays every `SYMBOL` callback as
  an alert still misrepresents raw provenance. `SYMBOL` and `OBSERVATION` are
  not alerts; only aggregate `FINDING` records should enter an alert queue.

### `blue-filtered-lane-repromotion-1`

- Date / model / reasoning: 2026-09-11; Codex controller implementation.
- Role: reconsider the high-volume case, gap-width, punctuation, and Markdown
  marker lanes after installing the shared bitstream scorer/filter.
- Implementation: each detector constructs its homogeneous source-order lane
  while emitting the unchanged provenance-bearing symbols, calls
  `dedsec_bitstream_filter()`, and emits one aggregate finding only for a
  surviving lane. Exact 128-bit carriers independently reconstruct
  `HIDDEN MESSAGE!!` through all five variants.
- Negative controls: README and filter documentation, four implementation/test
  files, and ten installed license texts produced no promoted findings in the
  tested lanes. Existing compact C, Rust, license-like, and aligned-gap unit
  controls also remain finding-free.
- Partial null result: unrestricted opaque promotion failed for comma versus
  semicolon. Ordinary C implementation files produced high-complexity balanced
  lanes. That lane therefore promotes recognized plaintext or periodic/LZ78
  structure automatically, but leaves unexplained opaque output as symbols for
  a caller-supplied grammar or baseline. Case, gap width, period/question, and
  Markdown marker lanes retain opaque-data promotion.
- False-positive caveat: this is a small heterogeneous control set, not the
  unavailable target corpus. Natural text can still resemble data, and a
  comma/semicolon ciphertext channel can evade default aggregate promotion.

### `blue-case-serial-filter-1`

- Date / model / reasoning: 2026-09-11; Codex controller implementation.
- Role: reduce opaque-data false promotion from high-noise case channels
  without discarding their value-bearing symbols.
- Exact controls: a 512-bit stream containing 256 one bits followed by 256
  zero bits models an uppercase disclaimer followed by lowercase prose; a
  separate 512-bit `01` stream models regular alternating novelty case.
- Reproduced issue: global one-bit balance plus byte diversity at shifted
  phases can make locally trivial case regimes appear opaque.
- Outcome: the filter now recognizes clear constant/block-like regimes and
  near-exact periods two through eight before opaque routing. Both controls
  return `REJECT` without `OPAQUE_DATA`. Existing plaintext, ciphertext-like,
  EBCDIC-like, non-byte-aligned five-bit, nested-radix, and shifted opaque
  regressions continue to qualify as before.
- False-positive caveat: this is deliberately a narrow serial-complexity gate,
  not proof that a periodic or run-structured stream contains no information.
  Detection symbols and byte provenance are unchanged, so callers may apply a
  separately declared run-length or periodic-channel hypothesis.

### `research-case-complexity-1`

- Date / model / reasoning: 2026-09-11; Codex controller empirical study.
- Role: test whether compressed-description-length approximations distinguish
  naturally occurring word-initial case from plaintext and opaque payloads.
- Inputs: 5,500 same-length natural streams sampled from four Gutenberg books,
  project C/tests/license material, and a system license; 1,100 harmless
  plaintext-encoded and 1,100 deterministic SHA-256-derived opaque-encoded
  streams; 44 constant, alternating, noisy-alternating, and period-three style
  controls. Lengths range from 16 through 512 bits.
- Extraction validation: all 2,200 generated carriers were decoded separately
  through libdedsec's `layout/word-case-bits` implementation; exact packed
  bytes and bit lengths matched the independently generated manifest with no
  failures.
- Metrics tried: raw-DEFLATE compressed length, LZ78 phrase fraction, run and
  transition statistics, KT prequential Markov code lengths of orders zero,
  one, two, and four, and an explicit periods-one-through-eight residual code.
- Follow-up challenge: added fixed-width RLE cost, one-change-point piecewise
  KT, LZ78 estimated code length, and Berlekamp-Massey linear complexity, then
  tested 1,650 deterministic Manchester, repetition-three, convolutional,
  bit-stuffed, and degree-seven LFSR streams across the same lengths.
- Outcome: DEFLATE framing overhead makes 16-64-bit results largely tied. A
  minimum KT-order-one/short-period description-length score is much more
  useful for short inputs. With a fixed 0.80 bits/source-bit research cutoff,
  natural controls above threshold fell from 60/500 at 16 bits to 20/500 at
  48, 10/500 at 64, 3/500 at 96, 1/500 at 128/192, and zero at 256/512; all
  encoded classes passed from 24 bits except the deliberately repetitive
  16-bit plaintext prefix. Styled controls were almost always explained by a
  simpler model.
- Calibration caveat: a split-sample empirical 99th-percentile threshold
  eliminated most short false positives but also rejected the tested plaintext
  class through 32 bits. At 40 bits and above it retained all tested encoded
  streams, with zero through nine false positives among 250 held-out natural
  controls depending on length. The baseline is heterogeneous and small, and
  samples overlap source documents; this is not a production false-positive
  estimate or evidence about the unavailable target corpus.
- Scorer disposition: retain raw transition fraction rather than fixed-width
  RLE code length; keep KT, bounded periodic, and LZ78 as complementary
  description models; add linear complexity because it alone exposed the
  balanced LFSR family. Piecewise KT did not materially improve the tested
  two-regime case. Random-input convolutional and bit-stuffed streams remained
  indistinguishable from opaque data without a declared inverse grammar.
- Disposition: retain the experiment and generated carriers under
  `.agent-workspaces/case-complexity-research/`. Do not install thresholds yet.
  Next validation should stratify by document genre and use held-out sources,
  especially chat/social-media capitalization and generated source code.

### `blue-bitstream-scorers-1`

- Date / model / reasoning: 2026-09-11; Codex controller implementation.
- Role: expose the validated research measurements through pure-C11 APIs and
  replace the filter's narrow serial-complexity gate with the scorer ensemble.
- Implementation: added transition-mask KT, selectable-order KT, bounded
  periodic residual, bounded LZ78, and bounded Berlekamp-Massey scorers. Every
  scorer returns source/assessed lengths, Q48.16 description length and ratio,
  raw statistic, selected model parameter, and explicit short/limit/arithmetic
  flags. `dedsec_bitstream_score()` returns the four general-purpose scorers
  plus explainable aggregate flags. Berlekamp-Massey remains an explicit
  forensic scorer because its quadratic, generator-specific classification is
  unnecessary for opaque-data triage.
- Filter disposition: high unexplained streams may route as `OPAQUE_DATA`;
  periodic or dictionary structure routes as
  `STRUCTURED_DATA`; simple streams remain rejected as literal data without
  deleting their carrier symbols. Plaintext/radix scoring remains independent.
- Exact regressions: alternating and constant regimes remain simple; a
  deterministic opaque stream remains high-unexplained; bounded LZ78 reports
  saturation; invalid options and malformed packed storage fail; a degree-seven
  LFSR remains review-worthy as opaque data by default and is independently
  exposed by the opt-in linear scorer; a 2,048-bit input verifies the
  1,024-bit linear work cap.
- Empirical check: all 2,200 generated case carriers still decode exactly. All
  opaque carriers at 48-512 bits score high-unexplained; tested plaintext case
  carriers do so from 40 bits. Four complete Gutenberg books, the GPL, source,
  tests, and a system license score simple under the word-case lane. The
  existing four-book all-lane result remains 24 reject, 44 insufficient, 28
  possible, and zero likely.
- Caveat: thresholds derive from a bounded heterogeneous corpus, not the
  unavailable target corpus. Short streams, distribution matching, and random
  data remain ambiguous. A low description length can itself identify a
  possible carrier grammar and must never be reported as absence of data.
