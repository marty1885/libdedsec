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
