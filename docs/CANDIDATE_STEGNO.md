# Steganography detection candidates

This register is for feature families worth detecting even where the library
cannot responsibly decode a payload. A finding may say that raw representation
is unusual; it must not claim intent, semantic equivalence, or decoded
plaintext without the evidence required for those claims.

## Admission and alert policy

A candidate needs a standards-defined, raw-byte-preserving representation
difference and a conceivable deterministic feature-to-symbol rule. Prefer
differences that a normal reader of rendered text is unlikely to notice.
Visibly conspicuous typography is not a stealth candidate merely because a
normalizer maps it to something else.

| Track | When it may report automatically | What it reports |
|---|---|---|
| Default anomaly | Ordinary text cannot produce the pattern under the stated grammar, or a representative corpus baseline demonstrates an acceptably low false-positive rate. | A provenance-preserving representation anomaly; optionally a conditional bit hypothesis. |
| Opt-in observation | Ordinary text can plausibly produce it and no corpus baseline is available. | Raw spans and feature counts only; no default alert and no intent claim. |

A deterministic bit extraction is useful but not required for either track.
To elevate extracted bits, require grammar, placement, balance,
framing/checksum or cross-record recurrence, and trial-count accounting.

## Unicode priority candidates

| Family | Candidate observation | Decoder status | Default-alert bar |
|---|---|---|---|
| Canonical combining-mark order | The reviewed exact `a + U+0323 + U+0301` / `a + U+0301 + U+0323` pair is built in with raw UTF-8 matching. Broader adjacent-mark runs still need Unicode-version-pinned canonical-combining-class data; a descending run is an anomaly observation. | `canonical-combining-order-bits` decodes only that exact reviewed pair. A general pair/order lane requires a bounded cluster grammar: same base, exact mark multiset, no intervening starter. | Default only where canonical ordering/normalization is required by the input contract, or after a representative corpus baseline. Otherwise opt-in. |
| Canonical composition/decomposition identities | Preserve which canonically equivalent raw spelling occurred before any normalization shadow. | Pair/table decoding is conditional on a reviewed identity and placement/framing evidence. | Default only for an inconsistent, structured mix in a normalization-governed field or after baseline measurement. |
| Line-break identities | Built-in raw lanes preserve LF (`0A`), CRLF (`0D 0A`), and LINE SEPARATOR (`E2 80 A8`) as complete, non-overlapping tokens. Variants cover LF/CRLF, LF/LINE SEPARATOR, and CRLF/LINE SEPARATOR. NEL and PARAGRAPH SEPARATOR remain future observations. | A mixed-line-ending lane yields a conditional bit hypothesis; CRLF is never also counted as LF. | A default anomaly needs a line-oriented grammar where ordinary text should use one representation, or a corpus baseline. Otherwise report opt-in counts/spans only. |
| Bidi and invisible controls | Existing structured control detection remains the model: retain raw controls and nesting/placement state. | Existing variants are conditional hypotheses, never proof. | Use structural constraints that normal prose should not satisfy; baseline mixed-directional text where available. |
| Non-ASCII Unicode `White_Space` | The Unicode-17.0.0-pinned property table emits one zero-score raw-span observation per non-ASCII `White_Space=yes` scalar. It does not alter ASCII SPACE/TAB layout features. | No generic whitespace-to-bit decoder. A caller may declare a complete field grammar and code-point alphabet, but normalized/folded text is lossy and absence is not a bit. | Opt-in forensic observation only. French punctuation, SI/math typography, publishing, copy/paste, font/layout behavior, baseline, framing/recurrence, and trial accounting are required before elevation. |
| C1 control scalars | The Unicode-17.0.0 `General_Category=Cc` table emits one zero-score raw-span observation per C1 scalar (`U+0080..U+009F`). It deliberately leaves C0/DEL byte-oriented handling unchanged. | No generic C1-to-bit decoder. Caller maps require a complete field grammar, and controls are never assumed invisible or semantically interchangeable. | Opt-in forensic observation only. C1 may arise from legacy conversion, terminal captures, parser/control interpretation, or display modes. U+0085 also has a whitespace observation on the same span; neither event may be double-counted as a bit. |
| Non-default-ignorable format controls | The Unicode-17.0.0 `Cf` inventory emits zero-score raw-value and preceding-scalar dependency observations for the residual after `Default_Ignorable_Code_Point`: prepended concatenation marks, interlinear annotation controls, and Egyptian hieroglyph format controls. | No generic format-control-to-bit decoder. A value pair is neither a slot nor an equivalence claim; any caller map needs a complete grammar plus rendering/processing contract. | Opt-in forensic observation only. `Cf` does not imply invisibility: these values can shape script text, alter annotations/layout, or be shown by accessibility and fallback tools. Require baseline, framing/recurrence, and trial accounting before elevation. |
| Default-Ignorable property inventory | Built-in Unicode-17.0.0-pinned property observation covers the complete `Default_Ignorable_Code_Point` range inventory. It emits every raw value span and an adjacent-scalar dependency span, retains aggregate triage, and is shared with the strip-known-ignorables transform. Specialized selector/tag/bidi/FVS lanes retain their own rules and symbols. | No generic property-to-bit decoder: the alphabet is non-power-of-two and property membership is not an identity claim. Caller-defined alphabets require complete slot grammar and retain raw bytes. | An occurrence is an anomaly only. The adjacent span is not a full shaping proof; script grammar, shaping/font behavior, reserved ranges, Unicode-version skew, recurrence/framing, baseline, and trial accounting remain mandatory before elevation. |
| Implicit bidi source-order collision | The exact LF-terminated `a + ALEF + 1` / `a + 1 + ALEF` records have the same visual scalar order only under standalone explicit LTR context. The bounded lane preserves the five-byte source span and never infers general UAX #9 behavior. | `implicit-bidi-ltr-source-order-bits-msb` maps only the two exact records in raw source order. | Opt-in only: higher-level protocols, RTL context, markup/segment boundaries, logical semantic differences, ordinary bilingual material, and line-ending/layout overlap require an exact field contract, baseline, framing/recurrence, and trial accounting. |
| Mongolian free variation selectors | Built-in `mongolian-fvs-binary-symbols` observes mixed `U+1820 U+180B` (FVS1) / `U+1820 U+180C` (FVS2) occurrences. It retains the selector byte span and excludes FVS3 and selectors after other bases from its bit lane. | `mongolian-fvs1-fvs2-bits-msb` maps the reviewed FVS1/FVS2 pair to conditional `0`/`1` bits. This is a covert-channel observation, not a claim that the two forms preserve spelling, search identity, or glyph identity. | Opt-in only. FVS rendering and shaping are Unicode-version-, font-, and context-dependent; a default alert needs a pinned shaping/field contract or representative baseline. |

## Generic layout candidate

Trailing horizontal whitespace at an end of line is visually unobtrusive and
now has a generic width feature. The default detector requires exactly two
positive widths, at least 32 marked lines, at least eight of each width, and a
20% minority floor. `trailing-hspace-width-low-bit` emits the low bit of each
positive width; `trailing-hspace-rule` accepts a caller-supplied
`dedsec_binary_rule` for an explicit reviewed convention. Lines without
trailing horizontal whitespace are not symbols in the low-bit lane.

Editors, source-control hooks, and copy/paste can create or strip trailing
whitespace, so a finding remains a hypothesis. The structural gate makes a
default anomaly reasonable only where normal material should not contain a
balanced, two-width EOL pattern; otherwise an investigator should treat it as
an opt-in observation or obtain a corpus baseline.

`ASCII A` / FULLWIDTH `A` is intentionally absent. Its width distinction is
normally conspicuous in Latin text and ordinary in CJK/fullwidth contexts, so
it is not a general stealth channel.

The same grammar-gated gap track may observe a non-White_Space scalar that
renders blank in a particular environment. One reviewed future spelling is
SPACE (`U+0020`, `20`) versus BRAILLE PATTERN BLANK (`U+2800`, `E2 A0 80`) in
an externally defined one-gap word slot. This is not a new default identity
decoder: `U+2800` is a braille graphic, has no normalization equivalence to a
space, and is conspicuous to byte-preserving, braille-aware, and many
accessibility tools. It may nevertheless be an opt-in raw-span observation
where the field contract permits exactly one visual gap. Do not count a SPACE
span simultaneously in this candidate and the existing SPACE/NBSP or
ASCII-gap-width lanes when composing hypotheses. A binary convention needs
complete slots, 32 observations, 8/8/20% balance, recurrence/framing, and a
field baseline before elevation.

## Composite lanes

ABI-v3 detection streams sub-threshold `DEDSEC_DETECTION_SYMBOL` observations
with exact raw spans. A payload may alternate several reviewed feature
families so no individual family reaches its aggregate gate. A caller can
deduplicate and select non-overlapping events, then use
`dedsec_symbols_glue_source_order()` to form a conditional hypothesis.

The mere union of ordinary anomalies must not report automatically. Require at
least two underlying families, 32 selected symbols, four per family, a 20%
minority floor, recurrent placement, and full trial accounting. Elevation also
needs framing/checksum or independently reproduced cross-record recurrence.
See `docs/COMPOSITE_CHANNELS.md`.

## Future non-Unicode formats

The built-in `gemtext` module is the first narrowly scoped non-Unicode format
extension. It recognizes only complete `=>` link records and exposes the four
documented prefix/label separator lanes in
`docs/GEMTEXT_MODULE.md`. Other format-specific syntax remains deferred. A
later module may tokenize a versioned format with raw-byte provenance and
expose a feature stream, but it must apply the same default-alert versus
opt-in/baseline rule above. Do not treat generic token matching as proof that
two format spellings share semantics.

## How to advance a candidate

Do not re-propose a family as a new discovery. Instead demonstrate one of:

1. a more precise raw feature/state machine that current modules miss;
2. a grammar that proves a selected representation pair is interchangeable in
   the exact field;
3. a baseline that makes a default alert defensible; or
4. independent framing/recurrence that makes a conditional decoder useful.

Record the result in `docs/REDTEAM_MODEL_LEDGER.md`, including null results.
