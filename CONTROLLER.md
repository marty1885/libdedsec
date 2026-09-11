# libdedsec controller playbook

Use this document to continue `libdedsec` without restarting it. It is a
defensive, API-only, pure ISO C11 framework for detecting and experimentally
decoding possible plaintext/Unicode steganographic representation channels.

## Non-negotiable boundaries

- Preserve raw bytes and lengths before any decoding, normalization, or
  transcoding.
- Do not claim findings about the private offline corpus. A decoded output is a
  hypothesis, never proof.
- No cryptography, payload execution, networking in the library, C++, Rust,
  Python runtime, or mandatory external dependency.
- Strict UTF-8 rejects malformed encodings. Overlong UTF-8 and unspecified
  parser behavior are forensic observations only, never normal decoders.
- Do not hard-code payloads. A standardized representation may justify a
  reviewed fixed table; otherwise require a general primitive.
- Stop a search when it becomes repetitive, saturated, or circular.

## The two coverage axes

Never collapse these into one claim:

1. **Model-space coverage:** whether independent models can identify a family.
2. **Repository coverage:** whether the exact carrier has a built-in detector,
   decoder, executable regression, and evidence gate.

Use these labels for every candidate:

| Label | Meaning |
|---|---|
| Model-known | A model recognized or proposed the family. |
| Generic primitive | A caller can supply a map/token table to extract it. |
| Built-in | `dedsec_detect_all()` detects it and a documented variant decodes it. |
| Regression-validated | Exact positive, negative, malformed, and expected-output tests exist. |
| Evidence-gated | Placement/grammar plus framing, checksum, recurrence, or equivalent controls are implemented. |

Generic matching does **not** establish built-in coverage. A repeated model
proposal does **not** establish saturation of repository coverage.

## Detection is broader than decoding

An observable, standards-defined representation difference can justify a
provenance-preserving anomaly feature even if there is no safe payload decoder.
Separate an anomaly observation, a conditional bit hypothesis, and an elevated
finding. A default detector may trigger only when ordinary text cannot produce
the pattern under a stated grammar, or a representative corpus baseline has
measured an acceptable false-positive rate. Otherwise expose it only as an
opt-in observation. Do not reject a stealth-capable candidate merely because
its semantic grammar is not yet implemented.

## Current baseline

Read source and tests before proposing work. `docs/REDTEAM_MODEL_LEDGER.md`
records model ownership and outcomes. `docs/CANDIDATE_STEGNO.md` prioritizes
detection-first candidate families. `docs/REJECTED_STEGNO.md` is the
append-only register of rejected and duplicate ideas; it names the specific
evidence needed to reopen an entry. The built-in `identity` module
contains a small reviewed fixed registry for these independently reproduced
gaps:

- `U+0020` SPACE / `U+00A0` NBSP;
- `U+00E9` / `U+0065 U+0301`;
- `U+002D` HYPHEN-MINUS / `U+2011` NON-BREAKING HYPHEN.
- `U+0061 U+0323 U+0301` / `U+0061 U+0301 U+0323`.

The `structure` module also has reviewed raw line-ending lanes for LF/CRLF,
LF/LINE SEPARATOR, and CRLF/LINE SEPARATOR. CRLF is always one token; decoded
bits remain conditional hypotheses.

The registry is intentionally incomplete. Its existence must not be used to
claim coverage for arbitrary Unicode aliases, typography, or grammatical
equivalence.

ABI v4 also exposes zero-score raw property observations and
`DEDSEC_DETECTION_SYMBOL` events with raw byte spans. Only symbols may enter
source-order composition. Composite red teams must test whether a payload split
across multiple reviewed families stays below every standalone gate.
Deduplicate overlapping features, then test only bounded source-order or
explicitly framed merge conventions; plaintext-looking output alone never
elevates a composite hypothesis.

## One red-team → blue-team cycle

1. **Inspect first.** Read `include/dedsec.h`, every module in `src/`, the
   executable tests, README, threat-model docs, identity contract, red-team
   ledger, candidate register, and rejection register. Treat code and tests—not
   an architectural claim—as coverage.

2. **Create isolated workspaces.** Make one directory per model under
   `.agent-workspaces/`, for example:

   ```sh
   mkdir -p .agent-workspaces/<pass>-<model>
   ```

   A model may write only its report there. Do not let two models share a
   workspace. Attribute every report to its actual model; a misplaced report is
   invalid as an independent result.

3. **Red-team with a fresh context.** Give each hypothesis agent no project
   history except the explicit prompt below. Ask it to inspect the project, but
   forbid edits and private-corpus claims. Use diversity of provider/model and
   reasoning effort where available. Keep free/limited models to three strong
   candidates or fewer. `NULL RESULT` is a successful outcome; never require a
   model to fill the candidate quota.

4. **Validate independently.** A different model/reviewer must reproduce exact
   carriers without using the author's code or conclusion. It must distinguish
   a missing detector from a merely missing semantic validator. Do not let the
   originating model validate itself.

5. **Deduplicate by feature.** Compare the underlying representation feature,
   not the carrier spelling. Record whether it is (a) a known family with an
   implementation gap, (b) a genuinely new primitive, or (c) an already covered
   implementation/variant. If it appears in the rejection register, either
   retain that disposition or explicitly demonstrate the stated reopening bar;
   a raw-bit round trip is never enough to reopen it.

6. **Require evidence gates.** A valid bit round trip is insufficient. Before
   elevating a candidate, specify minimum recurrence, balance/placement rules,
   framing/checksum/plaintext plausibility, grammar context, cross-record
   correlation, and trial-count accounting. If these cannot be specified, keep
   the item as a non-elevated observation or reject it.

   A non-elevated observation remains a valid implementation target if it meets
   the default-alert rule above; otherwise it must be opt-in until a corpus
   baseline exists.

7. **Implement only a verified gap.** Prefer one general table-driven module or
   sub-function over one-off decoders. Preserve byte offsets. Maintain strict
   UTF-8 behavior. Keep public ABI compatibility unless a real ABI change is
   justified.

8. **Add regressions.** Include exact raw carriers, independent expected bits,
   benign negative controls, malformed input, and detector-gate tests. Do not
   add a test simply because a model asserted a claim; add it after independent
   reproduction.

9. **Verify.** Build with `-std=c11 -pedantic -Wall -Wextra -Werror`; run CTest,
   ASan/UBSan where supported, and focused static analysis. Record sanitizer
   environmental limitations separately from code results.

10. **Update the ledger.** Append one index-table row **and** one matching
    outcome section in `docs/REDTEAM_MODEL_LEDGER.md`; use its copy-ready
    template. Include model, reasoning effort, workspace, exact scope,
    hypotheses tried, independent validation result, implementation disposition,
    false-positive caveats, and verification commands. Report null results
    explicitly; never overwrite prior attribution.

## Red-team prompt template

Copy this verbatim for a new reviewer. Replace `<WORKSPACE>` only.

```text
You are a defensive red-team reviewer of libdedsec. Your goal is to find up to
three standards-defined, low-bandwidth plaintext/Unicode representation channels
that can encode a harmless bitstream yet evade, or be materially mishandled by,
the repository's current built-in detection and decoding.

CWD: /home/marty/libdedsec. Inspect all source, public headers, tests, README,
and docs before proposing anything, including docs/CANDIDATE_STEGNO.md and
docs/REJECTED_STEGNO.md. Treat
implementation and executable tests, not architectural claims, as the coverage
baseline. Do not modify project files, run network commands, inspect any private
corpus, or claim corpus findings. Write only <WORKSPACE>/REPORT.md.

For every candidate provide: exact escaped carrier bytes/code points;
deterministic extraction; a locally reproducible harmless round trip; precisely
bounded semantic-equivalence or rendering claim; exact current detector/decoder
behavior with file and line citations; negative controls and realistic false
positives; a generalized pure-C11 implementation approach; novelty classification
versus generic caller maps and built-ins; and required grammar/framing/checksum/
recurrence gates.

Do not count malformed input, unspecified parser behavior, overlong UTF-8,
ciphertext, ordinary printable bytes, or payload-specific hard-coding as normal
decoders. Preserve raw-byte provenance. Do not mistake a generic code-point or
token map for an implemented semantic detector. Distinguish model-known,
generic-primitive, built-in, regression-validated, and evidence-gated status.
Deduplicate by underlying feature. Treat entries in CANDIDATE_STEGNO.md as
existing detection tracks: advance their state machine, grammar, baseline, or
evidence gate rather than renaming them as a discovery. For any feature in
REJECTED_STEGNO.md, do not resubmit it unless you name the entry and demonstrate
the exact stated reopening evidence. A missing built-in or generic-map bit round
trip does not qualify. State whether a proposal can be a default anomaly, needs
an opt-in observation, or needs a corpus baseline before alerting. Include null
results and hypotheses tried.

Evaluate stealth at the raw carrier boundary too: describe what an ordinary
strict UTF-8 viewer, editor, diff, or forensic byte-preserving tool displays.
Do not submit a legacy-charset escape spelling merely because a separately
chosen decoder maps it to ordinary text; visible UTF-7 `+...-` shifted sections
are not unobtrusive plaintext/Unicode carriers in the current scope. Such a
proposal needs a separately declared operational viewer/charset and is out of
scope unless it clears the rejection register's reopening bar.
Do not fill a quota. If no candidate meets every requirement, if the remaining
ideas are duplicates, or if the search becomes repetitive/circular, reply
exactly `NULL RESULT` followed by a short count and reason; do not invent a
weaker candidate. Otherwise stop after three strong candidates.
```

## Independent-validator prompt template

```text
You are an independent defensive validator. Read the project and only the
candidate report at <AUTHOR_WORKSPACE>/REPORT.md. Do not trust its code or
conclusions, do not edit the project, and write only <VALIDATOR_WORKSPACE>/
VALIDATION.md.

For each candidate, independently recreate its exact harmless carrier and
expected bits; run the current built-in detector/decoder; inspect cited source
paths plus docs/CANDIDATE_STEGNO.md and docs/REJECTED_STEGNO.md; and classify
the result as a default anomaly candidate, opt-in observation candidate,
built-in coverage, generic-primitive only, verified implementation gap,
malformed/undefined behavior, false equivalence, or duplicate feature. For a
claimed reopening, verify the rejection register's exact missing requirement
was actually met. Check the stated semantic limitation and realistic false
positives. State whether a corpus baseline is required before alerting and the
minimum evidence gate required before decoding/elevation. Do not make corpus
claims or invent candidates.
```

## Blue-team implementation rule

For a fixed Unicode identity family, extend the reviewed table in
`src/module_identity.c` only after the validator passes. Keep the pair exact,
assign a stable rule/variant name, retain strict UTF-8 validation, and use the
existing recurrence/balance detection gate unless evidence shows a justified
alternative. Update `docs/IDENTITY_MODULE.md`, tests, and the red-team ledger.

For a distinct feature family, add a small cohesive module instead; do not
misrepresent a caller-provided generic map as automatic detection.
