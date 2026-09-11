# Non-default-ignorable Unicode format controls

`unicode` observes every strict-decoded Unicode 17.0.0 `General_Category=Cf`
scalar that is **not** `Default_Ignorable_Code_Point`.

The observer uses the generated `Cf` range table and subtracts the existing
Unicode-17 default-ignorable predicate. It covers the residual inventory:

- prepended concatenation marks (`U+0600..U+0605`, `U+06DD`, `U+070F`,
  `U+0890..U+0891`, `U+08E2`, `U+110BD`, `U+110CD`);
- interlinear annotation controls (`U+FFF9..U+FFFB`); and
- Egyptian hieroglyph format controls (`U+13430..U+1343F`).

For each scalar, the module emits zero-score `DEDSEC_DETECTION_OBSERVATION`
events:

- `unicode-non-ignorable-format-control-scalar` retains the exact raw scalar
  byte span and code point evidence.
- `unicode-non-ignorable-format-control-adjacent-context` conservatively spans
  the immediately preceding scalar plus the control, when a preceding scalar
  exists. It records rendering/grammar dependency, not a claim of complete
  grapheme or shaping context.

These observations have no decoder hint, bit value, score, or source-order
composition eligibility. `Cf` does not mean invisible, harmless, equivalent,
or intentional. The controls can affect script shaping, annotations, layout,
accessibility, and text processing. Any bit hypothesis requires a caller-fixed
grammar/rendering contract, complete slots, framing or recurrence, negative
controls, a baseline, and trial accounting.

Malformed UTF-8 remains owned by the encoding module. The Unicode observer
emits nothing when whole-input strict validation fails.
