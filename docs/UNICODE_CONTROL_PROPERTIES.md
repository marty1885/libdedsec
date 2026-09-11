# Unicode C1-control observation

`libdedsec` carries a static `General_Category=Cc` table generated from Unicode
17.0.0 `UnicodeData.txt`. The complete table covers C0, DEL, and C1, but the
built-in Unicode module emits raw observations only for **C1** (`U+0080` through
`U+009F`). C0 and DEL remain byte-oriented/input-specific concerns so existing
ASCII layout behavior is unchanged.

Each strict-decoded C1 scalar emits the zero-score
`unicode-c1-control-scalar` `DEDSEC_DETECTION_OBSERVATION`; its raw byte span
identifies the scalar and `evidence` holds its code point. There is no decoder,
bit value, aggregate alert, or source-order-gluer input.

`U+0085` NEXT LINE is both C1 and Unicode `White_Space`, so it intentionally
emits both raw observations on the same bytes. Callers must retain the rule ID
and source span and must not treat overlapping observations as separate bits.
C1 can result from legacy conversion mistakes, terminal captures, control
interpretation, or ordinary tooling. It has no safe universal invisibility or
semantic-equivalence claim.
