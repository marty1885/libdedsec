# Unicode White_Space observation

`libdedsec` carries a static range table generated from Unicode 17.0.0
`PropList.txt`, property `White_Space`. It is compiled C11 data and has no
runtime Unicode-data dependency. This predicate is separate from the existing
byte-oriented ASCII SPACE/TAB layout features; it does not reinterpret ASCII
run widths, line endings, or existing identity lanes.

For every strict-decoded **non-ASCII** scalar with `White_Space=yes`, the
Unicode module emits a `DEDSEC_DETECTION_OBSERVATION` named
`unicode-white-space-scalar`. Its raw byte offset and byte length identify the
scalar exactly; `evidence` contains its scalar value. Observations have no
score, decoder hint, or symbol value. They cannot be passed to the source-order
bit gluer and do not claim a payload.

This is deliberately broad forensic visibility, not a default alert. Unicode
whitespace occurs legitimately in typography, publishing, language-specific
punctuation, mathematics, and copy/paste workflows. A caller who supplies a
complete field grammar may use a caller-defined code-point alphabet to test a
specific pair, but must retain raw bytes and require baseline, framing or
recurrence, and trial accounting. NFKC/NFKD can fold whitespace distinctions;
they must only be applied to a derived view after provenance is preserved.
