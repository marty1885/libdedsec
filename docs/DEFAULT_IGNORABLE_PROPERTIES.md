# Default-Ignorable property observation

`libdedsec` carries a reviewed static range table for Unicode 17.0.0
`Default_Ignorable_Code_Point`. The table is compiled C11 data, so it has no
runtime Unicode-data dependency. Its predicate is shared by the Unicode module
and `dedsec_transform_strip_known_ignorables()`.

This is an anomaly/property observation, not a claim that every covered scalar
is visually inert, semantically interchangeable, or intentional. For each
strict-decoded property member, the Unicode module emits a zero-score
`default-ignorable-scalar` raw value-span observation; `evidence` is its code
point. When a preceding scalar is adjacent, it also emits
`default-ignorable-adjacent-context` across the two scalars. This is a
conservative local dependency span for forensic/rendering review, not a full
grapheme-cluster or rendering-equivalence claim.

The existing aggregate `default-ignorable-candidates` finding remains for
triage. Neither observations nor the aggregate assign a bit value or emit
generic bit symbols. Specialized lanes keep their own rule IDs and symbol
policies; the exact reviewed `U+1820` + FVS1/FVS2 slots suppress the generic
aggregate on that same selector span.

For example, `U+17B4` and `U+17B5` are covered because the pinned property
table includes them. A caller may experiment with an explicitly declared
code-point alphabet and complete slot grammar, but that is a decoding
hypothesis—not a built-in Khmer decoder or evidence of a message.

The table must be deliberately regenerated/reviewed when its Unicode version
changes. Reserved/default-ignorable ranges remain detectable under the pinned
version, but never acquire automatic payload values. Strict UTF-8 validation
still precedes Unicode observation; malformed input remains owned by the
encoding module.
